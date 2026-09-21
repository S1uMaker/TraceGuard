//go:build linux && (amd64 || arm64)

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/zjc20/traceguard/internal/model"
)

// Collector owns one loaded BPF object, its tracepoint, and its ring reader.
// Close may run concurrently with Read or Dropped. Do not copy a Collector.
type Collector struct {
	mu         sync.Mutex
	collection *ebpf.Collection
	attachment link.Link
	reader     *ringbuf.Reader
	stats      *ebpf.Map
	closed     bool
	closeErr   error
}

// New loads an object built from bpf/exec.bpf.c and attaches it to the VM kernel.
func New(objectPath string) (*Collector, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("read BPF object %q (run make build in Ubuntu): %w", objectPath, err)
	}
	if spec.ByteOrder != binary.LittleEndian {
		return nil, fmt.Errorf("BPF object %q must be built for little-endian BPF (clang -target bpfel)", objectPath)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("prepare BPF memory accounting (run as root): %w", err)
	}
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			// The wrapped error only exposes a short summary. Format the typed
			// error directly to retain the verifier log supplied by cilium/ebpf.
			return nil, fmt.Errorf("load BPF object into kernel: %w\nverifier details:\n%+v", err, verifierErr)
		}
		return nil, fmt.Errorf("load BPF object into kernel: %w", err)
	}
	c := &Collector{collection: objects, stats: objects.Maps["stats"]}
	ready := false
	defer func() {
		if !ready {
			_ = c.Close()
		}
	}()

	program := objects.Programs["handle_exec"]
	events := objects.Maps["events"]
	if program == nil || events == nil || c.stats == nil {
		return nil, errors.New("BPF object must contain handle_exec, events, and stats; rebuild it with make build")
	}
	if events.Type() != ebpf.RingBuf || c.stats.Type() != ebpf.PerCPUArray ||
		c.stats.KeySize() != 4 || c.stats.ValueSize() != 8 || c.stats.MaxEntries() != 1 {
		return nil, errors.New("BPF object map ABI does not match this collector; rebuild it with make build")
	}
	c.reader, err = ringbuf.NewReader(events)
	if err != nil {
		return nil, fmt.Errorf("open BPF event ring buffer: %w", err)
	}
	c.attachment, err = link.Tracepoint("sched", "sched_process_exec", program, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sched/sched_process_exec tracepoint (requires root and tracefs): %w", err)
	}
	ready = true
	return c, nil
}

// Read blocks until a record is available or Close interrupts the wait.
func (c *Collector) Read() (model.RawEvent, error) {
	if c == nil {
		return model.RawEvent{}, ErrClosed
	}
	c.mu.Lock()
	if c.closed || c.reader == nil {
		c.mu.Unlock()
		return model.RawEvent{}, ErrClosed
	}
	reader := c.reader
	c.mu.Unlock()

	record, err := reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return model.RawEvent{}, ErrClosed
		}
		return model.RawEvent{}, fmt.Errorf("read BPF event: %w", err)
	}
	return decodeEvent(record.RawSample)
}

// Dropped returns the sum of ring-buffer reservation failures across all CPUs.
// This is a live snapshot and does not count user-space filtering or shutdown.
func (c *Collector) Dropped() (uint64, error) {
	if c == nil {
		return 0, ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.stats == nil {
		return 0, ErrClosed
	}
	var values []uint64
	key := uint32(0)
	if err := c.stats.Lookup(&key, &values); err != nil {
		return 0, fmt.Errorf("read BPF dropped-event counter: %w", err)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total, nil
}

// Close detaches the program, interrupts Read, and releases the BPF resources.
// Buffered events are not drained. Repeated calls return the same close error.
func (c *Collector) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	var failures []error
	if c.attachment != nil {
		if err := c.attachment.Close(); err != nil {
			failures = append(failures, fmt.Errorf("detach exec tracepoint: %w", err))
		}
	}
	if c.reader != nil {
		if err := c.reader.Close(); err != nil {
			failures = append(failures, fmt.Errorf("close event ring buffer: %w", err))
		}
	}
	if c.collection != nil {
		c.collection.Close()
	}
	c.closeErr = errors.Join(failures...)
	return c.closeErr
}
