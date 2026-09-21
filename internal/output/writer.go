// Package output persists events and alerts as append-only JSON lines.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/zjc20/traceguard/internal/model"
)

type Writer struct {
	mu       sync.Mutex
	events   *os.File
	alerts   *os.File
	lock     *os.File
	closed   bool
	writeErr error
	closeErr error
}

// New creates a private output directory and opens events.jsonl and alerts.jsonl
// for appending. On Linux, existing permissions must already be 0700 for the
// directory and 0600 for every file. Existing permissions are never changed.
// Symlinks and nonregular output files are rejected. A Linux advisory lock
// prevents multiple TraceGuard instances from writing to the same directory.
func New(dir string) (*Writer, error) {
	if dir == "" {
		return nil, errors.New("output directory is empty")
	}
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("output path must be a real directory, not a symlink")
	}
	if err := checkPrivatePermissions(info, 0700); err != nil {
		return nil, fmt.Errorf("output directory %q: %w; choose a dedicated private directory (mkdir -m 700 PATH)", dir, err)
	}
	lock, err := openLog(filepath.Join(dir, ".traceguard.lock"))
	if err != nil {
		return nil, err
	}
	if err := lockOutputDirectory(lock); err != nil {
		return nil, errors.Join(fmt.Errorf("lock output directory %q: %w", dir, err), lock.Close())
	}
	events, err := openLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	alerts, err := openLog(filepath.Join(dir, "alerts.jsonl"))
	if err != nil {
		return nil, errors.Join(err, events.Close(), lock.Close())
	}
	return &Writer{events: events, alerts: alerts, lock: lock}, nil
}

func openLog(filename string) (*os.File, error) {
	// Check before opening as well as afterwards: this gives a useful error for
	// FIFOs/devices and Linux O_NOFOLLOW prevents following a replaced symlink.
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("output file %q must be a regular file, not a symlink or device", filename)
		}
		if err := checkPrivatePermissions(info, 0600); err != nil {
			return nil, fmt.Errorf("output file %q: %w; existing permissions are not modified", filename, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect output file %q: %w", filename, err)
	}
	f, err := os.OpenFile(filename, privateOpenFlags(), 0600)
	if err != nil {
		return nil, fmt.Errorf("open output file %q: %w", filename, err)
	}
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("inspect opened output file %q: %w", filename, err), f.Close())
	}
	if !info.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("opened output file %q is not regular", filename), f.Close())
	}
	if err := checkPrivatePermissions(info, 0600); err != nil {
		return nil, errors.Join(fmt.Errorf("opened output file %q: %w", filename, err), f.Close())
	}
	return f, nil
}

func (writer *Writer) WriteEvent(event model.Event) error {
	return writer.write(writer.events, event)
}

func (writer *Writer) WriteAlert(alert model.Alert) error {
	return writer.write(writer.alerts, alert)
}

func (writer *Writer) write(file *os.File, value any) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return errors.New("output writer is closed")
	}
	if writer.writeErr != nil {
		return writer.writeErr
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s record: %w", filepath.Base(file.Name()), err)
	}
	data = append(data, '\n')
	written, err := file.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// A partial write can leave an incomplete last line. Stop all subsequent
		// writes and let the application stop instead of hiding a damaged log.
		writer.writeErr = fmt.Errorf("append %s: %w", file.Name(), err)
		return writer.writeErr
	}
	return nil
}

// Close flushes both files to the filesystem and closes them. Per-record writes
// are unbuffered, but are not fsynced; abrupt power loss may lose recent records.
// Events and alerts are separate files, not an atomic transaction.
func (writer *Writer) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return writer.closeErr
	}
	writer.closed = true
	var failures []error
	if writer.writeErr != nil {
		failures = append(failures, writer.writeErr)
	}
	for _, file := range []*os.File{writer.events, writer.alerts} {
		if err := file.Sync(); err != nil {
			failures = append(failures, fmt.Errorf("sync %s: %w", file.Name(), err))
		}
		if err := file.Close(); err != nil {
			failures = append(failures, fmt.Errorf("close %s: %w", file.Name(), err))
		}
	}
	// Close releases the advisory lock only after both logs are synced and
	// closed. Never remove the file: removing it could let a new process lock
	// another inode while a running process still holds the original lock.
	if err := writer.lock.Close(); err != nil {
		failures = append(failures, fmt.Errorf("close output lock %s: %w", writer.lock.Name(), err))
	}
	writer.closeErr = errors.Join(failures...)
	return writer.closeErr
}
