//go:build !linux || (!amd64 && !arm64)

package collector

import (
	"fmt"
	"runtime"

	"github.com/zjc20/traceguard/internal/model"
)

// Collector is unavailable outside the supported Linux VM architectures.
type Collector struct{}

func unsupportedError() error {
	return fmt.Errorf("live eBPF collection requires Linux amd64 or arm64; current platform is %s/%s (use the Ubuntu 24.04 VM)", runtime.GOOS, runtime.GOARCH)
}

func New(objectPath string) (*Collector, error) {
	return nil, unsupportedError()
}

func (c *Collector) Read() (model.RawEvent, error) {
	return model.RawEvent{}, unsupportedError()
}

func (c *Collector) Dropped() (uint64, error) {
	return 0, unsupportedError()
}

func (c *Collector) Close() error {
	return nil
}
