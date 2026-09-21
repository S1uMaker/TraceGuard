//go:build !linux

package container

import (
	"context"
	"errors"

	"github.com/zjc20/traceguard/internal/model"
)

// Resolver preserves the API for replay and other non-collection commands.
// Live Docker/cgroup attribution is supported only on Linux.
type Resolver struct{}

func New(socketPath, cgroupRoot, procRoot string) (*Resolver, error) {
	return nil, errors.New("live container attribution is only supported on Linux")
}

func (r *Resolver) Refresh(ctx context.Context) error {
	return errors.New("live container attribution is only supported on Linux")
}

func (r *Resolver) Resolve(cgroupID uint64, pid uint32) model.Source {
	return model.Source{Kind: "unknown", Reason: "container_attribution_unsupported_platform"}
}

func (r *Resolver) Close() error {
	return nil
}
