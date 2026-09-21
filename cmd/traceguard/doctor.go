package main

import (
	"context"
	"fmt"
	"time"

	"github.com/zjc20/traceguard/internal/config"
	containerresolver "github.com/zjc20/traceguard/internal/container"
)

func doctor(cfg config.Config) error {
	if err := checkRuntime(cfg); err != nil {
		return err
	}
	fmt.Println("OK: platform, root, cgroup v2, proc, object path and tracepoint field layout")
	resolver, err := containerresolver.New(cfg.DockerSocket, cfg.CgroupRoot, cfg.ProcRoot)
	if err != nil {
		return err
	}
	defer resolver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := resolver.Refresh(ctx); err != nil {
		return fmt.Errorf("Docker/cgroup inventory check: %w", err)
	}
	fmt.Println("OK: Docker API and inventory refresh")
	fmt.Println("Prerequisites checked. eBPF load, verifier acceptance, output writing and real events are NOT validated by doctor.")
	return nil
}
