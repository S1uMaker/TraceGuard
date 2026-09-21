package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/zjc20/traceguard/internal/collector"
	"github.com/zjc20/traceguard/internal/config"
	containerresolver "github.com/zjc20/traceguard/internal/container"
	"github.com/zjc20/traceguard/internal/model"
	"github.com/zjc20/traceguard/internal/output"
	"github.com/zjc20/traceguard/internal/rules"
)

type sample struct {
	event model.RawEvent
	err   error
}

func run(cfg config.Config, engine *rules.Engine) (result error) {
	console, err := newAlertEncoder(os.Stdout, cfg.AlertFormat)
	if err != nil {
		return err
	}
	if err := checkRuntime(cfg); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Restore default signal handling after the first cancellation. A second
	// Ctrl+C can then terminate even if a slow output device blocks a write.
	go func() { <-ctx.Done(); stop() }()
	resolver, err := containerresolver.New(cfg.DockerSocket, cfg.CgroupRoot, cfg.ProcRoot)
	if err != nil {
		return err
	}
	defer resolver.Close()
	refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = resolver.Refresh(refreshCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("initial Docker inventory failed: %w", err)
	}
	session, err := sessionID()
	if err != nil {
		return err
	}
	writer, err := output.New(cfg.OutputDir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, writer.Close()) }()
	source, err := collector.New(cfg.ObjectPath)
	if err != nil {
		return err
	}
	pipe := &pipeline{writer: writer, engine: engine, console: console, includeHost: cfg.IncludeHost, stats: statistics{Mode: "live"}}
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	var workers sync.WaitGroup
	// A bounded handoff keeps memory bounded. Backpressure eventually fills the
	// kernel ring; reserve failures are counted there instead of hidden here.
	samples := make(chan sample, 256)
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(samples)
		for {
			event, readErr := source.Read()
			select {
			case samples <- sample{event: event, err: readErr}:
			case <-workerCtx.Done():
				return
			}
			if readErr != nil {
				return
			}
		}
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Duration(cfg.RefreshSeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				refreshCtx, cancel := context.WithTimeout(workerCtx, 15*time.Second)
				refreshErr := resolver.Refresh(refreshCtx)
				cancel()
				if refreshErr != nil && workerCtx.Err() == nil {
					log.Printf("Docker inventory refresh failed; source attribution may be unknown: %v", refreshErr)
				}
			}
		}
	}()
	defer func() {
		cancelWorkers()
		if dropped, dropErr := source.Dropped(); dropErr == nil {
			pipe.stats.KernelDropped = dropped
		} else {
			result = errors.Join(result, fmt.Errorf("read final drop count: %w", dropErr))
		}
		result = errors.Join(result, source.Close())
		workers.Wait()
		result = errors.Join(result, pipe.report(os.Stderr, "stopped"))
	}()
	log.Printf("ready: session=%s output=%s; only successful process exec events are collected; Ctrl+C to stop", session, cfg.OutputDir)
	statusTicker := time.NewTicker(10 * time.Second)
	defer statusTicker.Stop()
	var sequence uint64
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-statusTicker.C:
			dropped, err := source.Dropped()
			if err != nil {
				return fmt.Errorf("read kernel drop count: %w", err)
			}
			pipe.stats.KernelDropped = dropped
			if err := pipe.report(os.Stderr, "stats"); err != nil {
				return err
			}
		case item, ok := <-samples:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("collector stopped unexpectedly")
			}
			if item.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("read kernel event: %w", item.err)
			}
			sequence++
			event := model.Event{
				ID: fmt.Sprintf("%s-%d", session, sequence), ObservedAt: time.Now().UTC(),
				Type: "process_exec", RawEvent: item.event,
				Source: resolver.Resolve(item.event.CgroupID, item.event.PID),
			}
			if err := pipe.process(event); err != nil {
				return err
			}
		}
	}
}
