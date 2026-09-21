package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/zjc20/traceguard/internal/config"
	"github.com/zjc20/traceguard/internal/model"
	"github.com/zjc20/traceguard/internal/output"
	"github.com/zjc20/traceguard/internal/rules"
)

func replay(cfg config.Config, engine *rules.Engine, input string) (result error) {
	console, err := newAlertEncoder(os.Stdout, cfg.AlertFormat)
	if err != nil {
		return err
	}
	f, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("open replay input: %w", err)
	}
	defer f.Close()
	inputInfo, err := f.Stat()
	if err != nil {
		return err
	}
	if !inputInfo.Mode().IsRegular() {
		return errors.New("replay input must be a regular file")
	}
	// Compare inode identity as well as paths: symlinks and hard links must not
	// turn replay into an endless read-and-append of its own output.
	for _, name := range []string{"events.jsonl", "alerts.jsonl"} {
		info, statErr := os.Stat(filepath.Join(cfg.OutputDir, name))
		if statErr == nil && os.SameFile(inputInfo, info) {
			return errors.New("replay output must not overwrite or append to the input file")
		}
		if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
	}
	writer, err := output.New(cfg.OutputDir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, writer.Close()) }()
	pipe := &pipeline{writer: writer, engine: engine, console: console, includeHost: cfg.IncludeHost, stats: statistics{Mode: "replay"}}
	defer func() { result = errors.Join(result, pipe.report(os.Stderr, "stopped")) }()
	session, err := sessionID()
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		data := bytes.TrimSpace(scanner.Bytes())
		if len(data) == 0 {
			continue
		}
		var event model.Event
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return fmt.Errorf("replay line %d: %w", line, err)
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return fmt.Errorf("replay line %d: trailing JSON data", line)
		}
		if err := validateReplayEvent(event); err != nil {
			return fmt.Errorf("replay line %d: %w", line, err)
		}
		if event.ID == "" {
			event.ID = fmt.Sprintf("replay-%s-%d", session, line)
		}
		if event.ObservedAt.IsZero() {
			event.ObservedAt = time.Now().UTC()
		}
		event.Replay = true
		if err := pipe.process(event); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read replay input near line %d (maximum 1 MiB per line): %w", line+1, err)
	}
	return nil
}

func validateReplayEvent(event model.Event) error {
	if event.Type != "process_exec" {
		return fmt.Errorf("type must be process_exec, got %q", event.Type)
	}
	// A failed kernel string read is recorded as an empty filename. It remains
	// a valid event; the rule engine intentionally does not match it.
	switch event.Source.Kind {
	case "docker":
		if event.Source.ContainerID == "" {
			return errors.New("docker source requires container_id")
		}
	case "host", "unknown":
	default:
		return fmt.Errorf("source.kind must be docker, host or unknown, got %q", event.Source.Kind)
	}
	return nil
}

func requireSeparateOutput(live, replayDir string) error {
	a, err := canonicalFuturePath(live)
	if err != nil {
		return err
	}
	b, err := canonicalFuturePath(replayDir)
	if err != nil {
		return err
	}
	if a == b {
		return errors.New("replay output must differ from the configured live output directory")
	}
	return nil
}

// Resolve existing ancestors too, so aliases through a parent symlink cannot
// silently merge replay and live files even before either directory exists.
func canonicalFuturePath(value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}
