package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/zjc20/traceguard/internal/config"
	"github.com/zjc20/traceguard/internal/rules"
)

const version = "0.2.0"

func main() {
	if err := execute(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "traceguard:", err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage()
		return nil
	case "version", "--version":
		fmt.Println("TraceGuard", version)
		return nil
	case "run", "doctor", "check-config", "replay":
	default:
		return fmt.Errorf("unknown command %q; use traceguard help", args[0])
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configPath := fs.String("config", "configs/traceguard.json", "JSON configuration path (paths relative to working directory)")
	outputPath := fs.String("output", "", "override output directory")
	inputPath := ""
	alertFormat := ""
	if args[0] == "run" || args[0] == "replay" {
		fs.StringVar(&alertFormat, "alert-format", "", "stdout alert format: json (default) or text; overrides config")
	}
	if args[0] == "replay" {
		fs.StringVar(&inputPath, "input", "", "recorded or synthetic event JSONL file")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	liveOutput := cfg.OutputDir
	if *outputPath != "" {
		cfg.OutputDir = *outputPath
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "alert-format" {
			cfg.AlertFormat = alertFormat
		}
	})
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid effective configuration: %w", err)
	}
	engine, err := rules.New(cfg.Rules)
	if err != nil {
		return err
	}
	switch args[0] {
	case "check-config":
		fmt.Println("Configuration and rules are valid.")
		return nil
	case "doctor":
		return doctor(cfg)
	case "run":
		return run(cfg, engine)
	case "replay":
		if inputPath == "" {
			return errors.New("replay requires --input")
		}
		if *outputPath == "" {
			return errors.New("replay requires a separate --output directory, for example data-replay")
		}
		if err := requireSeparateOutput(liveOutput, cfg.OutputDir); err != nil {
			return err
		}
		return replay(cfg, engine, inputPath)
	}
	return nil
}

func usage() {
	fmt.Printf(`TraceGuard %s — container exec monitoring

Usage (run from the project directory):
  traceguard check-config [--config configs/traceguard.json]
  traceguard doctor       [--config configs/traceguard.json]
  traceguard run          [--config configs/traceguard.json] [--output data] [--alert-format json|text]
  traceguard replay       --input examples/events.jsonl --output data-replay [--alert-format json|text]
  traceguard version

Live collection requires Linux amd64/arm64, root, cgroup v2 and a local Docker daemon.
doctor performs prerequisite checks only; it does not load eBPF or prove collection works.
run/replay emit alert JSON to stdout by default; --alert-format text enables a compact display.
JSONL files always contain full JSON records. Diagnostics/statistics go to stderr.
Rule exclude_container_names suppresses only that rule's alerts; events remain recorded.
Stop run with Ctrl+C. Replay does not load eBPF or contact Docker.
`, version)
}
