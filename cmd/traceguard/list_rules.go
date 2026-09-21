package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/zjc20/traceguard/internal/config"
)

// listRulesCommand displays configuration without creating an active engine or
// touching collector, Docker or log output resources.
func listRulesCommand(args []string) error {
	fs := flag.NewFlagSet("list-rules", flag.ContinueOnError)
	configPath := fs.String("config", "configs/traceguard.json", "JSON configuration path (paths relative to working directory)")
	format := fs.String("format", "text", "rule list format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("rule list format must be text or json, got %q", *format)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *format == "json" {
		configuredRules := cfg.Rules
		if configuredRules == nil {
			configuredRules = []config.Rule{}
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(configuredRules); err != nil {
			return fmt.Errorf("write rule list to stdout: %w", err)
		}
		return nil
	}

	w := bufio.NewWriter(os.Stdout)
	if len(cfg.Rules) == 0 {
		if _, err := fmt.Fprintln(w, "No rules configured."); err != nil {
			return fmt.Errorf("write rule list to stdout: %w", err)
		}
	}
	for _, rule := range cfg.Rules {
		uid := "any"
		if rule.UID != nil {
			uid = strconv.FormatUint(uint64(*rule.UID), 10)
		}
		// Quoted strings and slices keep control characters from altering the
		// terminal layout. A nil string slice is displayed as an empty list.
		_, err := fmt.Fprintf(w, "id=%q enabled=%t\n  name=%q severity=%q scope=%q\n  executables=%q\n  container_names=%q\n  exclude_container_names=%q\n  uid=%s\n  description=%q\n\n",
			rule.ID, rule.Enabled, rule.Name, rule.Severity, rule.Scope,
			rule.Executables, rule.ContainerNames, rule.ExcludeContainerNames, uid, rule.Description)
		if err != nil {
			return fmt.Errorf("write rule list to stdout: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("write rule list to stdout: %w", err)
	}
	return nil
}
