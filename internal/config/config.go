// Package config loads TraceGuard's deliberately small, strict JSON configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const maxConfigBytes = 1 << 20

type Config struct {
	ObjectPath     string `json:"bpf_object"`
	DockerSocket   string `json:"docker_socket"`
	CgroupRoot     string `json:"cgroup_root"`
	ProcRoot       string `json:"proc_root"`
	OutputDir      string `json:"output_dir"`
	AlertFormat    string `json:"alert_format,omitempty"`
	RefreshSeconds int    `json:"refresh_seconds"`
	IncludeHost    bool   `json:"include_host"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Description           string   `json:"description"`
	Severity              string   `json:"severity"`
	Scope                 string   `json:"scope"`
	Executables           []string `json:"executables"`
	ContainerNames        []string `json:"container_names,omitempty"`
	ExcludeContainerNames []string `json:"exclude_container_names,omitempty"`
	UID                   *uint32  `json:"uid,omitempty"`
	Enabled               bool     `json:"enabled"`
}

// Load resolves no paths itself: relative bpf_object and output_dir paths are
// relative to the working directory of the process, not the configuration file.
// Unknown keys, duplicate keys and trailing JSON values are configuration errors.
func Load(filename string) (Config, error) {
	var cfg Config
	f, err := os.Open(filename)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return cfg, errors.New("config exceeds 1 MiB")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if err := checkFieldNames(data); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (cfg Config) Validate() error {
	for _, field := range []struct{ name, value string }{
		{"bpf_object", cfg.ObjectPath}, {"output_dir", cfg.OutputDir},
		{"docker_socket", cfg.DockerSocket}, {"cgroup_root", cfg.CgroupRoot},
		{"proc_root", cfg.ProcRoot},
	} {
		if strings.TrimSpace(field.value) == "" || strings.ContainsRune(field.value, '\x00') {
			return fmt.Errorf("%s must be a nonempty path without NUL bytes", field.name)
		}
	}
	for _, field := range []struct{ name, value string }{
		{"docker_socket", cfg.DockerSocket}, {"cgroup_root", cfg.CgroupRoot},
		{"proc_root", cfg.ProcRoot},
	} {
		if !path.IsAbs(field.value) {
			return fmt.Errorf("%s must be an absolute Linux path", field.name)
		}
	}
	if cfg.RefreshSeconds < 1 || cfg.RefreshSeconds > 3600 {
		return errors.New("refresh_seconds must be between 1 and 3600")
	}
	switch cfg.AlertFormat {
	case "", "json", "text":
	default:
		return errors.New("alert_format must be json or text")
	}
	return ValidateRules(cfg.Rules)
}

// ValidateRules also validates disabled rules so that misspelled settings fail
// early instead of remaining hidden until the rule is enabled.
func ValidateRules(rules []Rule) error {
	seen := make(map[string]struct{}, len(rules))
	for i, rule := range rules {
		prefix := fmt.Sprintf("rules[%d]", i)
		if !validID(rule.ID) {
			return fmt.Errorf("%s.id must use 1-64 ASCII letters, digits, dots, underscores or hyphens", prefix)
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("%s.id duplicates %q", prefix, rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("%s.name is required", prefix)
		}
		switch rule.Severity {
		case "info", "warning", "critical":
		default:
			return fmt.Errorf("%s.severity must be info, warning or critical", prefix)
		}
		switch rule.Scope {
		case "docker", "host", "any":
		default:
			return fmt.Errorf("%s.scope must be docker, host or any", prefix)
		}
		if len(rule.Executables) == 0 {
			return fmt.Errorf("%s.executables must contain at least one exact name or absolute path", prefix)
		}
		for _, executable := range rule.Executables {
			if strings.TrimSpace(executable) == "" || strings.ContainsRune(executable, '\x00') {
				return fmt.Errorf("%s.executables contains an empty or invalid value", prefix)
			}
			if strings.Contains(executable, "/") && !path.IsAbs(executable) {
				return fmt.Errorf("%s.executables: %q must be a basename or an absolute Linux path", prefix, executable)
			}
			if path.Clean(executable) != executable || executable == "." || executable == ".." || executable == "/" {
				return fmt.Errorf("%s.executables: %q is not a clean executable name or path", prefix, executable)
			}
		}
		for _, field := range []struct {
			name   string
			values []string
		}{
			{"container_names", rule.ContainerNames},
			{"exclude_container_names", rule.ExcludeContainerNames},
		} {
			for _, name := range field.values {
				if strings.TrimSpace(name) == "" || strings.ContainsRune(name, '\x00') {
					return fmt.Errorf("%s.%s contains an empty or invalid name", prefix, field.name)
				}
			}
			if len(field.values) > 0 && rule.Scope == "host" {
				return fmt.Errorf("%s.%s cannot be combined with host scope", prefix, field.name)
			}
		}
	}
	return nil
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Go's typed JSON decoder accepts case-insensitive field names. Check the
// exact spelling too, so "enabled" and "Enabled" cannot override each other.
func checkFieldNames(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for key := range fields {
		switch key {
		case "bpf_object", "docker_socket", "cgroup_root", "proc_root", "output_dir", "alert_format", "refresh_seconds", "include_host", "rules":
		default:
			return fmt.Errorf("unknown config field %q", key)
		}
	}
	if raw, exists := fields["rules"]; exists {
		var rules []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rules); err != nil {
			return fmt.Errorf("rules: %w", err)
		}
		for i, rule := range rules {
			for key := range rule {
				switch key {
				case "id", "name", "description", "severity", "scope", "executables", "container_names", "exclude_container_names", "uid", "enabled":
				default:
					return fmt.Errorf("unknown rules[%d] field %q", i, key)
				}
			}
		}
	}
	return nil
}

// encoding/json normally accepts repeated object keys. Reject them before the
// typed decode so a copied setting cannot silently override an earlier one.
func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("trailing data after configuration object")
	}
	return nil
}

func consumeValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
	_, err = decoder.Token()
	return err
}
