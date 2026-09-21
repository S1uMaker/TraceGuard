package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zjc20/traceguard/internal/config"
	"github.com/zjc20/traceguard/internal/model"
	"github.com/zjc20/traceguard/internal/rules"
)

func TestReplayAcceptsMissingFilenameFromKernelReadFailure(t *testing.T) {
	event := model.Event{Type: "process_exec", Source: model.Source{Kind: "unknown"}}
	if err := validateReplayEvent(event); err != nil {
		t.Fatalf("a recorded exec with an unavailable filename must remain replayable: %v", err)
	}
}

func TestReplayRejectsUnsupportedEventAndIncompleteSource(t *testing.T) {
	cases := []struct {
		name  string
		event model.Event
	}{
		{"wrong event type", model.Event{Type: "network", Source: model.Source{Kind: "host"}}},
		{"missing source", model.Event{Type: "process_exec"}},
		{"docker without ID", model.Event{Type: "process_exec", Source: model.Source{Kind: "docker"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateReplayEvent(tc.event); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

func TestReplayRequiresDifferentDirectoryBeforeCreation(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live")
	alias := live + string(filepath.Separator) + "."
	if err := requireSeparateOutput(live, alias); err == nil {
		t.Fatal("alternate spelling of the live directory was accepted")
	}
	if err := requireSeparateOutput(live, filepath.Join(root, "replay")); err != nil {
		t.Fatalf("separate output should be accepted: %v", err)
	}
}

func TestReplayRejectsParentSymlinkAlias(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "actual")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(actual, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := requireSeparateOutput(filepath.Join(actual, "future"), filepath.Join(alias, "future")); err == nil {
		t.Fatal("parent symlink bypassed live/replay directory isolation")
	}
}

func TestReplayRejectsInputAliasedAsOutput(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input.jsonl")
	original := []byte("a sentinel that must never be appended to\n")
	if err := os.WriteFile(input, original, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(input, filepath.Join(out, "events.jsonl")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	engine, err := rules.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = replay(config.Config{OutputDir: out}, engine, input)
	if err == nil || !strings.Contains(err.Error(), "input file") {
		t.Fatalf("expected alias rejection before reading or writing, got %v", err)
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatal("input was modified")
	}
}
