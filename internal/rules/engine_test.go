package rules

import (
	"testing"
	"time"

	"github.com/zjc20/traceguard/internal/config"
	"github.com/zjc20/traceguard/internal/model"
)

func shellRule() config.Rule {
	return config.Rule{ID: "shell", Name: "Shell", Severity: "warning", Scope: "docker", Executables: []string{"sh", "bash"}, Enabled: true}
}

func shellEvent() model.Event {
	return model.Event{ID: "event-1", ObservedAt: time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC), Type: "process_exec", RawEvent: model.RawEvent{Filename: "/bin/sh", UID: 0}, Source: model.Source{Kind: "docker", ContainerID: "container-1", ContainerName: "allowed"}}
}

func TestRuleCombinesConditionsAndRetainsEvidence(t *testing.T) {
	uid := uint32(0)
	rule := shellRule()
	rule.UID = &uid
	rule.ContainerNames = []string{"allowed", "another"}
	engine, err := New([]config.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	event := shellEvent()
	alerts := engine.Match(event)
	if len(alerts) != 1 {
		t.Fatalf("expected one alert, got %d", len(alerts))
	}
	alert := alerts[0]
	if alert.EventID != event.ID || alert.RuleID != "shell" || alert.Event != event || len(alert.Evidence) < 3 {
		t.Fatalf("alert must preserve its event and rule evidence: %#v", alert)
	}
	cases := []struct {
		name   string
		change func(*model.Event)
	}{
		{"wrong UID", func(e *model.Event) { e.UID = 1000 }},
		{"wrong container", func(e *model.Event) { e.Source.ContainerName = "unlisted" }},
		{"unknown source", func(e *model.Event) { e.Source.Kind = "unknown" }},
		{"host source", func(e *model.Event) { e.Source.Kind = "host" }},
		{"unmatched program", func(e *model.Event) { e.Filename = "/usr/bin/sleep" }},
		{"missing filename", func(e *model.Event) { e.Filename = "" }},
		{"wrong event type", func(e *model.Event) { e.Type = "network" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := event
			tc.change(&changed)
			if got := engine.Match(changed); len(got) != 0 {
				t.Fatalf("unmet condition produced alerts: %#v", got)
			}
		})
	}
}

func TestExecutableMatchingAndScopeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, executable, filename, scope, source string
		enabled                                   bool
		want                                      int
	}{
		{"basename", "sh", "/usr/bin/sh", "docker", "docker", true, 1},
		{"absolute exact", "/bin/sh", "/bin/sh", "docker", "docker", true, 1},
		{"absolute differs", "/bin/sh", "/usr/bin/sh", "docker", "docker", true, 0},
		{"no glob", "sh*", "/bin/sh", "docker", "docker", true, 0},
		{"explicit any", "sh", "/bin/sh", "any", "unknown", true, 1},
		{"disabled", "sh", "/bin/sh", "docker", "docker", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := shellRule()
			rule.Executables, rule.Scope, rule.Enabled = []string{tc.executable}, tc.scope, tc.enabled
			engine, err := New([]config.Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			event := shellEvent()
			event.Filename, event.Source.Kind = tc.filename, tc.source
			if got := len(engine.Match(event)); got != tc.want {
				t.Fatalf("got %d alerts, want %d", got, tc.want)
			}
		})
	}
}
