package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/zjc20/traceguard/internal/model"
	"github.com/zjc20/traceguard/internal/output"
	"github.com/zjc20/traceguard/internal/rules"
)

type statistics struct {
	Kind           string            `json:"kind"`
	Mode           string            `json:"mode"`
	ObservedAt     time.Time         `json:"observed_at"`
	Received       uint64            `json:"received"`
	Saved          uint64            `json:"saved"`
	HostFiltered   uint64            `json:"host_filtered"`
	Unknown        uint64            `json:"unknown"`
	UnknownReasons map[string]uint64 `json:"unknown_reasons,omitempty"`
	Alerts         uint64            `json:"alerts"`
	AlertsByRule   map[string]uint64 `json:"alerts_by_rule,omitempty"`
	PreviewAlerts  uint64            `json:"preview_alerts,omitempty"`
	PreviewByRule  map[string]uint64 `json:"preview_alerts_by_rule,omitempty"`
	ExcludedAlerts uint64            `json:"excluded_alerts"`
	ExcludedByRule map[string]uint64 `json:"excluded_by_rule,omitempty"`
	KernelDropped  uint64            `json:"kernel_dropped"`
}

type pipeline struct {
	writer      *output.Writer
	engine      *rules.Engine
	console     alertEncoder
	includeHost bool
	dryRun      bool
	stats       statistics
}

func (p *pipeline) process(event model.Event) error {
	p.stats.Received++
	if event.Source.Kind == "unknown" {
		p.stats.Unknown++
		if p.stats.UnknownReasons == nil {
			p.stats.UnknownReasons = make(map[string]uint64)
		}
		p.stats.UnknownReasons[unknownReasonBucket(event.Source.Reason)]++
	}
	if event.Source.Kind == "host" && !p.includeHost {
		p.stats.HostFiltered++
		return nil
	}
	if !p.dryRun {
		if err := p.writer.WriteEvent(event); err != nil {
			return err
		}
		p.stats.Saved++
	}
	result := p.engine.Evaluate(event)
	for _, ruleID := range result.ExcludedRules {
		p.stats.ExcludedAlerts++
		if p.stats.ExcludedByRule == nil {
			p.stats.ExcludedByRule = make(map[string]uint64)
		}
		p.stats.ExcludedByRule[ruleID]++
	}
	for _, alert := range result.Alerts {
		if p.dryRun {
			// Count attempts before stdout encoding, without claiming persistence.
			p.stats.PreviewAlerts++
			if p.stats.PreviewByRule == nil {
				p.stats.PreviewByRule = make(map[string]uint64)
			}
			p.stats.PreviewByRule[alert.RuleID]++
		} else {
			if err := p.writer.WriteAlert(alert); err != nil {
				return err
			}
			p.stats.Alerts++
			if p.stats.AlertsByRule == nil {
				p.stats.AlertsByRule = make(map[string]uint64)
			}
			p.stats.AlertsByRule[alert.RuleID]++
		}
		if err := p.console.Encode(alert); err != nil {
			return fmt.Errorf("write alert to stdout: %w", err)
		}
	}
	return nil
}

// Keep replay input from creating an unbounded number of statistics keys.
// These reasons are produced by the Docker resolver for unknown sources.
func unknownReasonBucket(reason string) string {
	switch reason {
	case "missing_cgroup_id_or_pid",
		"process_cgroup_unavailable",
		"cgroup_path_unavailable",
		"event_cgroup_no_longer_matches_process",
		"docker_metadata_not_cached",
		"unresolved_container_cgroup",
		"docker_snapshot_unavailable_or_stale",
		"unrecognized_cgroup_layout",
		"conflicting_container_cgroup_mapping",
		"cached_container_not_in_latest_snapshot":
		return reason
	case "":
		return "unspecified"
	default:
		return "other"
	}
}

func (p *pipeline) report(w io.Writer, kind string) error {
	p.stats.Kind = kind
	p.stats.ObservedAt = time.Now().UTC()
	return json.NewEncoder(w).Encode(p.stats)
}

func sessionID() (string, error) {
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
}
