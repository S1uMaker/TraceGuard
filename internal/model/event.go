// Package model defines the common event contract used by collection and replay.
package model

import "time"

// RawEvent contains fields captured in the kernel. TimestampNS is monotonic time
// since boot (excluding suspend), not a Unix timestamp. PID/TID are host IDs.
type RawEvent struct {
	TimestampNS uint64 `json:"timestamp_ns"`
	CgroupID    uint64 `json:"cgroup_id"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Comm        string `json:"comm"`
	Filename    string `json:"filename"`
}

// Source never represents an unverified container association as confirmed.
type Source struct {
	Kind          string `json:"kind"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Image         string `json:"image,omitempty"`
	CgroupPath    string `json:"cgroup_path,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type Event struct {
	ID         string    `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	Type       string    `json:"type"`
	RawEvent
	Source Source `json:"source"`
	// Replay is explicitly marked so synthetic/replayed data is not evidence of
	// successful kernel collection. Recorded input IDs are preserved on replay.
	Replay bool `json:"replay,omitempty"`
}

type Alert struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	ObservedAt  time.Time `json:"observed_at"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence"`
	Event       Event     `json:"event"`
}
