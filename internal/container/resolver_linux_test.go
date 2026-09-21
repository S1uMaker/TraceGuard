//go:build linux

package container

import (
	"strings"
	"testing"
	"time"

	"github.com/zjc20/traceguard/internal/model"
)

// These tests exercise parsing and in-memory attribution only. They do not
// simulate kernel cgroup inodes or require Docker, root, proc, or a cgroup mount.
func TestValidateCgroupPath(t *testing.T) {
	for _, value := range []string{"/", "/init.scope", "/system.slice/sshd.service", "/user.slice/user-1000.slice", "/.hidden/..cache"} {
		if err := validateCgroupPath(value); err != nil {
			t.Errorf("valid path %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", ".", "relative/path", "../escape", "/../escape", "/safe/../escape", "/safe/./child", "/safe/", "//system.slice", "/safe//child", "/safe\x00/child"} {
		if err := validateCgroupPath(value); err == nil {
			t.Errorf("invalid path %q accepted", value)
		}
	}
}

func TestDockerIDFromPath(t *testing.T) {
	outerID := strings.Repeat("a1", 32)
	innerID := strings.Repeat("b2", 32)
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{"systemd", "/system.slice/docker-" + outerID + ".scope", outerID},
		{"systemd child", "/system.slice/docker-" + outerID + ".scope/init.scope", outerID},
		{"cgroupfs", "/docker/" + outerID + "/worker", outerID},
		{"nested uses innermost", "/docker/" + outerID + "/docker/" + innerID, innerID},
		{"host", "/system.slice/sshd.service", ""},
		{"short ID", "/docker/" + outerID[:12], ""},
		{"uppercase ID", "/docker/" + strings.ToUpper(outerID), ""},
		{"scope suffix must be exact", "/system.slice/docker-" + outerID + ".scope.extra", ""},
		{"ID component must be exact", "/docker/prefix-" + outerID, ""},
		{"bare ID is not Docker proof", "/custom/" + outerID, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := dockerIDFromPath(test.path); got != test.want {
				t.Fatalf("dockerIDFromPath(%q) = %q; want %q", test.path, got, test.want)
			}
		})
	}
}

func TestDockerRootPathAndIDMembership(t *testing.T) {
	id := strings.Repeat("c3", 32)
	for _, test := range []struct {
		name     string
		path     string
		root     string
		contains bool
	}{
		{"systemd child", "/system.slice/docker-" + id + ".scope/init.scope", "/system.slice/docker-" + id + ".scope", true},
		{"cgroupfs child", "/docker/" + id + "/worker", "/docker/" + id, true},
		{"custom parent with full ID", "/custom.slice/" + id + "/worker", "/custom.slice/" + id, true},
		{"unrelated", "/system.slice/sshd.service", "/system.slice/sshd.service", false},
		{"ID substring is not membership", "/custom/prefix-" + id, "/custom/prefix-" + id, false},
		{"scope substring is not membership", "/docker-" + id + ".scope-extra", "/docker-" + id + ".scope-extra", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := dockerRootPath(test.path, id); got != test.root {
				t.Errorf("dockerRootPath = %q; want %q", got, test.root)
			}
			if got := pathContainsDockerID(test.path, id); got != test.contains {
				t.Errorf("pathContainsDockerID = %t; want %t", got, test.contains)
			}
		})
	}
}

func TestContainerHintsPreventHostAssumption(t *testing.T) {
	for _, value := range []string{
		"/system.slice/docker-unknown.scope",
		"/kubepods.slice/pod/example",
		"/system.slice/containerd.service",
		"/cri-container-123.scope",
		"/crio-123.scope",
		"/user.slice/libpod-123.scope",
		"/user.slice/PODMAN.scope",
		"/lxc/example",
		"/machine.slice/example.scope",
		"/nspawn/example",
		"/custom/" + strings.Repeat("d4", 32),
	} {
		if !hasContainerHint(value) {
			t.Errorf("container hint in %q was not detected", value)
		}
	}
	for _, value := range []string{"/", "/init.scope", "/system.slice/sshd.service", "/user.slice/user-1000.slice/session-3.scope"} {
		if hasContainerHint(value) {
			t.Errorf("ordinary host path %q unexpectedly contains a container hint", value)
		}
	}
}

func TestResolveCachedMetadataAndExpiry(t *testing.T) {
	const cgroupID = uint64(5001)
	baseSource := model.Source{
		Kind:          "docker",
		ContainerID:   strings.Repeat("e5", 32),
		ContainerName: "demo",
		Image:         "busybox:1.36",
		CgroupPath:    "/docker/example",
	}
	for _, test := range []struct {
		name       string
		age        time.Duration
		oldReason  string
		wantKind   string
		wantReason string
	}{
		{"fresh", time.Second, "", "docker", ""},
		{"stale but unexpired", time.Minute, "", "docker", "cached_container_metadata_stale"},
		{"preserve missing snapshot reason", time.Minute, "cached_container_not_in_latest_snapshot", "docker", "cached_container_not_in_latest_snapshot"},
		{"expired", cacheTTL + time.Minute, "", "unknown", "missing_cgroup_id_or_pid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := baseSource
			source.Reason = test.oldReason
			resolver := &Resolver{entries: map[uint64]cacheEntry{
				cgroupID: {source: source, lastSeen: time.Now().Add(-test.age)},
			}}
			// PID 0 ensures a cache miss cannot read any real proc filesystem.
			got := resolver.Resolve(cgroupID, 0)
			if got.Kind != test.wantKind || got.Reason != test.wantReason {
				t.Fatalf("Resolve = %#v; want kind %q reason %q", got, test.wantKind, test.wantReason)
			}
			if got.Kind == "docker" && (got.ContainerID != baseSource.ContainerID || got.ContainerName != "demo" || got.Image != "busybox:1.36") {
				t.Errorf("cache hit lost container metadata: %#v", got)
			}
			if got.Kind == "unknown" && (got.ContainerID != "" || got.ContainerName != "" || got.Image != "") {
				t.Errorf("expired metadata leaked into unknown attribution: %#v", got)
			}
			if resolver.entries[cgroupID].source.Reason != test.oldReason {
				t.Error("Resolve mutated the cached source while annotating its returned value")
			}
		})
	}
}

func TestResolveMissingIdentifiersRemainUnknown(t *testing.T) {
	resolver := &Resolver{entries: make(map[uint64]cacheEntry)}
	for _, input := range []struct {
		cgroupID uint64
		pid      uint32
	}{{0, 0}, {0, 42}, {123, 0}} {
		got := resolver.Resolve(input.cgroupID, input.pid)
		if got.Kind != "unknown" || got.Reason != "missing_cgroup_id_or_pid" {
			t.Errorf("Resolve(%d, %d) = %#v; want unknown", input.cgroupID, input.pid, got)
		}
	}
}
