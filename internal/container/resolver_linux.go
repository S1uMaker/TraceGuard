//go:build linux

// Package container associates host cgroup-v2 IDs with Docker metadata.
// The collector must run in the host PID, mount and cgroup namespaces.
package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zjc20/traceguard/internal/model"
)

const (
	cacheTTL          = 5 * time.Minute
	requestTimeout    = 5 * time.Second
	refreshTimeout    = 30 * time.Second
	maxResponseBytes  = 8 << 20
	maxProcBytes      = 64 << 10
	maxCgroupDirs     = 4096
	cgroup2SuperMagic = 0x63677270
)

var (
	fullContainerID = regexp.MustCompile(`^[a-f0-9]{64}$`)
	dockerScopeID   = regexp.MustCompile(`^docker-([a-f0-9]{64})\.scope$`)
)

type cacheEntry struct {
	source   model.Source
	lastSeen time.Time
}

// Resolver performs Docker I/O only during Refresh. Cache hits in Resolve are
// in-memory; misses use the local proc/cgroup filesystems, never the Docker API.
type Resolver struct {
	client     *http.Client
	transport  *http.Transport
	cgroupRoot string
	procRoot   string
	refreshMu  sync.Mutex
	mu         sync.RWMutex
	entries    map[uint64]cacheEntry
	lastFull   time.Time
}

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
}

type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	State struct {
		PID     int  `json:"Pid"`
		Running bool `json:"Running"`
	} `json:"State"`
}

// New validates local paths without contacting Docker. Refresh must be called
// once at startup and periodically thereafter (a 10-second interval is suitable).
// A Docker failure can be logged by the caller while collection continues.
func New(socketPath, cgroupRoot, procRoot string) (*Resolver, error) {
	if strconv.IntSize != 64 {
		return nil, errors.New("container attribution requires a 64-bit Linux host")
	}
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return nil, errors.New("Docker socket must be an absolute Unix socket path")
	}
	root, err := canonicalDirectory(cgroupRoot)
	if err != nil {
		return nil, fmt.Errorf("cgroup root: %w", err)
	}
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(root, &statfs); err != nil {
		return nil, fmt.Errorf("inspect cgroup filesystem: %w", err)
	}
	if uint64(statfs.Type) != cgroup2SuperMagic {
		return nil, fmt.Errorf("%s is not a cgroup-v2 filesystem", root)
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("read cgroup-v2 root: %w", err)
	}
	proc, err := canonicalDirectory(procRoot)
	if err != nil {
		return nil, fmt.Errorf("proc root: %w", err)
	}
	dialer := &net.Dialer{Timeout: requestTimeout}
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		DisableCompression:    true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Resolver{
		client: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// The daemon is never allowed to redirect a request elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		transport:  transport,
		cgroupRoot: root,
		procRoot:   proc,
		entries:    make(map[uint64]cacheEntry),
	}, nil
}

// Close releases idle Docker connections. It does not own a background worker.
func (r *Resolver) Close() error {
	r.transport.CloseIdleConnections()
	return nil
}

// Refresh publishes a new snapshot atomically. Partial discovery is retained but
// reported as an error; a daemon failure never blocks concurrent cache lookups.
// Entries not seen again expire five minutes after their last observation,
// including when Docker remains unavailable. Old mappings are explicitly marked.
func (r *Resolver) Refresh(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()

	var containers []dockerContainer
	if err := r.getJSON(ctx, "/containers/json", &containers); err != nil {
		return fmt.Errorf("list Docker containers: %w", err)
	}

	now := time.Now()
	fresh := make(map[uint64]cacheEntry)
	var problems []error
	for _, item := range containers {
		if err := ctx.Err(); err != nil {
			problems = append(problems, err)
			break
		}
		if !fullContainerID.MatchString(item.ID) {
			problems = append(problems, errors.New("Docker returned an invalid full container ID"))
			continue
		}
		var detail dockerInspect
		if err := r.getJSON(ctx, "/containers/"+item.ID+"/json", &detail); err != nil {
			problems = append(problems, fmt.Errorf("inspect container %.12s: %w", item.ID, err))
			continue
		}
		if detail.ID != item.ID {
			problems = append(problems, fmt.Errorf("inspect container %.12s: mismatched ID", item.ID))
			continue
		}
		if !detail.State.Running || detail.State.PID <= 0 {
			// It may have stopped between list and inspect; keep only a TTL entry.
			continue
		}
		if uint64(detail.State.PID) > uint64(^uint32(0)) {
			problems = append(problems, fmt.Errorf("container %.12s: invalid init PID", item.ID))
			continue
		}
		cgroupPath, err := r.processCgroup(uint32(detail.State.PID))
		if err != nil {
			problems = append(problems, fmt.Errorf("container %.12s cgroup: %w", item.ID, err))
			continue
		}
		if !pathContainsDockerID(cgroupPath, item.ID) {
			// An init PID may have exited and been reused between inspect and
			// reading proc. Require the Docker ID in its cgroup path as well.
			problems = append(problems, fmt.Errorf("container %.12s: init cgroup does not contain its Docker ID", item.ID))
			continue
		}
		// An init process can move into an inner cgroup (for example init.scope).
		// Recover the actual Docker ancestor before enumerating its descendants.
		cgroupPath = dockerRootPath(cgroupPath, item.ID)
		if cgroupPath == "/" {
			problems = append(problems, fmt.Errorf("container %.12s resolves to the hierarchy root; use host namespaces", item.ID))
			continue
		}
		name := strings.TrimPrefix(detail.Name, "/")
		if name == "" && len(item.Names) > 0 {
			name = strings.TrimPrefix(item.Names[0], "/")
		}
		imageName := detail.Config.Image
		if imageName == "" {
			imageName = item.Image
		}
		source := model.Source{
			Kind:          "docker",
			ContainerID:   item.ID,
			ContainerName: name,
			Image:         imageName,
			CgroupPath:    cgroupPath,
		}
		if err := r.collectCgroups(ctx, cgroupPath, source, now, fresh); err != nil {
			problems = append(problems, fmt.Errorf("container %.12s cgroup scan: %w", item.ID, err))
		}
	}

	r.mu.Lock()
	for id, old := range r.entries {
		if _, updated := fresh[id]; !updated && now.Sub(old.lastSeen) < cacheTTL {
			old.source.Reason = "cached_container_not_in_latest_snapshot"
			fresh[id] = old
		}
	}
	r.entries = fresh
	if len(problems) == 0 {
		r.lastFull = now
	}
	r.mu.Unlock()
	return errors.Join(problems...)
}

// Resolve associates a kernel event with its source. Never infer a container
// name merely from a PID: it may have exited or been reused since the event.
func (r *Resolver) Resolve(cgroupID uint64, pid uint32) model.Source {
	now := time.Now()
	r.mu.RLock()
	entry, found := r.entries[cgroupID]
	lastFull := r.lastFull
	r.mu.RUnlock()
	if cgroupID != 0 && found && now.Sub(entry.lastSeen) < cacheTTL {
		if entry.source.Reason == "" && now.Sub(entry.lastSeen) > 30*time.Second {
			entry.source.Reason = "cached_container_metadata_stale"
		}
		return entry.source
	}
	if cgroupID == 0 || pid == 0 {
		return unknown("missing_cgroup_id_or_pid", "")
	}
	cgroupPath, err := r.processCgroup(pid)
	if err != nil {
		return unknown("process_cgroup_unavailable", "")
	}
	localPath, err := r.safeCgroupPath(cgroupPath)
	if err != nil {
		return unknown("cgroup_path_unavailable", cgroupPath)
	}
	id, err := inodeID(localPath)
	if err != nil || id != cgroupID {
		// This also handles PID reuse and process migration to another cgroup.
		return unknown("event_cgroup_no_longer_matches_process", cgroupPath)
	}
	if containerID := dockerIDFromPath(cgroupPath); containerID != "" {
		source := unknown("docker_metadata_not_cached", cgroupPath)
		source.ContainerID = containerID
		return source
	}
	if hasContainerHint(cgroupPath) {
		return unknown("unresolved_container_cgroup", cgroupPath)
	}
	// A degraded Docker view can hide custom cgroup-parent layouts. Prefer an
	// explicit unknown to calling such an event a host event with confidence.
	if lastFull.IsZero() || now.Sub(lastFull) > 30*time.Second {
		return unknown("docker_snapshot_unavailable_or_stale", cgroupPath)
	}
	if !conventionalHostPath(cgroupPath) {
		return unknown("unrecognized_cgroup_layout", cgroupPath)
	}
	return model.Source{Kind: "host", CgroupPath: cgroupPath, Reason: "matched_host_cgroup_layout"}
}

func (r *Resolver) getJSON(ctx context.Context, endpoint string, value any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Avoid logging arbitrary response text, which may contain sensitive data.
		return fmt.Errorf("Docker API HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read Docker response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return errors.New("Docker response exceeds 8 MiB limit")
	}
	if err := json.Unmarshal(body, value); err != nil {
		return fmt.Errorf("decode Docker response: %w", err)
	}
	return nil
}

func (r *Resolver) processCgroup(pid uint32) (string, error) {
	file, err := os.Open(filepath.Join(r.procRoot, strconv.FormatUint(uint64(pid), 10), "cgroup"))
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxProcBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxProcBytes {
		return "", errors.New("proc cgroup entry exceeds 64 KiB limit")
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "0::") {
			value := strings.TrimPrefix(line, "0::")
			if err := validateCgroupPath(value); err != nil {
				return "", err
			}
			return value, nil
		}
	}
	return "", errors.New("process has no unified cgroup-v2 entry")
}

func (r *Resolver) collectCgroups(ctx context.Context, cgroupPath string, source model.Source, now time.Time, entries map[uint64]cacheEntry) error {
	root, err := r.safeCgroupPath(cgroupPath)
	if err != nil {
		return err
	}
	count := 0
	return filepath.WalkDir(root, func(localPath string, item fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			// Containers can remove an inner cgroup while this snapshot is read.
			if errors.Is(walkErr, os.ErrNotExist) && localPath != root {
				return nil
			}
			return walkErr
		}
		if !item.IsDir() {
			return nil // WalkDir never follows symbolic links.
		}
		count++
		if count > maxCgroupDirs {
			return fmt.Errorf("cgroup subtree exceeds %d directories", maxCgroupDirs)
		}
		relative, err := filepath.Rel(r.cgroupRoot, localPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("cgroup scan escaped configured root")
		}
		currentPath := "/" + filepath.ToSlash(relative)
		if otherID := dockerIDFromPath(currentPath); otherID != "" && otherID != source.ContainerID {
			return filepath.SkipDir // Do not claim a distinct nested container.
		}
		id, err := inodeID(localPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		copySource := source
		copySource.CgroupPath = currentPath
		if existing, ok := entries[id]; ok && existing.source.ContainerID != source.ContainerID {
			// Conflicting Docker reports should never select an arbitrary owner.
			copySource = unknown("conflicting_container_cgroup_mapping", currentPath)
		}
		entries[id] = cacheEntry{source: copySource, lastSeen: now}
		return nil
	})
}

func canonicalDirectory(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) {
		return "", errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func validateCgroupPath(value string) error {
	if !strings.HasPrefix(value, "/") || strings.ContainsRune(value, '\x00') || path.Clean(value) != value {
		return errors.New("invalid unified cgroup path")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return errors.New("cgroup path traversal is not allowed")
		}
	}
	return nil
}

func (r *Resolver) safeCgroupPath(value string) (string, error) {
	if err := validateCgroupPath(value); err != nil {
		return "", err
	}
	current := r.cgroupRoot
	for _, component := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("cgroup path contains a link or non-directory")
		}
	}
	return current, nil
}

func inodeID(localPath string) (uint64, error) {
	info, err := os.Lstat(localPath)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("cgroup entry is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cgroup inode metadata unavailable")
	}
	// Linux kernfs_id_ino returns the full kernfs ID on 64-bit kernels;
	// cgroup_id() (used by bpf_get_current_cgroup_id) returns that same ID.
	return stat.Ino, nil
}

func dockerIDFromPath(value string) string {
	parts := strings.Split(value, "/")
	result := ""
	for index, component := range parts {
		if match := dockerScopeID.FindStringSubmatch(component); match != nil {
			result = match[1]
		}
		if index > 0 && parts[index-1] == "docker" && fullContainerID.MatchString(component) {
			result = component
		}
	}
	return result
}

func dockerRootPath(value, containerID string) string {
	parts := strings.Split(value, "/")
	for index, component := range parts {
		if component == "docker-"+containerID+".scope" || component == containerID {
			return strings.Join(parts[:index+1], "/")
		}
	}
	return value
}

func pathContainsDockerID(value, containerID string) bool {
	for _, component := range strings.Split(value, "/") {
		if component == containerID || component == "docker-"+containerID+".scope" {
			return true
		}
	}
	return false
}

func hasContainerHint(value string) bool {
	value = strings.ToLower(value)
	for _, component := range strings.Split(value, "/") {
		if fullContainerID.MatchString(component) {
			return true
		}
	}
	for _, hint := range []string{"docker", "kubepods", "containerd", "cri-container", "crio", "libpod", "podman", "lxc", "machine.slice", "nspawn"} {
		if strings.Contains(value, hint) {
			return true
		}
	}
	return false
}

func conventionalHostPath(value string) bool {
	return value == "/" || value == "/init.scope" || value == "/system.slice" ||
		value == "/user.slice" || strings.HasPrefix(value, "/system.slice/") ||
		strings.HasPrefix(value, "/user.slice/")
}

func unknown(reason, cgroupPath string) model.Source {
	return model.Source{Kind: "unknown", CgroupPath: cgroupPath, Reason: reason}
}
