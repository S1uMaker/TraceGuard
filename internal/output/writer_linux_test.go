//go:build linux

package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryLockAndPrivatePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "records")
	writer, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for name, want := range map[string]os.FileMode{"": 0700, "events.jsonl": 0600, "alerts.jsonl": 0600, ".traceguard.lock": 0600} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode=%o, want %o", name, info.Mode().Perm(), want)
		}
	}
	contender, err := New(dir)
	if err == nil {
		contender.Close()
		t.Fatal("second writer acquired an already locked directory")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected lock error, got %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInitializationFailureReleasesLockWithoutChangingPermissions(t *testing.T) {
	dir := t.TempDir()
	// testing.T.TempDir's numbered child can inherit the process umask. Set
	// the required directory mode so this case reaches the bad-file path.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, "alerts.jsonl")
	if err := os.WriteFile(filename, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0644); err != nil {
		t.Fatal(err)
	}
	writer, err := New(dir)
	if err == nil {
		writer.Close()
		t.Fatal("publicly readable output file was accepted")
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatal("existing permissions were silently changed")
	}
	if err := os.Chmod(filename, 0600); err != nil {
		t.Fatal(err)
	}
	retry, err := New(dir)
	if err != nil {
		t.Fatalf("failed initialization leaked the lock: %v", err)
	}
	if err := retry.Close(); err != nil {
		t.Fatal(err)
	}
}
