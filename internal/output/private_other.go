//go:build !linux

package output

import "os"

// This fallback permits offline replay on development platforms. The live
// collector, Unix permission checks and output locking are Linux only.
func privateOpenFlags() int {
	return os.O_CREATE | os.O_APPEND | os.O_WRONLY
}

func checkPrivatePermissions(_ os.FileInfo, _ os.FileMode) error {
	return nil
}

// Non-Linux replay is a development convenience; callers must use a separate
// directory per process because this fallback does not acquire a process lock.
func lockOutputDirectory(_ *os.File) error {
	return nil
}
