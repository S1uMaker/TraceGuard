//go:build linux

package output

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func privateOpenFlags() int {
	// O_NONBLOCK ensures a file exchanged for a FIFO cannot block startup.
	return os.O_CREATE | os.O_APPEND | os.O_WRONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
}

func checkPrivatePermissions(info os.FileInfo, expected os.FileMode) error {
	if info.Mode().Perm() != expected {
		return fmt.Errorf("permissions are %04o; required %04o", info.Mode().Perm(), expected)
	}
	return nil
}

func lockOutputDirectory(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("already in use by another TraceGuard instance; choose another output directory: %w", err)
		}
		return fmt.Errorf("acquire exclusive lock: %w", err)
	}
	return nil
}
