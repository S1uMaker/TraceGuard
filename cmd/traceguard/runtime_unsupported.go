//go:build !linux || (!amd64 && !arm64)

package main

import (
	"fmt"
	"runtime"

	"github.com/zjc20/traceguard/internal/config"
)

func checkRuntime(_ config.Config) error {
	return fmt.Errorf("live collection requires Linux amd64/arm64; current platform is %s/%s", runtime.GOOS, runtime.GOARCH)
}
