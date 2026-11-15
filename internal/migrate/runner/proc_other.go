//go:build !unix

package runner

import (
	"os"
	"os/exec"
	"time"
)

// Process groups are not available here; the tool process itself is signalled.
func setProcessGroup(*exec.Cmd) {}

func terminateGroup(pid int, grace time.Duration, done <-chan struct{}) {
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	select {
	case <-done:
	case <-time.After(grace):
		_ = p.Kill()
	}
}

func processAlive(int) bool { return true }
