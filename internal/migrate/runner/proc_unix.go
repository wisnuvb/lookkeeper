//go:build unix

package runner

import (
	"os/exec"
	"syscall"
	"time"
)

// setProcessGroup puts the child in its own process group so that signals reach
// the tool and everything it spawned (pgcopydb starts many workers).
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateGroup sends SIGTERM to the whole group, waits up to grace for the
// process to exit (done closes), then sends SIGKILL to the group. A final
// SIGKILL sweep after a short delay removes stragglers that ignored SIGTERM.
func terminateGroup(pid int, grace time.Duration, done <-chan struct{}) {
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-done:
		time.Sleep(200 * time.Millisecond)
	case <-time.After(grace):
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

// processAlive reports whether a process with this pid exists.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
