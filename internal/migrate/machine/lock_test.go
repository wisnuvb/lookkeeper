//go:build unix

package machine

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockExclusiveAndCleanReleaseLeavesNoStaleMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m1", "driver.lock")
	l1, stale, err := AcquireLock(path, time.Now())
	if err != nil || stale != nil {
		t.Fatalf("first acquire: %v %v", err, stale)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file must be 0600, is %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 {
		t.Errorf("lock directory must be 0700, is %v", fi.Mode().Perm())
	}
	_, _, err = AcquireLock(path, time.Now())
	if !errors.Is(err, ErrLocked) || !strings.Contains(err.Error(), fmt.Sprintf("pid=%d", os.Getpid())) {
		t.Fatalf("a second driver must be refused and told who holds it: %v", err)
	}
	if err := l1.Release(); err != nil {
		t.Fatal(err)
	}
	l2, stale, err := AcquireLock(path, time.Now())
	if err != nil || stale != nil {
		t.Fatalf("after a clean release the lock is free and not stale: %v %v", err, stale)
	}
	_ = l2.Release()
}

// TestLockHelper is the child process of TestKilledHolderLeavesAStaleLockThatIsTakenOver.
func TestLockHelper(t *testing.T) {
	path := os.Getenv("LK_LOCK_HELPER")
	if path == "" {
		t.Skip("helper process only")
	}
	if _, _, err := AcquireLock(path, time.Now()); err != nil {
		fmt.Println("error:", err)
		os.Exit(2)
	}
	fmt.Println("locked")
	time.Sleep(time.Minute)
}

func TestKilledHolderLeavesAStaleLockThatIsTakenOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "driver.lock")
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelper$")
	cmd.Env = append(os.Environ(), "LK_LOCK_HELPER="+path)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "locked" {
		t.Fatalf("helper did not lock: %q", line)
	}
	if _, _, err := AcquireLock(path, time.Now()); !errors.Is(err, ErrLocked) {
		t.Fatalf("a live holder must block us: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Kill() // SIGKILL: no chance to clean up
	_ = cmd.Wait()

	l, stale, err := AcquireLock(path, time.Now())
	if err != nil {
		t.Fatalf("the kernel drops a dead process's lock, so we must get it: %v", err)
	}
	defer l.Release()
	if stale == nil || stale.PID != pid || stale.Started.IsZero() {
		t.Fatalf("the abandoned lock must be reported with the dead pid %d and its start time, got %+v", pid, stale)
	}
}
