//go:build unix

package machine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Lock is the per-migration lock file: an exclusive flock held for as long as a
// process drives the migration. The kernel drops the lock when the process dies,
// so a killed driver can never block a resume; the file then still holds the
// dead process's pid and start time, which Acquire reports as a stale lock so
// the caller can take over the database lease too.
type Lock struct {
	f    *os.File
	path string
}

// Stale describes the holder of a lock that was found abandoned.
type Stale struct {
	PID     int
	Started time.Time
}

// ErrLocked is returned when another live process holds the lock.
var ErrLocked = errors.New("migration is driven by another process")

// AcquireLock takes the lock file at path (created 0600 in a 0700 directory).
// stale is non-nil when the previous holder died without releasing it.
func AcquireLock(path string, now time.Time) (*Lock, *Stale, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder := readHolder(f)
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			if holder != "" {
				return nil, nil, fmt.Errorf("%w (%s)", ErrLocked, holder)
			}
			return nil, nil, ErrLocked
		}
		return nil, nil, fmt.Errorf("lock %s: %w", path, err)
	}
	var stale *Stale
	if pid, started, ok := parseHolder(readHolder(f)); ok {
		stale = &Stale{PID: pid, Started: started}
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if _, err := f.WriteAt([]byte(fmt.Sprintf("pid=%d started=%s\n", os.Getpid(), now.UTC().Format(time.RFC3339))), 0); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return &Lock{f: f, path: path}, stale, nil
}

// Release empties the file (a clean release leaves no stale marker) and unlocks.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = l.f.Truncate(0)
	err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

func readHolder(f *os.File) string {
	b := make([]byte, 256)
	n, _ := f.ReadAt(b, 0)
	return strings.TrimSpace(string(b[:n]))
}

func parseHolder(s string) (int, time.Time, bool) {
	var pid int
	var started time.Time
	for _, field := range strings.Fields(s) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch k {
		case "pid":
			pid, _ = strconv.Atoi(v)
		case "started":
			started, _ = time.Parse(time.RFC3339, v)
		}
	}
	return pid, started, pid > 0
}
