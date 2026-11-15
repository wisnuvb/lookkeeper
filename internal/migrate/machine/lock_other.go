//go:build !unix

package machine

import (
	"errors"
	"time"
)

// Lock is not available on this platform.
type Lock struct{}

// Stale describes the holder of an abandoned lock.
type Stale struct {
	PID     int
	Started time.Time
}

// ErrLocked is returned when another live process holds the lock.
var ErrLocked = errors.New("migration is driven by another process")

// AcquireLock is unsupported here: migrations need flock.
func AcquireLock(string, time.Time) (*Lock, *Stale, error) {
	return nil, nil, errors.New("migrations are supported on Unix systems only")
}

// Release does nothing.
func (*Lock) Release() error { return nil }
