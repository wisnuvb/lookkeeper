package auth

import (
	"sync"
	"time"
)

// Bootstrap is the one-time token that lets the first administrator be created. The server prints it
// on the console at startup when no user exists; whoever can read the console (and so already controls
// the host) can claim the admin account, and nobody else can. It is single-use, expires, and only its
// digest is held in memory.
type Bootstrap struct {
	mu      sync.Mutex
	digest  []byte
	expires time.Time
	used    bool
	now     func() time.Time
}

// BootstrapLifetime is how long the first-run token stays valid.
const BootstrapLifetime = 30 * time.Minute

// NewBootstrap creates the token. The plaintext is returned once, for printing; it is not kept.
func NewBootstrap(now func() time.Time) (*Bootstrap, string, error) {
	if now == nil {
		now = time.Now
	}
	token, digest, err := NewToken()
	if err != nil {
		return nil, "", err
	}
	return &Bootstrap{digest: digest, expires: now().Add(BootstrapLifetime), now: now}, token, nil
}

// Consume checks the token in constant time and burns it on success. A wrong guess does not burn it
// (otherwise anyone could invalidate it), but the caller should rate-limit attempts like a login.
func (b *Bootstrap) Consume(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used || !b.now().Before(b.expires) {
		return false
	}
	if !EqualDigest(HashToken(token), b.digest) {
		return false
	}
	b.used = true
	return true
}

// Active reports whether the token can still be used.
func (b *Bootstrap) Active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.used && b.now().Before(b.expires)
}
