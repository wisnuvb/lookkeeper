package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const tokenBytes = 32 // 256 bits

// NewToken returns a random bearer token (for a session cookie or the first-run setup) and its
// SHA-256 digest. Only the digest is ever stored: a leaked database cannot be replayed as sessions,
// because the token is high-entropy and the digest is one-way.
func NewToken() (token string, digest []byte, err error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("auth: random source failed: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken is the digest under which a token is stored and looked up.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// EqualDigest compares two digests in constant time.
func EqualDigest(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
