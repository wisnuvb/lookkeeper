// Package auth holds the pure building blocks of web authentication (ADR 0005 item 3): password
// hashing, session tokens, roles, login throttling, CSRF and the first-run bootstrap token.
//
// Nothing here talks to a database or an HTTP server. Storage is behind small interfaces
// (SessionStore) so the rules can be tested exhaustively and the SQLite implementation is a thin
// layer added with the state-database schema.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Argon2id parameters for newly created hashes: 64 MiB, 3 passes, 2 lanes. That is above the OWASP
// minimum (19 MiB, 2 passes, 1 lane) and about 60-100 ms on a small VPS, which is acceptable for a
// login that happens a few times a day and makes offline guessing expensive.
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 2
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// Upper bounds accepted when READING a stored hash. A hash value comes from the database, and a
// crafted one (m=4 TiB) would otherwise turn a login attempt into a memory-exhaustion attack.
const (
	maxMemoryKiB = 256 * 1024
	maxTime      = 10
	maxThreads   = 16
	minSaltLen   = 8
	maxSaltLen   = 64
	minKeyLen    = 16
	maxKeyLen    = 64
)

// Password length limits, in bytes after normalisation. The upper bound exists so that a megabyte
// password cannot be used to make the server burn time.
const (
	MinPasswordRunes = 12
	maxPasswordBytes = 1024
)

var (
	// ErrInvalidHash means the stored hash is malformed or outside the accepted parameter bounds.
	ErrInvalidHash = errors.New("auth: invalid password hash")
	// ErrWeakPassword wraps the human-readable reason a password was rejected.
	ErrWeakPassword = errors.New("auth: password rejected")
)

// normalise applies Unicode NFKC so that visually identical passwords typed on different systems
// (composed vs decomposed accents) hash the same (NIST SP 800-63B section 5.1.1.2).
func normalise(pw string) []byte { return []byte(norm.NFKC.String(pw)) }

// HashPassword returns an argon2id hash in the PHC string format.
func HashPassword(password string) (string, error) {
	pw := normalise(password)
	if len(pw) > maxPasswordBytes {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrWeakPassword, maxPasswordBytes)
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: random source failed: %w", err)
	}
	key := argon2.IDKey(pw, salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return encodeHash(argonMemoryKiB, argonTime, argonThreads, salt, key), nil
}

func encodeHash(m, t uint32, p uint8, salt, key []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, m, t, p, b64.EncodeToString(salt), b64.EncodeToString(key))
}

type parsedHash struct {
	m, t    uint32
	p       uint8
	salt    []byte
	key     []byte
	version int
}

func parseHash(encoded string) (parsedHash, error) {
	var h parsedHash
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return h, ErrInvalidHash
	}
	v, ok := strings.CutPrefix(parts[2], "v=")
	if !ok {
		return h, ErrInvalidHash
	}
	ver, err := strconv.Atoi(v)
	if err != nil || ver != argon2.Version {
		return h, ErrInvalidHash
	}
	h.version = ver
	var vals [3]uint64 // m, t, p
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return h, ErrInvalidHash
	}
	for i, want := range []string{"m=", "t=", "p="} {
		s, ok := strings.CutPrefix(fields[i], want)
		if !ok {
			return h, ErrInvalidHash
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return h, ErrInvalidHash
		}
		vals[i] = n
	}
	m, t, p := vals[0], vals[1], vals[2]
	if m < 8 || m > maxMemoryKiB || t < 1 || t > maxTime || p < 1 || p > maxThreads || m < 8*p {
		return h, ErrInvalidHash
	}
	h.m, h.t, h.p = uint32(m), uint32(t), uint8(p)
	b64 := base64.RawStdEncoding
	if h.salt, err = b64.DecodeString(parts[4]); err != nil || len(h.salt) < minSaltLen || len(h.salt) > maxSaltLen {
		return h, ErrInvalidHash
	}
	if h.key, err = b64.DecodeString(parts[5]); err != nil || len(h.key) < minKeyLen || len(h.key) > maxKeyLen {
		return h, ErrInvalidHash
	}
	return h, nil
}

// VerifyPassword checks password against an encoded hash in constant time. needsRehash is true when
// the hash is valid but uses weaker parameters than the current ones, so the caller can upgrade it
// after a successful login.
func VerifyPassword(password, encoded string) (ok, needsRehash bool, err error) {
	h, err := parseHash(encoded)
	if err != nil {
		return false, false, err
	}
	pw := normalise(password)
	if len(pw) > maxPasswordBytes {
		// Still do the work, so the response time does not reveal the length rule.
		pw = pw[:maxPasswordBytes]
		got := argon2.IDKey(pw, h.salt, h.t, h.m, h.p, uint32(len(h.key)))
		_ = subtle.ConstantTimeCompare(got, h.key)
		return false, false, nil
	}
	got := argon2.IDKey(pw, h.salt, h.t, h.m, h.p, uint32(len(h.key)))
	ok = subtle.ConstantTimeCompare(got, h.key) == 1
	needsRehash = ok && (h.m < argonMemoryKiB || h.t < argonTime || h.p < argonThreads || len(h.key) < argonKeyLen)
	return ok, needsRehash, nil
}

// dummyHash is verified when the user does not exist, so "unknown user" and "wrong password" take the
// same time and the login endpoint does not reveal which usernames exist.
var dummyHash = func() string {
	h, err := HashPassword("lockkeeper-dummy-password-for-timing-equalisation")
	if err != nil {
		panic(err)
	}
	return h
}()

// DummyVerify burns the same CPU time as a real verification and always reports failure.
func DummyVerify(password string) {
	_, _, _ = VerifyPassword(password, dummyHash)
}

var commonPasswords = map[string]struct{}{
	"password1234": {}, "123456789012": {}, "qwertyuiop12": {}, "letmein12345": {}, "administrator": {},
	"changeme1234": {}, "welcome12345": {}, "password12345": {}, "iloveyou1234": {}, "lockkeeper123": {},
	"lockkeeper!!": {}, "adminadmin12": {}, "passw0rd1234": {}, "1q2w3e4r5t6y": {}, "abcdefghijkl": {},
}

// ValidatePassword enforces the password policy for NEW passwords: at least 12 characters (length, not
// composition rules, is what resists guessing; passphrases and password managers are welcome), no more
// than 1024 bytes, not the username, not a single repeated character, not a well-known weak password.
// The blocklist is small by design; it is a floor, not a breach-corpus check.
func ValidatePassword(password, username string) error {
	pw := norm.NFKC.String(password)
	if !utf8.ValidString(pw) {
		return fmt.Errorf("%w: not valid text", ErrWeakPassword)
	}
	if n := utf8.RuneCountInString(pw); n < MinPasswordRunes {
		return fmt.Errorf("%w: use at least %d characters", ErrWeakPassword, MinPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Errorf("%w: longer than %d bytes", ErrWeakPassword, maxPasswordBytes)
	}
	lower := strings.ToLower(pw)
	if u := strings.ToLower(strings.TrimSpace(username)); len(u) >= 3 && strings.Contains(lower, u) {
		return fmt.Errorf("%w: must not contain the username", ErrWeakPassword)
	}
	if repeated(pw) {
		return fmt.Errorf("%w: must not be one repeated character", ErrWeakPassword)
	}
	if _, bad := commonPasswords[lower]; bad {
		return fmt.Errorf("%w: too common", ErrWeakPassword)
	}
	return nil
}

func repeated(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	for _, c := range s {
		if c != r {
			return false
		}
	}
	return true
}
