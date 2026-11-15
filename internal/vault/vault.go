// Package vault encrypts the secrets that users type into the web UI (ADR 0005 item 4, option B).
//
// Model. Every secret gets its own random 256-bit data key (DEK). The secret is encrypted with the DEK
// (AES-256-GCM); the DEK is encrypted ("wrapped") with the master key (AES-256-GCM). The master key is
// never stored in the database: it is supplied through a secret reference (env var or a 0600 file, for
// example a systemd credential) and the server refuses to start without it. A copied state database is
// therefore ciphertext only.
//
// Binding. Every ciphertext is bound to a context string such as "connection:rds-main:password" through
// the AEAD associated data. A blob copied to another row or field fails to open, so an attacker who can
// write the database cannot swap one secret for another.
//
// Rotation. Rewrap changes only the wrapped DEK, so rotating the master key does not re-encrypt every
// secret payload and never needs the plaintext to leave this package.
//
// What this does NOT protect against: an attacker who has both the database file and the master key
// recovers everything (the knowingly relaxed letter of security principle 3, ADR 0005), and an
// attacker who can run code inside the Lockkeeper process while secrets are in memory.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/secret"
)

const (
	formatV1 = 1
	keyLen   = 32
	nonceLen = 12
	tagLen   = 16
	idLen    = 8

	headerLen  = 1 + idLen
	wrappedLen = keyLen + tagLen
	offWrapN   = headerLen
	offWrapped = offWrapN + nonceLen
	offDataN   = offWrapped + wrappedLen
	offData    = offDataN + nonceLen
	minBlobLen = offData + tagLen
)

// Errors are deliberately coarse: they never contain key material or plaintext.
var (
	ErrInvalidKey   = errors.New("vault: master key must be exactly 32 random bytes (base64)")
	ErrCorrupt      = errors.New("vault: ciphertext is damaged, was bound to a different field, or the master key is wrong")
	ErrUnknownKey   = errors.New("vault: ciphertext was sealed with a different master key (key rotation needed?)")
	ErrUnsupported  = errors.New("vault: unsupported ciphertext format")
	ErrEmptyContext = errors.New("vault: context must not be empty")
)

// Vault seals and opens secrets under one master key.
type Vault struct {
	wrap  cipher.AEAD
	keyID [idLen]byte
}

// New builds a Vault from a 32-byte master key. The key is copied; clear your copy afterwards.
func New(master []byte) (*Vault, error) {
	if len(master) != keyLen || allSame(master) {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, ErrInvalidKey
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidKey
	}
	v := &Vault{wrap: gcm}
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("lockkeeper-vault-key-id"))
	copy(v.keyID[:], mac.Sum(nil))
	return v, nil
}

func allSame(b []byte) bool {
	for _, c := range b {
		if c != b[0] {
			return false
		}
	}
	return true
}

// GenerateMasterKey returns a fresh random master key, base64-encoded for storage in a 0600 file or
// a secret manager. Show it once; it cannot be recovered from the database.
func GenerateMasterKey() (string, error) {
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		return "", fmt.Errorf("vault: random source failed: %w", err)
	}
	defer clear(k)
	return base64.StdEncoding.EncodeToString(k), nil
}

// MasterKeyFromSecret decodes a master key held in a secret.Value (resolved from an env var or a
// checked 0600 file by secret.Resolver). Standard and URL-safe base64, with or without padding, are
// accepted. The error never contains the value.
func MasterKeyFromSecret(v secret.Value) ([]byte, error) {
	s := strings.TrimSpace(v.Reveal())
	if s == "" {
		return nil, ErrInvalidKey
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) == keyLen && !allSame(b) {
				return b, nil
			}
			clear(b)
			return nil, ErrInvalidKey
		}
	}
	return nil, ErrInvalidKey
}

// KeyID is a short, non-secret identifier of the master key (an HMAC, not a hash of the key), shown in
// the UI and stored with each blob so rotation tooling knows which key sealed what.
func (v *Vault) KeyID() string { return hex.EncodeToString(v.keyID[:]) }

// String, GoString and LogValue make it impossible to print key material by accident.
func (v *Vault) String() string   { return "vault(" + v.KeyID() + ")" }
func (v *Vault) GoString() string { return v.String() }
func (v *Vault) LogValue() slog.Value {
	return slog.StringValue(v.String())
}

func aadWrap(h []byte, ctx string) []byte {
	return append(append(append([]byte{}, h...), "wrap\x00"...), ctx...)
}
func aadData(ctx string) []byte {
	return append([]byte{formatV1}, append([]byte("data\x00"), ctx...)...)
}

// Seal encrypts plaintext and binds it to context (for example "connection:<id>:password").
func (v *Vault) Seal(plaintext []byte, context string) ([]byte, error) {
	if context == "" {
		return nil, ErrEmptyContext
	}
	dek := make([]byte, keyLen)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("vault: random source failed: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrCorrupt
	}
	data, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCorrupt
	}

	out := make([]byte, 0, minBlobLen+len(plaintext))
	out = append(out, formatV1)
	out = append(out, v.keyID[:]...)

	wrapNonce := make([]byte, nonceLen)
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("vault: random source failed: %w", err)
	}
	out = append(out, wrapNonce...)
	out = v.wrap.Seal(out, wrapNonce, dek, aadWrap(out[:headerLen], context))

	dataNonce := make([]byte, nonceLen)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, fmt.Errorf("vault: random source failed: %w", err)
	}
	out = append(out, dataNonce...)
	out = data.Seal(out, dataNonce, plaintext, aadData(context))
	return out, nil
}

func (v *Vault) checkHeader(blob []byte) error {
	if len(blob) < minBlobLen {
		return ErrCorrupt
	}
	if blob[0] != formatV1 {
		return ErrUnsupported
	}
	if !hmac.Equal(blob[1:headerLen], v.keyID[:]) {
		return ErrUnknownKey
	}
	return nil
}

func (v *Vault) unwrap(blob []byte, context string) ([]byte, error) {
	dek, err := v.wrap.Open(nil, blob[offWrapN:offWrapped], blob[offWrapped:offDataN], aadWrap(blob[:headerLen], context))
	if err != nil {
		return nil, ErrCorrupt
	}
	return dek, nil
}

// Open decrypts a blob produced by Seal with the same context. The caller owns the returned slice
// and should clear it when done.
func (v *Vault) Open(blob []byte, context string) ([]byte, error) {
	if context == "" {
		return nil, ErrEmptyContext
	}
	if err := v.checkHeader(blob); err != nil {
		return nil, err
	}
	dek, err := v.unwrap(blob, context)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrCorrupt
	}
	data, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCorrupt
	}
	pt, err := data.Open(nil, blob[offDataN:offData], blob[offData:], aadData(context))
	if err != nil {
		return nil, ErrCorrupt
	}
	return pt, nil
}

// OpenSecret decrypts into a secret.Value, which redacts itself in logs, JSON and fmt output.
func (v *Vault) OpenSecret(blob []byte, context string) (secret.Value, error) {
	pt, err := v.Open(blob, context)
	if err != nil {
		return secret.Value{}, err
	}
	defer clear(pt)
	return secret.New(string(pt)), nil
}

// KeyIDOf reads which master key sealed a blob without needing any key (rotation reports).
func KeyIDOf(blob []byte) (string, error) {
	if len(blob) < minBlobLen {
		return "", ErrCorrupt
	}
	if blob[0] != formatV1 {
		return "", ErrUnsupported
	}
	return hex.EncodeToString(blob[1:headerLen]), nil
}

// Rewrap re-seals the data key under next's master key. The encrypted payload is not touched and the
// plaintext is never produced. Use it to rotate the master key: for every stored blob, call Rewrap
// with the old vault as the receiver and the new vault as next, then store the result.
func (v *Vault) Rewrap(blob []byte, context string, next *Vault) ([]byte, error) {
	if context == "" {
		return nil, ErrEmptyContext
	}
	if err := v.checkHeader(blob); err != nil {
		return nil, err
	}
	dek, err := v.unwrap(blob, context)
	if err != nil {
		return nil, err
	}
	defer clear(dek)

	out := make([]byte, 0, len(blob))
	out = append(out, formatV1)
	out = append(out, next.keyID[:]...)
	wrapNonce := make([]byte, nonceLen)
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("vault: random source failed: %w", err)
	}
	out = append(out, wrapNonce...)
	out = next.wrap.Seal(out, wrapNonce, dek, aadWrap(out[:headerLen], context))
	out = append(out, blob[offDataN:]...) // payload nonce + ciphertext, byte for byte
	return out, nil
}
