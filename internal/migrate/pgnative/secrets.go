package pgnative

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// scramIterations is PostgreSQL's default for scram_iterations.
const scramIterations = 4096

// GeneratePassword returns a random password for the per-migration role: 192
// bits as hex, so it needs no quoting anywhere (SQL literal, conninfo, URI).
func GeneratePassword() (secret.Value, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return secret.Value{}, fmt.Errorf("generate migration password: %w", err)
	}
	return secret.New(hex.EncodeToString(b)), nil
}

// ScramVerifier computes the SCRAM-SHA-256 verifier PostgreSQL stores for a
// password (the format of pg_authid.rolpassword). Sending the verifier in
// CREATE ROLE ... PASSWORD means the clear-text password never reaches the
// source server, its statement log or pg_stat_statements: only the target's
// subscription catalog needs the clear text (ADR 0004 item 7).
func ScramVerifier(password string, salt []byte) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, scramIterations, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	serverKey := mac(salted, "Server Key")
	enc := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", scramIterations, enc(salt), enc(stored[:]), enc(serverKey)), nil
}

// RandomVerifier returns a verifier for password with a fresh random salt.
func RandomVerifier(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return ScramVerifier(password, salt)
}

// PasswordFile holds the generated migration-role password between the command
// that creates the role and the one that creates the subscription. It is a
// secret *file reference* in the sense of ADR 0004: mode 0600 in a 0700
// directory, never in the state database, never printed, deleted at cleanup.
type PasswordFile struct{ Path string }

// PasswordFileFor returns the location for a migration under dir.
func PasswordFileFor(dir, migrationID string) PasswordFile {
	return PasswordFile{Path: filepath.Join(dir, migrationID, "migration-role.secret")}
}

// Exists reports whether the password file exists.
func (p PasswordFile) Exists() bool {
	_, err := os.Stat(p.Path)
	return err == nil
}

// Ensure returns the stored password, generating and persisting a new one if the
// file does not exist. The file is written (0600, exclusive create) before the
// caller uses the password anywhere, so a crash cannot lose a password that a
// role was already created with.
func (p PasswordFile) Ensure() (secret.Value, error) {
	if v, err := p.Read(); err == nil {
		return v, nil
	}
	if err := os.MkdirAll(filepath.Dir(p.Path), 0o700); err != nil {
		return secret.Value{}, fmt.Errorf("create secret directory: %w", err)
	}
	pw, err := GeneratePassword()
	if err != nil {
		return secret.Value{}, err
	}
	f, err := os.OpenFile(p.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return p.Read() // lost a race with ourselves: use what is there
		}
		return secret.Value{}, fmt.Errorf("create password file: %w", err)
	}
	if _, err := f.WriteString(pw.Reveal() + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(p.Path)
		return secret.Value{}, fmt.Errorf("write password file: %w", err)
	}
	if err := f.Close(); err != nil {
		return secret.Value{}, err
	}
	return pw, nil
}

// Read returns the stored password, refusing a file that group or others can read.
func (p PasswordFile) Read() (secret.Value, error) {
	fi, err := os.Stat(p.Path)
	if err != nil {
		return secret.Value{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return secret.Value{}, fmt.Errorf("password file %s has mode %#o; it must not be accessible by group or others", p.Path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(p.Path)
	if err != nil {
		return secret.Value{}, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return secret.Value{}, fmt.Errorf("password file %s is empty", p.Path)
	}
	return secret.New(s), nil
}

// Remove deletes the file.
func (p PasswordFile) Remove() error {
	if err := os.Remove(p.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// roleSecrets supplies the placeholder values of the CREATE ROLE statement.
func roleSecrets(p PasswordFile) func() (map[string]string, error) {
	return func() (map[string]string, error) {
		pw, err := p.Ensure()
		if err != nil {
			return nil, err
		}
		v, err := RandomVerifier(pw.Reveal())
		if err != nil {
			return nil, err
		}
		return map[string]string{"verifier": action.QuoteLiteral(v)}, nil
	}
}

// subscriptionSecrets supplies the password placeholder of CREATE SUBSCRIPTION.
func subscriptionSecrets(p PasswordFile) func() (map[string]string, error) {
	return func() (map[string]string, error) {
		pw, err := p.Read()
		if err != nil {
			return nil, fmt.Errorf("the migration role password is not available (%w); it is created by apply-source-changes", err)
		}
		return map[string]string{"password": pw.Reveal()}, nil
	}
}
