// Package secret provides a redacting wrapper for sensitive strings and the
// resolvers that turn a secret *reference* (env var, file, prompt) into a value.
//
// Configuration and state only ever hold references. A resolved value lives in a
// Value, which prints as "***" through every common formatting path; reading the
// plaintext requires an explicit Reveal call, which is easy to grep and review.
package secret

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"
)

const mask = "***"

// Value holds a secret string. The zero Value is "not set".
type Value struct {
	v string
}

// New wraps s in a Value.
func New(s string) Value { return Value{v: s} }

// Reveal returns the plaintext. Call sites should be few and obvious.
func (v Value) Reveal() string { return v.v }

// IsSet reports whether the value is non-empty.
func (v Value) IsSet() bool { return v.v != "" }

// String implements fmt.Stringer and never leaks the plaintext.
func (v Value) String() string { return mask }

// GoString implements fmt.GoStringer (%#v).
func (v Value) GoString() string { return `secret.Value("` + mask + `")` }

// MarshalText implements encoding.TextMarshaler (used by JSON and others).
func (v Value) MarshalText() ([]byte, error) { return []byte(mask), nil }

// MarshalJSON implements json.Marshaler.
func (v Value) MarshalJSON() ([]byte, error) { return []byte(`"` + mask + `"`), nil }

// MarshalYAML implements yaml.Marshaler.
func (v Value) MarshalYAML() (any, error) { return mask, nil }

// LogValue implements slog.LogValuer.
func (v Value) LogValue() slog.Value { return slog.StringValue(mask) }

// Ref is a reference to a secret. Exactly one field is set.
type Ref struct {
	// Env is the name of an environment variable holding the secret.
	Env string `yaml:"env"`
	// File is the path of a file holding the secret (mode 0600 or stricter).
	File string `yaml:"file"`
	// Prompt asks for the secret interactively on a TTY.
	Prompt bool `yaml:"prompt"`
}

// IsZero reports whether no reference is configured.
func (r Ref) IsZero() bool { return r.Env == "" && r.File == "" && !r.Prompt }

// Validate checks that exactly one source is set.
func (r Ref) Validate() error {
	n := 0
	if r.Env != "" {
		n++
	}
	if r.File != "" {
		n++
	}
	if r.Prompt {
		n++
	}
	switch n {
	case 0:
		return errors.New("secret reference is empty: use { env: NAME }, { file: PATH } or { prompt: true }")
	case 1:
		return nil
	default:
		return errors.New("secret reference must set exactly one of env, file, prompt")
	}
}

// String describes the reference without any value, for error messages.
func (r Ref) String() string {
	switch {
	case r.Env != "":
		return "env:" + r.Env
	case r.File != "":
		return "file:" + r.File
	case r.Prompt:
		return "prompt"
	default:
		return "<unset>"
	}
}

// UnmarshalYAML rejects inline plaintext: a secret in a config file must be a
// reference, never a value.
func (r *Ref) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return fmt.Errorf("line %d: inline secrets are not allowed; use { env: NAME }, { file: PATH } or { prompt: true }", n.Line)
	}
	type plain Ref
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*r = Ref(p)
	return r.Validate()
}

// Resolver resolves references. All side effects are injected so that it can be
// tested and so that core code never reads the process environment directly.
type Resolver struct {
	Getenv   func(string) (string, bool)
	ReadFile func(string) ([]byte, error)
	Stat     func(string) (fs.FileInfo, error)
	// Prompt reads a secret from an interactive terminal. It may be nil, in which
	// case prompt references fail with a clear error.
	Prompt func(label string) (string, error)
}

// OSResolver returns a Resolver backed by the real environment and filesystem.
// prompt may be nil.
func OSResolver(prompt func(label string) (string, error)) Resolver {
	return Resolver{
		Getenv:   os.LookupEnv,
		ReadFile: os.ReadFile,
		Stat:     os.Stat,
		Prompt:   prompt,
	}
}

// Resolve returns the secret referenced by r. label names the secret for prompts
// and errors (for example "password for rds-main").
func (rs Resolver) Resolve(ctx context.Context, r Ref, label string) (Value, error) {
	if err := r.Validate(); err != nil {
		return Value{}, fmt.Errorf("%s: %w", label, err)
	}
	if err := ctx.Err(); err != nil {
		return Value{}, err
	}
	switch {
	case r.Env != "":
		s, ok := rs.Getenv(r.Env)
		if !ok || s == "" {
			return Value{}, fmt.Errorf("%s: environment variable %s is not set or empty", label, r.Env)
		}
		return New(s), nil
	case r.File != "":
		if err := rs.checkFileMode(r.File); err != nil {
			return Value{}, fmt.Errorf("%s: %w", label, err)
		}
		b, err := rs.ReadFile(r.File)
		if err != nil {
			return Value{}, fmt.Errorf("%s: read secret file: %w", label, pathErrorOnly(err))
		}
		s := strings.TrimRight(string(b), "\r\n")
		if s == "" {
			return Value{}, fmt.Errorf("%s: secret file %s is empty", label, r.File)
		}
		return New(s), nil
	default: // prompt
		if rs.Prompt == nil {
			return Value{}, fmt.Errorf("%s: interactive prompt is not available here (no TTY)", label)
		}
		s, err := rs.Prompt(label)
		if err != nil {
			return Value{}, fmt.Errorf("%s: prompt: %w", label, err)
		}
		if s == "" {
			return Value{}, fmt.Errorf("%s: empty secret entered", label)
		}
		return New(s), nil
	}
}

// checkFileMode refuses secret files readable by group or others. On Windows
// POSIX modes are not meaningful, so the check is skipped.
func (rs Resolver) checkFileMode(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := rs.Stat(path)
	if err != nil {
		return fmt.Errorf("stat secret file: %w", pathErrorOnly(err))
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("secret file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("secret file %s has mode %#o; it must not be accessible by group or others (chmod 600)", path, perm)
	}
	return nil
}

// pathErrorOnly strips wrapper detail so errors stay short and predictable.
func pathErrorOnly(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Path, pe.Err)
	}
	return err
}
