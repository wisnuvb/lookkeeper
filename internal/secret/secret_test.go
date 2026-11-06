package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const plain = "s3cr3t-PLAIN-value"

func TestValueNeverLeaks(t *testing.T) {
	v := New(plain)
	var sb strings.Builder
	logger := slog.New(slog.NewJSONHandler(&sb, nil))
	logger.Info("test", "pw", v)

	j, _ := json.Marshal(struct{ P Value }{v})
	y, _ := yaml.Marshal(struct{ P Value }{v})

	outputs := map[string]string{
		"%v": fmt.Sprintf("%v", v),
		"%s": fmt.Sprintf("%s", v), //lint:ignore S1025 deliberately exercises the %s verb

		"%+v":  fmt.Sprintf("%+v", v),
		"%#v":  fmt.Sprintf("%#v", v),
		"%q":   fmt.Sprintf("%q", v),
		"json": string(j),
		"yaml": string(y),
		"slog": sb.String(),
		"ptr":  fmt.Sprintf("%v", &v),
	}
	for name, out := range outputs {
		if strings.Contains(out, plain) {
			t.Errorf("%s leaked the secret: %q", name, out)
		}
	}
	if v.Reveal() != plain {
		t.Fatal("Reveal must return the plaintext")
	}
}

func TestRefYAML(t *testing.T) {
	type doc struct {
		Password Ref `yaml:"password"`
	}
	good := []struct {
		in   string
		want Ref
	}{
		{"password: { env: DB_PW }", Ref{Env: "DB_PW"}},
		{"password: { file: /run/secret }", Ref{File: "/run/secret"}},
		{"password: { prompt: true }", Ref{Prompt: true}},
	}
	for _, c := range good {
		var d doc
		if err := yaml.Unmarshal([]byte(c.in), &d); err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if d.Password != c.want {
			t.Errorf("%q: got %+v want %+v", c.in, d.Password, c.want)
		}
	}
	bad := map[string]string{
		"password: hunter2":              "inline secrets are not allowed",
		"password: { env: A, file: /x }": "exactly one",
		"password: {}":                   "empty",
		"password: { prompt: false }":    "empty",
		"password: { unknown: x }":       "", // any error is fine
	}
	for in, wantSub := range bad {
		var d doc
		err := yaml.Unmarshal([]byte(in), &d)
		if err == nil {
			// unknown keys are only rejected under KnownFields; validate emptiness instead.
			if d.Password.Validate() == nil {
				t.Errorf("%q: expected an error", in)
			}
			continue
		}
		if wantSub != "" && !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%q: error %q does not contain %q", in, err, wantSub)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%q: error leaks the inline value: %v", in, err)
		}
	}
}

func TestResolveEnv(t *testing.T) {
	rs := Resolver{Getenv: func(k string) (string, bool) {
		if k == "PW" {
			return plain, true
		}
		return "", false
	}}
	v, err := rs.Resolve(context.Background(), Ref{Env: "PW"}, "pw")
	if err != nil || v.Reveal() != plain {
		t.Fatalf("got %v, %v", v, err)
	}
	if _, err := rs.Resolve(context.Background(), Ref{Env: "MISSING"}, "pw"); err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestResolveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte(plain+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(plain), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rs := OSResolver(nil)
	ctx := context.Background()

	v, err := rs.Resolve(ctx, Ref{File: good}, "pw")
	if err != nil || v.Reveal() != plain {
		t.Fatalf("good file: %v %v", v, err)
	}
	if _, err := rs.Resolve(ctx, Ref{File: loose}, "pw"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("loose permissions must be refused, got %v", err)
	}
	if _, err := rs.Resolve(ctx, Ref{File: empty}, "pw"); err == nil {
		t.Fatal("empty file must be refused")
	}
	if _, err := rs.Resolve(ctx, Ref{File: filepath.Join(dir, "nope")}, "pw"); err == nil {
		t.Fatal("missing file must be refused")
	}
}

func TestResolvePrompt(t *testing.T) {
	ctx := context.Background()
	if _, err := (Resolver{}).Resolve(ctx, Ref{Prompt: true}, "pw"); err == nil {
		t.Fatal("prompt without TTY must fail")
	}
	rs := Resolver{Prompt: func(string) (string, error) { return plain, nil }}
	v, err := rs.Resolve(ctx, Ref{Prompt: true}, "pw")
	if err != nil || v.Reveal() != plain {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestResolveHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rs := Resolver{Getenv: func(string) (string, bool) { return plain, true }}
	if _, err := rs.Resolve(ctx, Ref{Env: "X"}, "pw"); err == nil {
		t.Fatal("expected context error")
	}
}
