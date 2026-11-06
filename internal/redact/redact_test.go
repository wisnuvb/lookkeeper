package redact

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStringScrubsLiteralsAndPatterns(t *testing.T) {
	r := New()
	r.Add("hunter2-LITERAL", "ab") // "ab" is too short and must be ignored
	cases := []struct{ name, in, mustNotContain string }{
		{"literal", "connect failed for hunter2-LITERAL now", "hunter2-LITERAL"},
		{"uri", "dial postgres://admin:p4ss-w0rd@db.example.com:5432/app", "p4ss-w0rd"},
		{"uri mysql", "mysql://root:topsecret@10.0.0.1/db", "topsecret"},
		{"kv libpq", "host=db user=u password=abc123XYZ dbname=x", "abc123XYZ"},
		{"kv quoted", `password='with space'`, "with space"},
		{"kv url", "https://x/y?token=AAA111&z=1", "AAA111"},
		{"telegram", "Post https://api.telegram.org/bot123456:ABC-def_GHI/sendMessage", "ABC-def_GHI"},
	}
	for _, c := range cases {
		got := r.String(c.in)
		if strings.Contains(got, c.mustNotContain) {
			t.Errorf("%s: %q still contains %q", c.name, got, c.mustNotContain)
		}
		if !strings.Contains(got, Mask) {
			t.Errorf("%s: expected a mask in %q", c.name, got)
		}
	}
	if got := r.String("ab and nothing else"); got != "ab and nothing else" {
		t.Errorf("short secret must not be scrubbed, got %q", got)
	}
}

func TestStringKeepsNormalText(t *testing.T) {
	r := New()
	in := "replication slot lk_slot retained 5 GiB on host db.example.com"
	if got := r.String(in); got != in {
		t.Errorf("unexpected change: %q", got)
	}
}

func TestLongestSecretFirst(t *testing.T) {
	r := New()
	r.Add("abcd", "abcdefgh")
	if got := r.String("x abcdefgh y"); strings.Contains(got, "efgh") {
		t.Errorf("partial leak: %q", got)
	}
}

func TestErrorKeepsChain(t *testing.T) {
	r := New()
	r.Add("topsecret1")
	base := errors.New("auth failed with topsecret1")
	err := r.Error(fmt.Errorf("wrap: %w", base))
	if strings.Contains(err.Error(), "topsecret1") {
		t.Fatalf("leak: %v", err)
	}
	if !errors.Is(err, base) {
		t.Fatal("errors.Is must still reach the original error")
	}
	if r.Error(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestWriterCatchesSecretSplitAcrossWrites(t *testing.T) {
	r := New()
	r.Add("SPLIT-secret-VALUE")
	var out bytes.Buffer
	w := r.Writer(&out)
	for _, chunk := range []string{"line one SPLIT-sec", "ret-VALUE end\nsecond ", "line\ntail without newline SPLIT-secret-VALUE"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SPLIT-secret-VALUE") || strings.Contains(out.String(), "SPLIT-sec") {
		t.Fatalf("leak: %q", out.String())
	}
	if !strings.Contains(out.String(), "second line\n") || !strings.Contains(out.String(), "tail without newline") {
		t.Fatalf("content lost: %q", out.String())
	}
}

func TestWriterBoundsMemory(t *testing.T) {
	r := New()
	var out bytes.Buffer
	w := r.Writer(&out)
	big := bytes.Repeat([]byte("x"), 3*maxLine)
	if _, err := w.Write(big); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		t.Fatal("expected a forced flush for an overlong line")
	}
}
