package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/secret"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newVault(t *testing.T) *Vault {
	t.Helper()
	v, err := New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

const ctxA = "connection:rds-main:password"

func TestRoundTrip(t *testing.T) {
	v := newVault(t)
	for _, pt := range []string{"hunter2", "", "päss wörd with ünïcode and 🔑", strings.Repeat("x", 100_000)} {
		blob, err := v.Seal([]byte(pt), ctxA)
		if err != nil {
			t.Fatal(err)
		}
		got, err := v.Open(blob, ctxA)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if string(got) != pt {
			t.Fatalf("round trip mismatch for %d bytes", len(pt))
		}
	}
}

func TestEveryCiphertextIsDifferent(t *testing.T) {
	v := newVault(t)
	a, _ := v.Seal([]byte("same"), ctxA)
	b, _ := v.Seal([]byte("same"), ctxA)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (fresh DEK and nonces)")
	}
	if bytes.Contains(a, []byte("same")) {
		t.Fatal("plaintext must not appear in the blob")
	}
}

func TestPlaintextNeverInBlobOrErrors(t *testing.T) {
	v := newVault(t)
	canary := "CANARY-PASSWORD-9f3a"
	blob, _ := v.Seal([]byte(canary), ctxA)
	if bytes.Contains(blob, []byte(canary)) {
		t.Fatal("canary visible in ciphertext")
	}
	_, err := v.Open(blob, "connection:other:password")
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("error must exist and not carry the secret: %v", err)
	}
}

func TestBoundToItsContext(t *testing.T) {
	v := newVault(t)
	blob, _ := v.Seal([]byte("pw"), ctxA)
	for _, other := range []string{"connection:other:password", "connection:rds-main:token", "connection:rds-main:passwor", ctxA + " "} {
		if _, err := v.Open(blob, other); !errors.Is(err, ErrCorrupt) {
			t.Errorf("context %q must not open the blob: %v", other, err)
		}
	}
	if _, err := v.Seal([]byte("pw"), ""); !errors.Is(err, ErrEmptyContext) {
		t.Error("empty context must be refused on Seal")
	}
	if _, err := v.Open(blob, ""); !errors.Is(err, ErrEmptyContext) {
		t.Error("empty context must be refused on Open")
	}
}

// Flipping any single bit anywhere in the blob must make Open fail: header, wrapped key, nonces, payload, tag.
func TestAnyTamperingIsDetected(t *testing.T) {
	v := newVault(t)
	blob, _ := v.Seal([]byte("some secret value"), ctxA)
	for i := range blob {
		for bit := 0; bit < 8; bit += 7 { // lowest and highest bit of each byte keeps the test fast
			mut := bytes.Clone(blob)
			mut[i] ^= 1 << bit
			if pt, err := v.Open(mut, ctxA); err == nil {
				t.Fatalf("flipping bit %d of byte %d went unnoticed (plaintext %q)", bit, i, pt)
			}
		}
	}
}

func TestTruncationAndGarbage(t *testing.T) {
	v := newVault(t)
	blob, _ := v.Seal([]byte("pw"), ctxA)
	for n := 0; n < len(blob); n += 7 {
		if _, err := v.Open(blob[:n], ctxA); err == nil {
			t.Fatalf("truncation to %d bytes must fail", n)
		}
	}
	if _, err := v.Open(nil, ctxA); err == nil {
		t.Fatal("nil blob must fail")
	}
	junk := make([]byte, 200)
	_, _ = rand.Read(junk)
	if _, err := v.Open(junk, ctxA); err == nil {
		t.Fatal("random bytes must fail")
	}
}

func TestWrongMasterKey(t *testing.T) {
	v1, v2 := newVault(t), newVault(t)
	blob, _ := v1.Seal([]byte("pw"), ctxA)
	if _, err := v2.Open(blob, ctxA); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("a different master key must be reported as unknown key, got %v", err)
	}
	id, err := KeyIDOf(blob)
	if err != nil || id != v1.KeyID() || id == v2.KeyID() {
		t.Fatalf("KeyIDOf = %q, %v", id, err)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	v := newVault(t)
	blob, _ := v.Seal([]byte("pw"), ctxA)
	blob[0] = 9
	if _, err := v.Open(blob, ctxA); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
	if _, err := KeyIDOf(blob); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestRewrapRotatesTheMasterKeyWithoutTouchingThePayload(t *testing.T) {
	old, next := newVault(t), newVault(t)
	blob, _ := old.Seal([]byte("rotate me"), ctxA)

	re, err := old.Rewrap(blob, ctxA, next)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := next.Open(re, ctxA); err != nil || string(got) != "rotate me" {
		t.Fatalf("new key must open the rewrapped blob: %q %v", got, err)
	}
	if _, err := old.Open(re, ctxA); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old key must no longer open the rewrapped blob: %v", err)
	}
	if !bytes.Equal(blob[offDataN:], re[offDataN:]) {
		t.Fatal("the encrypted payload must be byte-identical: Rewrap must not re-encrypt")
	}
	if id, _ := KeyIDOf(re); id != next.KeyID() {
		t.Fatalf("rewrapped blob must carry the new key id")
	}
	// Rewrap respects the binding too.
	if _, err := old.Rewrap(blob, "connection:other:password", next); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("rewrap with the wrong context must fail: %v", err)
	}
	if _, err := next.Rewrap(blob, ctxA, old); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("rewrap by a vault that does not own the blob must fail: %v", err)
	}
}

func TestNewRejectsBadKeys(t *testing.T) {
	for name, k := range map[string][]byte{
		"nil":      nil,
		"short":    make([]byte, 16),
		"long":     make([]byte, 33),
		"all zero": make([]byte, 32),
		"all 0xff": bytes.Repeat([]byte{0xff}, 32),
	} {
		if _, err := New(k); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: want ErrInvalidKey, got %v", name, err)
		}
	}
}

func TestMasterKeyFromSecret(t *testing.T) {
	k := newKey(t)
	for name, enc := range map[string]string{
		"std":         base64.StdEncoding.EncodeToString(k),
		"raw std":     base64.RawStdEncoding.EncodeToString(k),
		"url":         base64.URLEncoding.EncodeToString(k),
		"raw url":     base64.RawURLEncoding.EncodeToString(k),
		"with spaces": "  " + base64.StdEncoding.EncodeToString(k) + "\n",
	} {
		got, err := MasterKeyFromSecret(secret.New(enc))
		if err != nil || !bytes.Equal(got, k) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]string{
		"empty":       "",
		"not base64":  "!!!not-base64!!!",
		"too short":   base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"all zero":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"plain words": "correct horse battery staple",
	}
	for name, s := range bad {
		_, err := MasterKeyFromSecret(secret.New(s))
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: want ErrInvalidKey, got %v", name, err)
		}
		if s != "" && strings.Contains(fmt.Sprint(err), s) {
			t.Errorf("%s: the error must not echo the value", name)
		}
	}
}

func TestGenerateMasterKeyIsUsable(t *testing.T) {
	a, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateMasterKey()
	if a == b {
		t.Fatal("keys must be random")
	}
	k, err := MasterKeyFromSecret(secret.New(a))
	if err != nil {
		t.Fatalf("a generated key must be accepted: %v", err)
	}
	if _, err := New(k); err != nil {
		t.Fatal(err)
	}
}

func TestVaultNeverPrintsKeyMaterial(t *testing.T) {
	k := newKey(t)
	v, _ := New(k)
	raw := base64.StdEncoding.EncodeToString(k)
	hexed := fmt.Sprintf("%x", k)
	for _, s := range []string{fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
		if strings.Contains(s, raw) || strings.Contains(s, hexed) || strings.Contains(s, fmt.Sprint(k)) {
			t.Fatalf("key material in %q", s)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "vault", v)
	if strings.Contains(buf.String(), raw) || strings.Contains(buf.String(), hexed) {
		t.Fatalf("key material in log: %s", buf.String())
	}
	if v.KeyID() == hexed[:16] {
		t.Fatal("the key id must not be a prefix of the key")
	}
}

func TestOpenSecretRedactsItself(t *testing.T) {
	v := newVault(t)
	blob, _ := v.Seal([]byte("TopSecret!"), ctxA)
	sv, err := v.OpenSecret(blob, ctxA)
	if err != nil {
		t.Fatal(err)
	}
	if sv.Reveal() != "TopSecret!" {
		t.Fatal("reveal")
	}
	if strings.Contains(fmt.Sprint(sv), "TopSecret!") || strings.Contains(fmt.Sprintf("%#v", sv), "TopSecret!") {
		t.Fatal("secret.Value must redact")
	}
}

// Review finding 6: a rotation must not report success for a row that is already unrecoverable.
func TestRewrapRefusesADamagedPayload(t *testing.T) {
	old, next := newVault(t), newVault(t)
	blob, _ := old.Seal([]byte("rotate me"), ctxA)
	for _, i := range []int{offDataN, offDataN + nonceLen, len(blob) / 2, len(blob) - 1} {
		damaged := bytes.Clone(blob)
		damaged[i] ^= 0x01
		if _, err := old.Rewrap(damaged, ctxA, next); !errors.Is(err, ErrCorrupt) {
			t.Errorf("flipping byte %d: Rewrap must report ErrCorrupt, got %v", i, err)
		}
	}
	// And the good blob still rotates.
	if _, err := old.Rewrap(blob, ctxA, next); err != nil {
		t.Fatal(err)
	}
}

func TestRewrapToNilVaultIsAnErrorNotAPanic(t *testing.T) {
	v := newVault(t)
	blob, _ := v.Seal([]byte("x"), ctxA)
	if _, err := v.Rewrap(blob, ctxA, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("got %v", err)
	}
}

// Review finding 7, documented and pinned: binding stops cross-field swaps but not rollback within the
// same context. Callers that need rollback resistance put a revision in the context.
func TestRollbackWithinTheSameContextIsPossibleUnlessTheContextCarriesARevision(t *testing.T) {
	v := newVault(t)
	oldBlob, _ := v.Seal([]byte("old password"), "connection:c1:password")
	if got, err := v.Open(oldBlob, "connection:c1:password"); err != nil || string(got) != "old password" {
		t.Fatal("known limit: an older blob in the same context still opens")
	}
	// With a revision in the context, the stale blob no longer opens once the revision moved on.
	rev1, _ := v.Seal([]byte("old password"), "connection:c1:password:v1")
	if _, err := v.Open(rev1, "connection:c1:password:v2"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a blob sealed for revision 1 must not open as revision 2: %v", err)
	}
}
