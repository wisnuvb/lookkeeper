package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected format: %s", h)
	}
	ok, rehash, err := VerifyPassword("correct horse battery staple", h)
	if err != nil || !ok || rehash {
		t.Fatalf("right password: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, _, err = VerifyPassword("correct horse battery stapl", h)
	if err != nil || ok {
		t.Fatalf("wrong password must fail without error: ok=%v err=%v", ok, err)
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
	if strings.Contains(h, "correct horse") {
		t.Fatal("password visible in hash")
	}
}

func TestUnicodeNormalisation(t *testing.T) {
	composed := "café-passphrase-ok"    // é as one code point
	decomposed := "café-passphrase-ok" // e + combining acute
	h, _ := HashPassword(composed)
	ok, _, err := VerifyPassword(decomposed, h)
	if err != nil || !ok {
		t.Fatalf("visually identical passwords must verify (NFKC): ok=%v err=%v", ok, err)
	}
}

func TestRehashWhenParametersAreWeaker(t *testing.T) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte("old password value"), salt, 2, 19*1024, 1, 32) // OWASP minimum
	old := encodeHash(19*1024, 2, 1, salt, key)
	ok, rehash, err := VerifyPassword("old password value", old)
	if err != nil || !ok || !rehash {
		t.Fatalf("weaker params must verify and ask for a rehash: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, rehash, _ := VerifyPassword("wrong", old); ok || rehash {
		t.Fatal("a failed login must never request a rehash")
	}
}

// A stored hash is read from the database; a crafted one must not be able to exhaust memory or CPU.
func TestParseRejectsHostileAndMalformedHashes(t *testing.T) {
	good, _ := HashPassword("a perfectly fine password")
	parts := strings.Split(good, "$")
	salt, key := parts[4], parts[5]
	mk := func(params string) string { return fmt.Sprintf("$argon2id$v=19$%s$%s$%s", params, salt, key) }

	bad := map[string]string{
		"empty":                "",
		"garbage":              "not a hash",
		"wrong algorithm":      strings.Replace(good, "argon2id", "argon2i", 1),
		"bad version":          strings.Replace(good, "v=19", "v=16", 1),
		"memory bomb 4 TiB":    mk("m=4294967295,t=3,p=2"),
		"memory over bound":    mk("m=262145,t=3,p=2"),
		"time bomb":            mk("m=65536,t=1000000,p=2"),
		"zero time":            mk("m=65536,t=0,p=2"),
		"zero lanes":           mk("m=65536,t=3,p=0"),
		"too many lanes":       mk("m=65536,t=3,p=17"),
		"memory below 8*lanes": mk("m=8,t=3,p=2"),
		"memory too tiny":      mk("m=4,t=3,p=1"),
		"missing field":        mk("m=65536,t=3"),
		"extra field":          mk("m=65536,t=3,p=2,x=1"),
		"swapped fields":       mk("t=3,m=65536,p=2"),
		"non numeric":          mk("m=abc,t=3,p=2"),
		"negative":             mk("m=-1,t=3,p=2"),
		"short salt":           fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", "AAAA", key),
		"short key":            fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", salt, "AAAA"),
		"salt not base64":      fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", "!!!!!!!!!!!!!!!!", key),
		"too few parts":        "$argon2id$v=19$m=65536,t=3,p=2$" + salt,
		"too many parts":       good + "$extra",
	}
	for name, h := range bad {
		ok, _, err := VerifyPassword("a perfectly fine password", h)
		if ok || !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%s: want ErrInvalidHash, got ok=%v err=%v", name, ok, err)
		}
	}
}

func TestLongPasswords(t *testing.T) {
	long := strings.Repeat("x", 5000)
	if _, err := HashPassword(long); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("hashing a 5000 byte password must be refused: %v", err)
	}
	h, _ := HashPassword("a perfectly fine password")
	ok, _, err := VerifyPassword(long, h)
	if err != nil || ok {
		t.Fatalf("verifying an overlong password must fail cleanly: ok=%v err=%v", ok, err)
	}
}

func TestDummyVerifyUsesTheCurrentParameters(t *testing.T) {
	// The dummy hash must cost as much as a real one, or login timing reveals which users exist.
	dh, err := dummyHash()
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHash(dh)
	if err != nil {
		t.Fatal(err)
	}
	if h.m != argonMemoryKiB || h.t != argonTime || h.p != argonThreads || len(h.key) != argonKeyLen {
		t.Fatalf("dummy hash parameters differ from the real ones: %+v", h)
	}
	if err := DummyVerify("anything"); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePassword(t *testing.T) {
	good := []string{"correct horse battery staple", "a-long-enough-pass", "pässwörd-with-ünïcode-1", strings.Repeat("ab", 20)}
	for _, p := range good {
		if err := ValidatePassword(p, "alice"); err != nil {
			t.Errorf("%q should be accepted: %v", p, err)
		}
	}
	bad := map[string]string{
		"too short":            "short1!",
		"eleven chars":         "elevenchars",
		"repeated":             strings.Repeat("a", 30),
		"repeated unicode":     strings.Repeat("é", 30),
		"common":               "password1234",
		"common mixed case":    "PassWord1234",
		"contains username":    "my-alice-secret-phrase",
		"contains username ci": "ALICE-is-the-best-user",
		"too long":             strings.Repeat("ab", 600),
		"invalid utf8":         "valid-start-\xff\xfe-end-xyz",
	}
	for name, p := range bad {
		if err := ValidatePassword(p, "alice"); !errors.Is(err, ErrWeakPassword) {
			t.Errorf("%s: want ErrWeakPassword, got %v", name, err)
		}
	}
	// A short username must not block ordinary passwords that happen to contain it.
	if err := ValidatePassword("a-passphrase-with-ab-inside", "ab"); err != nil {
		t.Errorf("a 2-letter username must not be matched inside the password: %v", err)
	}
	// Spaces and punctuation are fine: no composition rules.
	if err := ValidatePassword("correct horse battery staple!", "bob"); err != nil {
		t.Errorf("passphrases must be accepted: %v", err)
	}
}

// cheapHash makes a valid but fast hash (8 KiB, 1 pass) so concurrency tests do not pay for 64 MiB runs.
func cheapHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, 1, 8*1024, 1, 32)
	return encodeHash(8*1024, 1, 1, salt, key)
}

// Review finding 9: unlimited parallel logins (each 64 MiB) could exhaust memory before any throttle ran.
func TestPasswordChecksAreBoundedAndShedLoad(t *testing.T) {
	oldSlots, oldWait := hashSlots, hashWait
	hashSlots, hashWait = make(chan struct{}, 2), 80*time.Millisecond
	defer func() { hashSlots, hashWait = oldSlots, oldWait }()

	h := cheapHash(t, "a perfectly fine password")
	// Occupy every slot, as two long verifications would.
	hashSlots <- struct{}{}
	hashSlots <- struct{}{}

	start := time.Now()
	if _, _, err := VerifyPassword("a perfectly fine password", h); err != ErrBusy {
		t.Fatalf("a saturated server must answer ErrBusy, got %v", err)
	}
	if time.Since(start) < 60*time.Millisecond {
		t.Fatal("a request should queue briefly before being turned away")
	}
	if err := DummyVerify("x"); err != ErrBusy {
		t.Fatalf("the dummy verification is bounded too, got %v", err)
	}
	if _, err := HashPassword("another fine password!"); err != ErrBusy {
		t.Fatalf("hashing is bounded too, got %v", err)
	}
	// Malformed hashes are rejected before taking a slot: they cost nothing.
	if _, _, err := VerifyPassword("x", "garbage"); err != ErrInvalidHash {
		t.Fatalf("an invalid hash must not need a slot, got %v", err)
	}
	// A freed slot lets the next one through.
	<-hashSlots
	if ok, _, err := VerifyPassword("a perfectly fine password", h); err != nil || !ok {
		t.Fatalf("after a slot frees up the check must run: ok=%v err=%v", ok, err)
	}
	<-hashSlots
}

func TestNoMoreThanTheLimitRunAtOnce(t *testing.T) {
	oldSlots, oldWait := hashSlots, hashWait
	hashSlots, hashWait = make(chan struct{}, 2), 5*time.Second
	defer func() { hashSlots, hashWait = oldSlots, oldWait }()
	h := cheapHash(t, "a perfectly fine password")

	var wg sync.WaitGroup
	var mu sync.Mutex
	maxSeen := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = VerifyPassword("a perfectly fine password", h)
		}()
	}
	// Sample the number of occupied slots while the checks run.
	done := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-done:
				return
			default:
				mu.Lock()
				if n := len(hashSlots); n > maxSeen {
					maxSeen = n
				}
				mu.Unlock()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	wg.Wait()
	close(done)
	<-sampled // the sampler must be gone before the deferred restore touches hashSlots
	if maxSeen > 2 || maxSeen == 0 {
		t.Fatalf("saw %d concurrent runs, want between 1 and 2", maxSeen)
	}
}
