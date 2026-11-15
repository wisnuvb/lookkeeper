package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/auth"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// fakeHash passes the store's "is this an argon2id string" check without paying for a real hash.
const fakeHash = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA"

func TestUsersCreateAndLookupAreCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	u, err := s.CreateUser(ctx, "  Alice ", auth.Operator, fakeHash, base)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || u.Role != auth.Operator || u.Disabled || !u.LastLoginAt.IsZero() {
		t.Fatalf("unexpected user %+v", u)
	}
	for _, name := range []string{"alice", "ALICE", " Alice\t"} {
		got, err := s.GetUserByName(ctx, name)
		if err != nil || got.ID != u.ID {
			t.Fatalf("lookup %q: %v %v", name, got, err)
		}
	}
	if _, err := s.CreateUser(ctx, "ALICE", auth.Viewer, fakeHash, base); !errors.Is(err, ErrUserExists) {
		t.Fatalf("a second account under the same canonical name must be refused, got %v", err)
	}
	if _, err := s.GetUserByName(ctx, "bob"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
}

func TestUsersRejectBadInput(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	cases := map[string]struct {
		name string
		role auth.Role
		hash string
	}{
		"empty name":      {"   ", auth.Viewer, fakeHash},
		"long name":       {strings.Repeat("a", 65), auth.Viewer, fakeHash},
		"unknown role":    {"x", auth.Role("root"), fakeHash},
		"plaintext hash":  {"x", auth.Viewer, "hunter2"},
		"other algorithm": {"x", auth.Viewer, "$2a$10$abcdefghijklmnopqrstuv"},
	}
	for name, c := range cases {
		if _, err := s.CreateUser(ctx, c.name, c.role, c.hash, base); !errors.Is(err, ErrBadUser) {
			t.Errorf("%s: want ErrBadUser, got %v", name, err)
		}
	}
	if n, _ := s.CountUsers(ctx); n != 0 {
		t.Fatalf("a rejected user must not be stored, have %d", n)
	}
}

func TestFirstAdminOnlyOnceEvenWhenRaced(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.CreateFirstAdmin(ctx, "admin"+string(rune('a'+i)), fakeHash, base)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	ok, done := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrSetupDone):
			done++
		default:
			t.Fatalf("unexpected error %v", err)
		}
	}
	if ok != 1 || done != 7 {
		t.Fatalf("exactly one setup must win: ok=%d done=%d", ok, done)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("want 1 user, have %d", n)
	}
	// Setup stays closed after the admin exists, even for a different name.
	if _, err := s.CreateFirstAdmin(ctx, "another", fakeHash, base); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("want ErrSetupDone, got %v", err)
	}
}

func TestLastActiveAdminCannotBeDemotedOrDisabled(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	a1, err := s.CreateFirstAdmin(ctx, "root", fakeHash, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(ctx, a1.ID, auth.Viewer, base); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting the only admin: want ErrLastAdmin, got %v", err)
	}
	if err := s.SetDisabled(ctx, a1.ID, true, base); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disabling the only admin: want ErrLastAdmin, got %v", err)
	}
	if got, _ := s.GetUser(ctx, a1.ID); got.Role != auth.Admin || got.Disabled {
		t.Fatalf("a refused change must leave the account untouched: %+v", got)
	}

	a2, err := s.CreateUser(ctx, "second", auth.Admin, fakeHash, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, a1.ID, true, base); err != nil {
		t.Fatalf("with a second active admin the first may be disabled: %v", err)
	}
	// a1 is now disabled, so a2 is the last ACTIVE admin even though two admin rows exist.
	if err := s.SetRole(ctx, a2.ID, auth.Operator, base); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("a disabled admin does not count: want ErrLastAdmin, got %v", err)
	}
	// Re-enabling and then demoting works because a2 is no longer alone.
	if err := s.SetDisabled(ctx, a1.ID, false, base); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(ctx, a2.ID, auth.Operator, base); err != nil {
		t.Fatalf("demoting one of two admins: %v", err)
	}
	// Changing something unrelated on the last admin is fine.
	if err := s.SetPasswordHash(ctx, a1.ID, fakeHash+"x", base); err != nil {
		t.Fatalf("a password change is not a demotion: %v", err)
	}
}

func TestPasswordChangeStampsTimeAndRejectsPlaintext(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	u, _ := s.CreateUser(ctx, "carol", auth.Viewer, fakeHash, base)
	later := base.Add(time.Hour)
	if err := s.SetRole(ctx, u.ID, auth.Operator, later); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if !got.PasswordChangedAt.Equal(base) || !got.UpdatedAt.Equal(later) {
		t.Fatalf("a role change must not look like a password change: %+v", got)
	}
	if err := s.SetPasswordHash(ctx, u.ID, "plain", later); !errors.Is(err, ErrBadUser) {
		t.Fatalf("want ErrBadUser, got %v", err)
	}
	if err := s.SetPasswordHash(ctx, u.ID, fakeHash+"2", later); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if !got.PasswordChangedAt.Equal(later) || got.PasswordHash != fakeHash+"2" {
		t.Fatalf("password change not recorded: %+v", got)
	}
	if err := s.SetPasswordHash(ctx, "nope", fakeHash, later); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
	if err := s.RecordLogin(ctx, u.ID, later); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetUser(ctx, u.ID); !got.LastLoginAt.Equal(later) {
		t.Fatalf("login not recorded: %+v", got)
	}
	if err := s.RecordLogin(ctx, "nope", later); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
}

func TestListUsersIsOrdered(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for _, n := range []string{"zed", "amy", "Mia"} {
		if _, err := s.CreateUser(ctx, n, auth.Viewer, fakeHash, base); err != nil {
			t.Fatal(err)
		}
	}
	us, err := s.ListUsers(ctx)
	if err != nil || len(us) != 3 || us[0].Username != "amy" || us[1].Username != "mia" || us[2].Username != "zed" {
		t.Fatalf("got %v %v", us, err)
	}
}

// The schema itself refuses what the Go code should never send, so a bug above cannot corrupt state.
func TestSchemaConstraintsHoldWithoutTheGoChecks(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	exec := func(q string, args ...any) error { _, err := s.db.ExecContext(ctx, q, args...); return err }
	if err := exec(`INSERT INTO users (id, username, role, password_hash, created_at, updated_at, password_changed_at) VALUES ('x', 'x', 'root', 'h', 0, 0, 0)`); err == nil {
		t.Error("the schema must refuse an unknown role")
	}
	if err := exec(`INSERT INTO sessions (token_hash, user_id, created_at, last_seen, expires_at, idle_until) VALUES (x'00', 'ghost', 0, 0, 0, 0)`); err == nil {
		t.Error("the schema must refuse a session for an unknown user and a short digest")
	}
	if err := exec(`INSERT INTO web_audit (ts, action, outcome) VALUES (0, 'a', 'maybe')`); err == nil {
		t.Error("the schema must refuse an unknown audit outcome")
	}
}

func TestUpgradeFromSchemaV2KeepsMigrationsAndAddsWebTables(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "lockkeeper.db")
	old, err := open(ctx, path, migrations[:2])
	if err != nil {
		t.Fatal(err)
	}
	if err := old.AppendSamples(ctx, []model.Sample{{Target: "db", Metric: "m", Value: 9, At: base}}); err != nil {
		t.Fatal(err)
	}
	if _, err := old.db.ExecContext(ctx, `SELECT count(*) FROM users`); err == nil {
		t.Fatal("a v2 database must not have the users table")
	}
	_ = old.Close()

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer s.Close()
	if got, err := s.LatestSamples(ctx, "db"); err != nil || len(got) != 1 || got[0].Value != 9 {
		t.Fatalf("data lost in the upgrade: %v %v", got, err)
	}
	if _, err := s.CreateFirstAdmin(ctx, "admin", fakeHash, base); err != nil {
		t.Fatalf("new tables unusable after the upgrade: %v", err)
	}
	if _, err := os.Stat(path + ".bak-v2"); err != nil {
		t.Fatalf("the pre-upgrade backup is missing: %v", err)
	}
}
