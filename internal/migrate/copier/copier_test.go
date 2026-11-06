//go:build unix

package copier

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/migrate"
	"github.com/wisnuvb/lockkeeper/internal/migrate/runner"
	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

const srcPW = "CANARY_SRC_PW_81c3"
const tgtPW = "CANARY_TGT_PW_c20e"

func testRunner(t *testing.T, toolDir string) *runner.Runner {
	t.Helper()
	root := t.TempDir()
	return &runner.Runner{BaseDir: filepath.Join(root, "run"), LogDir: filepath.Join(root, "logs"), Redactor: redact.New(),
		Grace: 500 * time.Millisecond, Path: toolDir + ":/usr/bin:/bin"}
}

func tool(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func input(t *testing.T) migrate.CopyInput {
	t.Helper()
	return migrate.CopyInput{
		Source:     migrate.Endpoint{Host: "src.example", Port: 5432, Database: "app", User: "lk", Password: secret.New(srcPW), TLSMode: "verify-full"},
		Target:     migrate.Endpoint{Host: "tgt.example", Port: 5432, Database: "app", User: "admin", Password: secret.New(tgtPW), TLSMode: "verify-full"},
		SnapshotID: "00000003-0000001B-1", WorkDir: filepath.Join(t.TempDir(), "work"), SourceMajor: 17, TableJobs: 3, IndexJobs: 2,
	}
}

func TestNewRejectsUnknownKind(t *testing.T) {
	if _, err := New(Config{Kind: "rsync", Runner: &runner.Runner{}}); err == nil {
		t.Fatal("unknown copier must be refused")
	}
	if _, err := New(Config{Kind: KindPgcopydb}); err == nil {
		t.Fatal("a runner is required")
	}
	c, err := New(Config{Runner: &runner.Runner{}})
	if err != nil || c.Name() != KindPgcopydb {
		t.Fatalf("pgcopydb is the default: %v %v", c, err)
	}
}

func TestDescribeHasNoPasswordAndNoForbiddenFlags(t *testing.T) {
	in := input(t)
	for _, kind := range []string{KindPgcopydb, KindPgdump} {
		c, _ := New(Config{Kind: kind, Runner: &runner.Runner{}})
		text := strings.Join(c.Describe(in), "\n")
		if strings.Contains(text, srcPW) || strings.Contains(text, tgtPW) {
			t.Fatalf("%s: password in the displayed command line", kind)
		}
		if !strings.Contains(text, in.SnapshotID) {
			t.Errorf("%s: the copy must run inside the snapshot: %s", kind, text)
		}
		for _, f := range forbiddenFlags {
			if strings.Contains(text, f) {
				t.Errorf("%s: forbidden flag %s in %s", kind, f, text)
			}
		}
	}
}

func TestPgcopydbCheckVersionPinning(t *testing.T) {
	dir := t.TempDir()
	tool(t, dir, "pg_dump", `echo "pg_dump (PostgreSQL) 17.2"`)
	for _, tc := range []struct {
		name, out, pin string
		allow          bool
		wantErr        string
	}{
		{"pinned and matching", "pgcopydb version 0.18", "0.18", false, ""},
		{"other version refused", "pgcopydb version 0.19", "0.18", false, "not the pinned version"},
		{"other version allowed", "pgcopydb version 0.19", "0.18", true, ""},
		{"empty version (official image) refused", "pgcopydb version ", "0.18", false, "does not report its version"},
		{"empty version allowed when opted in", "pgcopydb version ", "0.18", true, ""},
		{"no pin accepts any", "pgcopydb version 9.9", "", false, ""},
		{"garbage", "hello", "0.18", false, "cannot determine"},
		{"version line glued to a log line", "pgcopydb version 2026-11-06 11:46:57.383 1 INFO main.c:150 Running", "0.18", false, "does not report its version"},
		{"log line first, version after", "2026-11-06 1 INFO Running pgcopydb version  from x\npgcopydb version 0.18", "0.18", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool(t, dir, "pgcopydb", `echo "`+tc.out+`"`)
			c, _ := New(Config{Kind: KindPgcopydb, Runner: testRunner(t, dir), PinnedVersion: tc.pin, AllowUntested: tc.allow})
			err := c.Check(context.Background(), 17)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestClientToolMustBeAtLeastTheSourceMajor(t *testing.T) {
	dir := t.TempDir()
	tool(t, dir, "pgcopydb", `echo "pgcopydb version 0.18"`)
	tool(t, dir, "pg_dump", `echo "pg_dump (PostgreSQL) 16.14 (Debian 16.14-1.pgdg12+1)"`)
	tool(t, dir, "pg_restore", `echo "pg_restore (PostgreSQL) 16.14"`)
	for _, kind := range []string{KindPgcopydb, KindPgdump} {
		c, _ := New(Config{Kind: kind, Runner: testRunner(t, dir), PinnedVersion: "0.18"})
		err := c.Check(context.Background(), 17)
		if err == nil || !strings.Contains(err.Error(), "server version mismatch") {
			t.Fatalf("%s: a pg_dump older than the source must be refused up front, got %v", kind, err)
		}
		if err := c.Check(context.Background(), 14); err != nil {
			t.Fatalf("%s: a newer client than the source is fine: %v", kind, err)
		}
	}
	c, _ := New(Config{Kind: KindPgcopydb, Runner: testRunner(t, t.TempDir())})
	if err := c.Check(context.Background(), 17); err == nil {
		t.Fatal("a missing tool must be an error")
	}
}

func TestPgcopydbCopyArgsEnvAndFreshWorkDir(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(t.TempDir(), "rec")
	tool(t, dir, "pgcopydb", `
{ echo "ARGS: $*"; env; echo "PASSFILE-EXISTS: $(test -f "$PGPASSFILE" && echo yes)"; } > `+rec)
	c, _ := New(Config{Kind: KindPgcopydb, Runner: testRunner(t, dir)})
	in := input(t)
	in.NoOwner = true
	if err := c.Copy(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(rec)
	got := string(b)
	for _, want := range []string{"clone", "--snapshot " + in.SnapshotID, "--table-jobs 3", "--index-jobs 2", "--no-owner", "--dir " + in.WorkDir, "postgres://lk@src.example:5432/app", "postgres://admin@tgt.example:5432/app", "PASSFILE-EXISTS: yes"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, srcPW) || strings.Contains(got, tgtPW) {
		t.Fatal("a password reached the child's argv or environment")
	}
	for _, f := range forbiddenFlags {
		if strings.Contains(got, f) {
			t.Fatalf("forbidden flag %s passed", f)
		}
	}

	// A second attempt in the same, now non-empty, work directory is refused:
	// pgcopydb would need --restart, which Lockkeeper never passes.
	_ = os.WriteFile(filepath.Join(in.WorkDir, "leftover"), []byte("x"), 0o600)
	if err := c.Copy(context.Background(), in); err == nil || !strings.Contains(err.Error(), "fresh") {
		t.Fatalf("a reused work directory must be refused: %v", err)
	}
	in.SnapshotID = ""
	in.WorkDir = filepath.Join(t.TempDir(), "w2")
	if err := c.Copy(context.Background(), in); err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("no snapshot must be refused: %v", err)
	}
}

func TestPgdumpCopyOrderAndDumpIsAlwaysRemoved(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(t.TempDir(), "rec")
	tool(t, dir, "pg_dump", `
echo "pg_dump $*" >> `+rec+`
for a in "$@"; do last="$a"; done
prev=""; for a in "$@"; do if [ "$prev" = "-f" ]; then out="$a"; fi; prev="$a"; done
mkdir -p "$out"; echo "ROW DATA customer@example.com" > "$out/1.dat"`)
	tool(t, dir, "pg_restore", `
echo "pg_restore $*" >> `+rec+`
test -f "$(for a in "$@"; do :; done; echo "$a")/1.dat" || exit 9
exit ${RESTORE_EXIT:-0}`)
	c, _ := New(Config{Kind: KindPgdump, Runner: testRunner(t, dir)})
	in := input(t)
	if err := c.Copy(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(rec)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "pg_dump") || !strings.HasPrefix(lines[1], "pg_restore") {
		t.Fatalf("dump must run before restore: %v", lines)
	}
	for _, want := range []string{"--snapshot=" + in.SnapshotID, "-Fd", "-j 3", "--no-publications", "--no-password"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("pg_dump args lack %q: %s", want, lines[0])
		}
	}
	if !strings.Contains(lines[1], "--exit-on-error") || !strings.Contains(lines[1], "-j 2") {
		t.Errorf("pg_restore args: %s", lines[1])
	}
	if strings.Contains(string(b), srcPW) || strings.Contains(string(b), tgtPW) {
		t.Fatal("password on argv")
	}
	if _, err := os.Stat(filepath.Join(in.WorkDir, "dump")); !os.IsNotExist(err) {
		t.Fatal("the dump directory holds table data and must be removed after a successful copy")
	}

	// A failing restore also removes the dump.
	tool(t, dir, "pg_restore", `echo "pg_restore failed: boom" >&2; exit 1`)
	in.WorkDir = filepath.Join(t.TempDir(), "w2")
	if err := c.Copy(context.Background(), in); err == nil || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("restore failure must be reported: %v", err)
	}
	if _, err := os.Stat(filepath.Join(in.WorkDir, "dump")); !os.IsNotExist(err) {
		t.Fatal("the dump directory must be removed after a failed copy too")
	}
}
