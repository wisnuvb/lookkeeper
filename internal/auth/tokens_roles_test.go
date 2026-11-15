package auth

import (
	"crypto/sha256"
	"testing"
)

func TestNewToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok, digest, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != 43 { // 32 bytes, unpadded base64url
			t.Fatalf("token length %d", len(tok))
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
		want := sha256.Sum256([]byte(tok))
		if !EqualDigest(digest, want[:]) || !EqualDigest(HashToken(tok), digest) {
			t.Fatal("digest must be SHA-256 of the token")
		}
		if EqualDigest(digest, HashToken(tok+"x")) {
			t.Fatal("different tokens must have different digests")
		}
	}
	if EqualDigest([]byte{1}, []byte{1, 2}) || EqualDigest(nil, []byte{1}) {
		t.Fatal("digests of different length must not be equal")
	}
}

// The expected matrix is written out independently of the production table, so an accidental change
// to who may do what fails here. Read it as the specification of ADR 0005 item 3.
func TestRoleMatrixIsExactlyTheSpecification(t *testing.T) {
	type row struct{ viewer, operator, admin bool }
	want := map[Permission]row{
		PermViewMonitoring:   {true, true, true},
		PermRunPreflight:     {false, true, true},
		PermPlanMigration:    {false, true, true},
		PermRunMigration:     {false, true, true},
		PermApproveMutation:  {false, false, true},
		PermCutover:          {false, false, true},
		PermCleanup:          {false, false, true},
		PermManageConnection: {false, false, true},
		PermTestConnection:   {false, false, true},
		PermManageUsers:      {false, false, true},
		PermViewAudit:        {false, false, true},
		PermManageAlerts:     {false, false, true},
	}
	all := Permissions()
	if len(all) != len(want) {
		t.Fatalf("the production table has %d permissions, the specification %d: update both deliberately", len(all), len(want))
	}
	for p, w := range want {
		if got := Viewer.Can(p); got != w.viewer {
			t.Errorf("viewer %s = %v, want %v", p, got, w.viewer)
		}
		if got := Operator.Can(p); got != w.operator {
			t.Errorf("operator %s = %v, want %v", p, got, w.operator)
		}
		if got := Admin.Can(p); got != w.admin {
			t.Errorf("admin %s = %v, want %v", p, got, w.admin)
		}
	}
}

func TestRolesAreOrderedAndNothingIsUnreachable(t *testing.T) {
	for _, p := range Permissions() {
		// Privilege never decreases up the hierarchy.
		if Viewer.Can(p) && !Operator.Can(p) {
			t.Errorf("%s: operator must include everything viewer can", p)
		}
		if Operator.Can(p) && !Admin.Can(p) {
			t.Errorf("%s: admin must include everything operator can", p)
		}
		if !Admin.Can(p) {
			t.Errorf("%s: no role can do it (dead permission)", p)
		}
	}
}

func TestUnknownRolesAndPermissionsAreDenied(t *testing.T) {
	for _, r := range []Role{"", "root", "ADMIN", "Admin ", "superuser"} {
		for _, p := range Permissions() {
			if r.Can(p) {
				t.Errorf("unknown role %q must be denied %s", r, p)
			}
		}
	}
	for _, p := range []Permission{"", "monitoring.view ", "everything", "migration.*"} {
		for _, r := range Roles() {
			if r.Can(p) {
				t.Errorf("unknown permission %q must be denied to %s", p, r)
			}
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, s := range []string{"viewer", "operator", "admin"} {
		if r, err := ParseRole(s); err != nil || string(r) != s {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"", "Admin", "root", "admin ", "viewer,admin"} {
		if _, err := ParseRole(s); err == nil {
			t.Errorf("%q must be rejected", s)
		}
	}
}
