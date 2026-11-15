package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestWebAuditAppendListAndPaging(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for i := 0; i < 5; i++ {
		err := s.AppendWebAudit(ctx, WebAuditEvent{At: base.Add(time.Duration(i) * time.Second), Actor: "admin", ActorID: "u1",
			Action: "connection.create", Target: "rds-main", Outcome: AuditOK, Remote: "203.0.113.9", Detail: "n"})
		if err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ListWebAudit(ctx, 0, 3)
	if err != nil || len(all) != 3 || all[0].ID <= all[1].ID {
		t.Fatalf("newest first expected: %+v %v", all, err)
	}
	if all[0].Action != "connection.create" || all[0].Outcome != AuditOK || all[0].Remote != "203.0.113.9" || !all[0].At.Equal(base.Add(4*time.Second)) {
		t.Fatalf("fields lost: %+v", all[0])
	}
	older, err := s.ListWebAudit(ctx, all[2].ID, 10)
	if err != nil || len(older) != 2 {
		t.Fatalf("paging backwards from id %d: %+v %v", all[2].ID, older, err)
	}
}

func TestWebAuditIsAppendOnly(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.AppendWebAudit(ctx, WebAuditEvent{At: base, Action: "login", Outcome: AuditDenied}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE web_audit SET outcome = 'ok'`); err == nil {
		t.Error("UPDATE must be refused")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM web_audit`); err == nil {
		t.Error("DELETE must be refused")
	}
	if ev, _ := s.ListWebAudit(ctx, 0, 10); len(ev) != 1 || ev[0].Outcome != AuditDenied {
		t.Fatalf("history was altered: %+v", ev)
	}
}

func TestWebAuditRejectsBadEventsAndClipsLongFields(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.AppendWebAudit(ctx, WebAuditEvent{At: base, Action: "x", Outcome: "maybe"}); err == nil {
		t.Error("an unknown outcome must be refused")
	}
	if err := s.AppendWebAudit(ctx, WebAuditEvent{At: base, Action: "  ", Outcome: AuditOK}); err == nil {
		t.Error("an empty action must be refused")
	}
	long := strings.Repeat("é", 1000) // two bytes each: clipping must not split one
	if err := s.AppendWebAudit(ctx, WebAuditEvent{At: base, Action: "x", Detail: long, Target: long, Outcome: AuditError}); err != nil {
		t.Fatal(err)
	}
	ev, _ := s.ListWebAudit(ctx, 0, 1)
	if len(ev) != 1 || len(ev[0].Detail) > maxAuditDetail || len(ev[0].Target) > maxAuditField {
		t.Fatalf("fields were not clipped: detail=%d target=%d", len(ev[0].Detail), len(ev[0].Target))
	}
	for _, f := range []string{ev[0].Detail, ev[0].Target} {
		if strings.ContainsRune(f, '�') || !strings.HasPrefix(long, f) {
			t.Fatal("clipping split a multi-byte character")
		}
	}
}
