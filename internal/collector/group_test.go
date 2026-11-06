package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

type stub struct {
	samples  []model.Sample
	complete bool
	err      error
	closed   bool
	audit    []string
}

func (s *stub) Target() string { return "t" }
func (s *stub) Collect(context.Context) ([]model.Sample, bool, error) {
	return s.samples, s.complete, s.err
}
func (s *stub) Close() error                            { s.closed = true; return nil }
func (s *stub) Audit(context.Context) ([]string, error) { return s.audit, nil }

func TestNewGroupWithOneMemberReturnsIt(t *testing.T) {
	a := &stub{}
	if got := NewGroup("t", a); got != Collector(a) {
		t.Fatal("a single member must be returned unchanged")
	}
}

func TestGroupMergesAndIsOnlyCompleteWhenAllAre(t *testing.T) {
	boom := errors.New("cloud down")
	a := &stub{samples: []model.Sample{{Metric: "a"}}, complete: true, audit: []string{"warn"}}
	b := &stub{samples: []model.Sample{{Metric: "b"}}, complete: false, err: boom}
	g := NewGroup("t", a, b)

	s, complete, err := g.Collect(context.Background())
	if len(s) != 2 || complete || !errors.Is(err, boom) {
		t.Fatalf("samples=%d complete=%v err=%v", len(s), complete, err)
	}
	w, err := g.(interface {
		Audit(context.Context) ([]string, error)
	}).Audit(context.Background())
	if err != nil || len(w) != 1 || w[0] != "warn" {
		t.Errorf("audit must be delegated: %v %v", w, err)
	}
	if err := g.Close(); err != nil || !a.closed || !b.closed {
		t.Errorf("all members must be closed: %v", err)
	}
}
