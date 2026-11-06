package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

func TestGroupDeriveAddsSamplesFromTheMergedBatch(t *testing.T) {
	a := &stub{samples: []model.Sample{{Metric: "in.a", Value: 2}}, complete: true}
	b := &stub{samples: []model.Sample{{Metric: "in.b", Value: 8}}, complete: true}
	derive := func(in []model.Sample) []model.Sample {
		var x, y float64
		for _, s := range in {
			switch s.Metric {
			case "in.a":
				x = s.Value
			case "in.b":
				y = s.Value
			}
		}
		return []model.Sample{{Metric: "out", Value: x / y}}
	}
	g := NewGroupWithDerive("t", derive, a, b)
	s, complete, err := g.Collect(context.Background())
	if err != nil || !complete || len(s) != 3 || s[2].Metric != "out" || s[2].Value != 0.25 {
		t.Fatalf("samples=%+v complete=%v err=%v", s, complete, err)
	}

	// A nil hook is plain NewGroup, including the single-member shortcut.
	if got := NewGroupWithDerive("t", nil, a); got != Collector(a) {
		t.Error("nil derive with one member must return the member unchanged")
	}

	// The hook also runs on partial batches, so it must cope with missing inputs.
	b.samples, b.complete, b.err = nil, false, errors.New("down")
	s, complete, _ = g.Collect(context.Background())
	if complete || len(s) != 2 {
		t.Errorf("samples=%+v complete=%v", s, complete)
	}
}
