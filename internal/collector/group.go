package collector

import (
	"context"
	"errors"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// auditor is implemented by collectors that can audit the privileges of their role.
type auditor interface {
	Audit(ctx context.Context) ([]string, error)
}

// Group runs several collectors for the same target (for example the database
// itself plus a cloud metrics reader) and merges their output. A batch is
// complete only if every member's batch is complete.
type Group struct {
	target  string
	members []Collector
	derive  DeriveFunc
}

// DeriveFunc computes extra samples from the merged output of a group's members,
// for metrics that combine inputs from different collectors (for example retained
// WAL from the database and free storage from a cloud reader). It receives every
// sample collected and returns only the new ones.
type DeriveFunc func(samples []model.Sample) []model.Sample

// NewGroup returns a single Collector for target. With one member it returns
// that member unchanged.
func NewGroup(target string, members ...Collector) Collector {
	if len(members) == 1 {
		return members[0]
	}
	return &Group{target: target, members: members}
}

// NewGroupWithDerive is NewGroup plus a derive hook applied to the merged
// samples of every collection. A nil derive is the same as NewGroup.
func NewGroupWithDerive(target string, derive DeriveFunc, members ...Collector) Collector {
	if derive == nil {
		return NewGroup(target, members...)
	}
	return &Group{target: target, members: members, derive: derive}
}

// Target implements Collector.
func (g *Group) Target() string { return g.target }

// Collect implements Collector. Members run sequentially; one failing does not
// stop the others.
func (g *Group) Collect(ctx context.Context) ([]model.Sample, bool, error) {
	var all []model.Sample
	complete := true
	var errs []error
	for _, m := range g.members {
		s, c, err := m.Collect(ctx)
		all = append(all, s...)
		complete = complete && c
		if err != nil {
			errs = append(errs, err)
		}
	}
	if g.derive != nil {
		all = append(all, g.derive(all)...)
	}
	return all, complete, errors.Join(errs...)
}

// Audit implements the optional audit interface by delegating to members that
// support it.
func (g *Group) Audit(ctx context.Context) ([]string, error) {
	var out []string
	var errs []error
	for _, m := range g.members {
		if a, ok := m.(auditor); ok {
			w, err := a.Audit(ctx)
			out = append(out, w...)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return out, errors.Join(errs...)
}

// Close implements Collector.
func (g *Group) Close() error {
	var errs []error
	for _, m := range g.members {
		if err := m.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
