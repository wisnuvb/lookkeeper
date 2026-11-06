package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Route sends events of the listed severities (empty = all) to the notifiers.
type Route struct {
	Severities []model.Severity
	Notifiers  []Notifier
}

func (r Route) matches(e model.Event) bool {
	if len(r.Severities) == 0 {
		return true
	}
	for _, s := range r.Severities {
		if s == e.Severity {
			return true
		}
	}
	return false
}

// Targets returns the distinct notifiers that should receive e.
func Targets(routes []Route, e model.Event) []Notifier {
	seen := map[string]bool{}
	var out []Notifier
	for _, r := range routes {
		if !r.matches(e) {
			continue
		}
		for _, n := range r.Notifiers {
			if !seen[n.Name()] {
				seen[n.Name()] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// Dispatcher delivers events asynchronously so that a slow or failing channel
// never blocks collection or alert evaluation. The queue is bounded: when it is
// full the event is dropped and logged, which is preferable to unbounded memory.
type Dispatcher struct {
	routes []Route
	log    *slog.Logger
	queue  chan job
	wg     sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	dropped int
	failed  int
	sent    int
}

type job struct {
	n Notifier
	e model.Event
}

// NewDispatcher starts workers goroutines draining a queue of the given size.
func NewDispatcher(routes []Route, log *slog.Logger, workers, queueSize int) *Dispatcher {
	if workers <= 0 {
		workers = 2
	}
	if queueSize <= 0 {
		queueSize = 256
	}
	d := &Dispatcher{routes: routes, log: log, queue: make(chan job, queueSize)}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	return d
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for j := range d.queue {
		// Delivery gets its own deadline, independent of the collection context, so
		// a shutdown can still flush what was already queued.
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		err := j.n.Send(ctx, j.e)
		cancel()
		d.mu.Lock()
		if err != nil {
			d.failed++
		} else {
			d.sent++
		}
		d.mu.Unlock()
		if err != nil {
			d.log.Error("alert delivery failed", "channel", j.n.Name(), "rule", j.e.Rule, "target", j.e.Target, "error", err)
		}
	}
}

// Dispatch queues e for every matching notifier. It never blocks.
func (d *Dispatcher) Dispatch(e model.Event) {
	targets := Targets(d.routes, e)
	if len(targets) == 0 {
		d.log.Warn("alert has no matching route", "rule", e.Rule, "target", e.Target, "severity", e.Severity)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		d.log.Warn("alert dispatcher is closed; event not sent", "rule", e.Rule, "target", e.Target)
		return
	}
	for _, n := range targets {
		select {
		case d.queue <- job{n: n, e: e}:
		default:
			d.dropped++
			d.log.Error("alert queue full; event dropped", "channel", n.Name(), "rule", e.Rule, "target", e.Target)
		}
	}
}

// Close stops accepting events and waits for queued deliveries, up to ctx.
func (d *Dispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("flush alert queue: %w", ctx.Err())
	}
}

// Stats returns delivery counters.
func (d *Dispatcher) Stats() (sent, failed, dropped int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sent, d.failed, d.dropped
}
