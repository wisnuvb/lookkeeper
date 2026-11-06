package service

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/alert/notify"
	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/prom"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

const (
	eventRetention  = 90 * 24 * time.Hour
	pruneEvery      = time.Hour
	shutdownFlush   = 20 * time.Second
	storeWriteLimit = 10 * time.Second
)

// runner holds the state shared by the per-target monitor loops.
type runner struct {
	svc        *Service
	store      *store.Store
	engine     *rules.Engine
	dispatcher *notify.Dispatcher
	lastTick   atomic.Int64   // unix nanoseconds of the most recent finished tick
	reg        *prom.Registry // nil unless monitor.metrics is configured (all methods are nil-safe)
}

// MonitorRun collects metrics from every configured target until ctx is
// cancelled, stores them, evaluates alert rules and delivers notifications.
func (s *Service) MonitorRun(ctx context.Context) error {
	path, err := s.StorePath()
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, path)
	if err != nil {
		return fmt.Errorf("open state store: %w", err)
	}
	defer st.Close()

	channels, err := s.buildChannels(ctx)
	if err != nil {
		return s.redactErr(err)
	}
	routes := s.buildRoutes(channels)
	if len(routes) == 0 {
		s.log.Warn("no notification channel configured: alerts will only be logged and stored")
	}
	dispatcher := notify.NewDispatcher(routes, s.log, 2, 256)

	engine, err := rules.New(s.rules, s.engineOptions())
	if err != nil {
		return err
	}
	if snaps, err := st.LoadAlertState(ctx); err != nil {
		s.log.Warn("could not load previous alert state; starting clean", "error", err)
	} else {
		engine.Import(snaps)
		if n := len(engine.Active()); n > 0 {
			s.log.Info("restored active alerts from the previous run", "count", n)
		}
	}

	r := &runner{svc: s, store: st, engine: engine, dispatcher: dispatcher}
	r.lastTick.Store(s.deps.Now().UnixNano())

	// Optional Prometheus endpoint: off unless monitor.metrics is configured. A
	// bad or busy address fails the start instead of silently running without it.
	var metrics *prom.Server
	if m := s.cfg.Monitor.Metrics; m != nil {
		r.reg = prom.NewRegistry()
		r.reg.SetAlerts(engine.Active()) // alerts restored from the previous run
		metrics, err = prom.Start(r.reg, prom.ServerOptions{Listen: m.Listen, AllowNonLoopback: m.AllowNonLoopback, Log: s.log})
		if err != nil {
			return err
		}
		s.log.Info("prometheus endpoint listening", "addr", metrics.Addr())
	}

	targets := s.cfg.Monitor.Targets
	s.log.Info("monitor started",
		"targets", targets, "interval", s.cfg.Monitor.Interval.D().String(),
		"channels", s.cfg.ChannelNames(), "store", path)

	var wg sync.WaitGroup
	for _, name := range targets {
		col := s.newCollector(name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer col.Close()
			r.loop(ctx, col)
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); r.pruneLoop(ctx) }()
	if hb := s.cfg.Monitor.Heartbeat; hb != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.heartbeatLoop(ctx) }()
	}

	<-ctx.Done()
	s.log.Info("shutting down: waiting for in-flight collections")
	if metrics != nil {
		mctx, mcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if err := metrics.Shutdown(mctx); err != nil {
			s.log.Warn("prometheus endpoint did not shut down cleanly", "error", err)
		}
		mcancel()
	}
	wg.Wait()

	// Persist final state and flush queued notifications even though ctx is done.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeWriteLimit)
	if err := st.SaveAlertState(wctx, engine.Export()); err != nil {
		s.log.Error("could not save alert state on shutdown", "error", err)
	}
	cancel()
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownFlush)
	defer cancel()
	if err := dispatcher.Close(fctx); err != nil {
		s.log.Error("notification queue not fully flushed", "error", err)
	}
	sent, failed, dropped := dispatcher.Stats()
	s.log.Info("monitor stopped", "notifications_sent", sent, "notifications_failed", failed, "notifications_dropped", dropped)
	return nil
}

func (r *runner) loop(ctx context.Context, col collector.Collector) {
	interval := r.svc.cfg.Monitor.Interval.D()
	log := r.svc.log.With("target", col.Target())

	// Audit privileges once at start so over-privileged roles are noticed early.
	if a, ok := col.(interface {
		Audit(context.Context) ([]string, error)
	}); ok {
		actx, cancel := context.WithTimeout(ctx, r.svc.cfg.Monitor.QueryTimeout.D())
		warnings, err := a.Audit(actx)
		cancel()
		if err != nil {
			log.Warn("role privilege audit failed", "error", r.svc.redactErr(err))
		}
		for _, w := range warnings {
			log.Warn("role privilege warning", "detail", w)
		}
	}

	// Jitter the first tick so many targets do not hit their servers in lockstep.
	jitter := time.Duration(rand.Int64N(int64(interval)/10 + 1))
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r.tick(ctx, col)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick performs one collect → store → evaluate → notify cycle. A panic in a
// collector is logged with its stack and does not kill the daemon.
func (r *runner) tick(ctx context.Context, col collector.Collector) {
	log := r.svc.log.With("target", col.Target())
	defer func() {
		if p := recover(); p != nil {
			log.Error("panic during collection (continuing)", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
		r.lastTick.Store(r.svc.deps.Now().UnixNano())
	}()

	timeout := r.svc.cfg.Monitor.QueryTimeout.D() * 6
	if iv := r.svc.cfg.Monitor.Interval.D(); timeout > iv {
		timeout = iv
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	samples, complete, err := col.Collect(cctx)
	cancel()
	if ctx.Err() != nil {
		return // shutting down: do not record a half-finished collection
	}
	if err != nil {
		log.Warn("collection problem", "complete", complete, "error", r.svc.redactErr(err))
	}

	wctx, wcancel := context.WithTimeout(context.WithoutCancel(ctx), storeWriteLimit)
	defer wcancel()
	if err := r.store.AppendSamples(wctx, samples); err != nil {
		log.Error("could not store samples", "error", err)
	}
	events := r.engine.Eval(r.svc.deps.Now(), col.Target(), samples, complete)
	r.reg.UpdateTarget(col.Target(), samples, complete, r.svc.deps.Now())
	r.reg.SetAlerts(r.engine.Active())
	for _, ev := range events {
		log.Info("alert event", "rule", ev.Rule, "state", ev.State, "severity", ev.Severity, "summary", ev.Summary)
		if err := r.store.AppendEvent(wctx, ev); err != nil {
			log.Error("could not store event", "error", err)
		}
		r.dispatcher.Dispatch(ev)
	}
	if err := r.store.SaveAlertState(wctx, r.engine.Export()); err != nil {
		log.Error("could not save alert state", "error", err)
	}
}

func (r *runner) pruneLoop(ctx context.Context) {
	prune := func() {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeWriteLimit)
		defer cancel()
		now := r.svc.deps.Now()
		if n, err := r.store.PruneSamples(wctx, now.Add(-r.svc.cfg.Monitor.Retention.D())); err != nil {
			r.svc.log.Error("prune samples failed", "error", err)
		} else if n > 0 {
			r.svc.log.Info("pruned old samples", "rows", n)
		}
		if _, err := r.store.PruneEvents(wctx, now.Add(-eventRetention)); err != nil {
			r.svc.log.Error("prune events failed", "error", err)
		}
	}
	prune()
	t := time.NewTicker(pruneEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}

// heartbeatLoop pings the dead-man URL, but only while collection ticks are
// actually happening: a hung monitor must stop pinging so the outside service
// raises the alarm.
func (r *runner) heartbeatLoop(ctx context.Context) {
	hbCfg := r.svc.cfg.Monitor.Heartbeat
	url, err := r.svc.resolveSecret(ctx, hbCfg.URL, "heartbeat URL")
	if err != nil {
		r.svc.log.Error("heartbeat disabled: cannot resolve URL", "error", r.svc.redactErr(err))
		return
	}
	hb := &notify.Heartbeat{URL: url, Client: r.svc.httpClient()}
	interval := hbCfg.Interval.D()
	staleAfter := 3 * r.svc.cfg.Monitor.Interval.D()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		last := time.Unix(0, r.lastTick.Load())
		if r.svc.deps.Now().Sub(last) <= staleAfter {
			pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := hb.Ping(pctx); err != nil {
				r.svc.log.Warn("heartbeat ping failed", "error", r.svc.redactErr(err))
			}
			cancel()
		} else {
			r.svc.log.Error("collection loop looks stalled; heartbeat withheld", "last_tick", last)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
