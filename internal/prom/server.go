package prom

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/config"
)

// ServerOptions configures Start.
type ServerOptions struct {
	// Listen is host:port. It must be a loopback address unless AllowNonLoopback.
	Listen string
	// AllowNonLoopback permits a non-loopback listen address. The endpoint has no
	// authentication, so Start logs a warning when this is used.
	AllowNonLoopback bool
	// Log receives the startup warning and serve errors. Nil discards.
	Log *slog.Logger
}

// Server is the running HTTP endpoint.
type Server struct {
	srv  *http.Server
	ln   net.Listener
	done chan struct{}
}

// Start validates the listen address, binds it and serves GET /metrics in the
// background. Binding happens before Start returns, so a bad or busy address is
// an immediate error rather than a log line later. Call Shutdown to stop.
func Start(reg *Registry, opts ServerOptions) (*Server, error) {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	warning, err := config.CheckMetricsListen(opts.Listen, opts.AllowNonLoopback)
	if err != nil {
		return nil, fmt.Errorf("prometheus endpoint: %w", err)
	}
	if warning != "" {
		log.Warn(warning)
	}
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("prometheus endpoint: listen on %s: %w", opts.Listen, err)
	}
	// Defence in depth: a host name such as "localhost" is resolved by the OS at
	// bind time; never trust the name, check where the socket really is.
	if !opts.AllowNonLoopback {
		if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
			_ = ln.Close()
			return nil, fmt.Errorf("prometheus endpoint: %s bound to non-loopback address %s; refusing", opts.Listen, ln.Addr())
		}
	}

	s := &Server{
		ln:   ln,
		done: make(chan struct{}),
		srv: &http.Server{
			Handler:           Handler(reg, !opts.AllowNonLoopback),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		},
	}
	go func() {
		defer close(s.done)
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("prometheus endpoint stopped unexpectedly", "error", err)
		}
	}()
	return s, nil
}

// Addr returns the address the server is bound to (useful with port 0 in tests).
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Shutdown stops accepting connections, lets in-flight scrapes finish until ctx
// expires (then closes them), and waits for the serve loop to end.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	if err != nil {
		_ = s.srv.Close()
	}
	<-s.done
	return err
}

// Handler serves the registry: GET /metrics returns the exposition text, any
// other path is 404 and any other method on /metrics is 405.
//
// With loopbackOnly set, the Host header must name a loopback address or
// "localhost". That stops a web page from reading the endpoint through DNS
// rebinding (the browser would send the attacker's host name). Scrapers on the
// same machine use 127.0.0.1 or localhost; a reverse proxy in front must send
// such a Host header or the operator must set allow_non_loopback.
func Handler(reg *Registry, loopbackOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if loopbackOnly && !loopbackHostHeader(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = reg.WriteText(w)
	})
}

func loopbackHostHeader(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
