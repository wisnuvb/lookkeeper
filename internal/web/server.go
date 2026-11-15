package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/webui"
)

// DefaultListen is where the server binds unless told otherwise: loopback only.
const DefaultListen = "127.0.0.1:8443"

// Config is everything the server needs from the outside. It holds no secrets: the TLS key is read
// from a file path and never kept in the config.
type Config struct {
	Listen string
	// AllowedHosts are extra Host header names accepted besides localhost and IP literals, for
	// example the name a reverse proxy forwards. Requests for any other name get 421.
	AllowedHosts []string
	// TLSCertFile and TLSKeyFile enable HTTPS. Both or neither.
	TLSCertFile, TLSKeyFile string
	// AllowNonLoopback is the explicit opt-in to listen beyond loopback; it also needs TLS and AuthEnabled.
	AllowNonLoopback bool
	// Proxy declares trusted reverse proxies (client address and HTTPS detection, see ProxyPolicy).
	Proxy ProxyPolicy
	// AuthEnabled declares that routes are protected by authentication (checked by CheckListen).
	AuthEnabled bool
	// UI is the static asset tree; nil means the embedded build (webui.FS()).
	UI     fs.FS
	Logger *slog.Logger
	Now    func() time.Time
}

// Server is the hardened HTTP server.
type Server struct {
	cfg  Config
	mux  *http.ServeMux
	root http.Handler
	log  *slog.Logger
}

// New validates the configuration and builds the handler chain. It binds nothing.
func New(cfg Config) (*Server, error) {
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, errors.New("web: tls_cert_file and tls_key_file must be set together")
	}
	tlsOn := cfg.TLSCertFile != ""
	warn, err := CheckListen(cfg.Listen, tlsOn, cfg.AuthEnabled, cfg.AllowNonLoopback)
	if err != nil {
		return nil, fmt.Errorf("web.listen: %w", err)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.UI == nil {
		cfg.UI = webui.FS()
	}
	if warn != "" {
		cfg.Logger.Warn(warn)
	}

	s := &Server{cfg: cfg, mux: http.NewServeMux(), log: cfg.Logger}
	s.mux.HandleFunc("/api/v1/health", health)
	s.mux.HandleFunc("/api/", apiNotFound)
	s.mux.Handle("/", uiHandler{fsys: cfg.UI, built: webui.Built(cfg.UI)})

	var h http.Handler = s.mux
	h = limitBody(h)
	h = newHostGuard(cfg.AllowedHosts).middleware(h)
	h = recoverer(cfg.Logger)(h)
	h = accessLog(cfg.Logger, cfg.Now)(h)
	h = securityHeaders(h) // outermost: headers are on every response, even a rejected or recovered one
	s.root = h
	return s, nil
}

// Handle registers an API route. Call it before serving. The pattern must be under /api/ so that the
// static fallback can never shadow it.
func (s *Server) Handle(pattern string, h http.Handler) { s.mux.Handle(pattern, h) }

// Proxy returns the trusted-proxy policy for handlers that need the client address or the HTTPS flag.
func (s *Server) Proxy() ProxyPolicy { return s.cfg.Proxy }

// Handler returns the full handler chain (for tests and for embedding in another server).
func (s *Server) Handler() http.Handler { return s.root }

// Serve serves on ln until ctx is cancelled, then shuts down gracefully (in-flight requests get up to
// ten seconds). The caller opens the listener so that tests can use port 0.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// CheckListen judged the configured STRING. A name such as "localhost" is resolved only now, by the
	// operating system, and a hosts-file entry could make it a public address (independent review,
	// finding 11). Judge the address that was really bound.
	if err := checkBound(ln.Addr(), s.cfg.AllowNonLoopback); err != nil {
		_ = ln.Close()
		return err
	}
	srv := &http.Server{
		Handler:           s.root,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		if s.cfg.TLSCertFile != "" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errc <- srv.ServeTLS(ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
			return
		}
		errc <- srv.Serve(ln)
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			return fmt.Errorf("web: shutdown: %w", err)
		}
		<-errc
		return nil
	}
}

// checkBound refuses a listener that is not loopback unless the operator opted in. (CheckListen already
// required TLS and authentication for that opt-in.)
func checkBound(a net.Addr, allowNonLoopback bool) error {
	if allowNonLoopback {
		return nil
	}
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("web: unexpected listener address type %T", a)
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok || !ip.Unmap().IsLoopback() {
		return fmt.Errorf("web: the listener is bound to %s, which is not loopback; refusing to serve (name resolution gave a non-loopback address)", tcp.IP)
	}
	return nil
}

// WriteTimeout note: Serve sets a 60 s write timeout, which would cut a long-lived stream. A streaming
// handler (progress events) must extend its own deadline with http.NewResponseController(w).SetWriteDeadline.

// ListenAndServe binds the configured address and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("web: listen on %s: %w", s.cfg.Listen, err)
	}
	s.log.Info("web server listening", "addr", ln.Addr().String(), "tls", s.cfg.TLSCertFile != "")
	return s.Serve(ctx, ln)
}
