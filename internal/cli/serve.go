package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/wisnuvb/lockkeeper/internal/web"
	"github.com/wisnuvb/lockkeeper/internal/webui"
)

func init() {
	commandFactories = append(commandFactories, func(a *app) *cobra.Command { return a.serveCmd() })
}

func (a *app) serveCmd() *cobra.Command {
	var listen, certFile, keyFile string
	var hosts []string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the web interface (preview: demo data, no login yet, loopback only)",
		Long: `Serves the web interface that is built into this binary.

PREVIEW (ADR 0006, stage U1): the interface shows invented demo data and talks to no database. There
is no login yet, so the server refuses to listen on anything but loopback. Connections, sign-in and
real data arrive in the next slices.

Exposing the server beyond your own machine is intentionally unsupported for now; to look at it from
another machine use an SSH tunnel:  ssh -L 8443:127.0.0.1:8443 yourserver`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := a.logger()
			if err != nil {
				return err
			}
			// AuthEnabled stays false until sign-in exists, which is what keeps CheckListen refusing
			// every non-loopback address.
			srv, err := web.New(web.Config{
				Listen: listen, AllowedHosts: hosts, TLSCertFile: certFile, TLSKeyFile: keyFile, Logger: log,
			})
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			scheme := "http"
			if certFile != "" {
				scheme = "https"
			}
			if !webui.Built(webui.FS()) {
				fmt.Fprintln(a.env.Stderr, "Note: this binary has no web interface built in (run `make web-build web-embed build`). Only /api/v1/health is served.")
			}
			fmt.Fprintf(a.env.Stderr, "Lockkeeper web preview (demo data, no login): %s://%s/\n", scheme, listen)
			return srv.ListenAndServe(ctx)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", web.DefaultListen, "address to listen on (loopback only for now)")
	cmd.Flags().StringArrayVar(&hosts, "allowed-host", nil, "extra Host header name to accept (repeatable), for a reverse proxy or tunnel")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "TLS certificate file (with --tls-key)")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "TLS private key file (with --tls-cert)")
	return cmd
}
