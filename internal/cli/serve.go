package cli

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/serve"
)

var (
	servePort         int
	serveResetPairing bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve decrypted repo data to the local web dashboard",
	Long: `Start a local read-only HTTP server the web dashboard's repo browser talks
to. The server binds 127.0.0.1 only — it is never reachable from the
network — and runs in the foreground until Ctrl+C.

The dashboard fetches encrypted data from the Ghostfork server through this
helper, which decrypts it locally; the server never sees plaintext, even
while you browse. See docs/gf-serve-api.md for the HTTP API.

On first run a pairing token is generated and printed; paste it into the
dashboard when prompted. The token persists across runs, so pairing happens
once. Requests without it are rejected — being on localhost is not enough,
since any local process or web page can reach 127.0.0.1.`,
	Example: `  # Serve on the default port (7777)
  gf serve

  # Serve on a different port
  gf serve --port 8888

  # Invalidate the old pairing token and print a fresh one
  gf serve --reset-pairing`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", serve.DefaultPort, "loopback port to listen on")
	serveCmd.Flags().BoolVar(&serveResetPairing, "reset-pairing", false,
		"generate a new pairing token, invalidating the old one")
}

func runServe(cmd *cobra.Command, _ []string) error {
	if servePort < 1 || servePort > 65535 {
		return fmt.Errorf("invalid --port %d: must be between 1 and 65535", servePort)
	}

	// The helper answers with the caller's decrypted data, so it needs the
	// logged-in identity — same requirement as any other authenticated command.
	sess, err := loadSession()
	if err != nil {
		return err
	}
	origin, err := serve.Origin(sess.cfg.ServerURL)
	if err != nil {
		return err
	}

	token, err := serve.LoadOrCreateToken(serve.TokenPath(), serveResetPairing)
	if err != nil {
		return err
	}

	srv, err := serve.Listen(serve.Options{
		Port:   servePort,
		Token:  token,
		Origin: origin,
		Repos:  sess.client,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "gf serve listening on http://%s\n", srv.Addr())
	if serveResetPairing {
		fmt.Fprintln(out, "Pairing token rotated — previously paired dashboards must re-pair.")
	}
	fmt.Fprintf(out, "Pairing token: %s   (paste into the dashboard when prompted)\n", token)
	fmt.Fprintln(out, "Press Ctrl+C to stop.")
	// The token itself never goes to the log file — the log is not permission-
	// protected the way the token file is.
	slog.Info("gf serve started", slog.String("addr", srv.Addr()))

	if err := srv.Serve(ctx); err != nil {
		return err
	}
	fmt.Fprintln(out, "gf serve stopped.")
	slog.Info("gf serve stopped")
	return nil
}
