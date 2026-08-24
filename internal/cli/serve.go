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
	servePort          int
	serveResetPairing  bool
	serveStablePairing bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve decrypted vault data to the local web dashboard",
	Long: `Start a local read-only HTTP server the web dashboard's vault browser talks
to. The server binds 127.0.0.1 only — it is never reachable from the
network — and runs in the foreground until Ctrl+C.

The dashboard fetches encrypted data from the Ghostfork server through this
helper, which decrypts it locally; the server never sees plaintext, even
while you browse. See docs/gf-serve-api.md for the HTTP API.

A pairing token is printed at every start; paste it into the dashboard when
prompted. By DEFAULT the token is freshly generated on each run and kept only
in memory — nothing is written to disk, so there is no long-lived credential
to leak, and the token stops working the moment this process exits. The
trade-off is that the dashboard must be paired again every time you start the
helper.

Pass --stable-pairing to keep one token across runs instead (stored in the gf
config directory, mode 0600), so you pair the dashboard only once.

Requests without the token are rejected — being on localhost is not enough,
since any local process or web page can reach 127.0.0.1.`,
	Example: `  # Serve on the default port (7777)
  gf serve

  # Serve on a different port
  gf serve --port 8888

  # Reuse one token across runs, so you pair the dashboard only once
  gf serve --stable-pairing

  # Replace the stored token from --stable-pairing with a fresh one
  gf serve --stable-pairing --reset-pairing`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", serve.DefaultPort, "loopback port to listen on")
	serveCmd.Flags().BoolVar(&serveStablePairing, "stable-pairing", false,
		"reuse one stored pairing token across runs instead of a fresh one per start")
	serveCmd.Flags().BoolVar(&serveResetPairing, "reset-pairing", false,
		"replace the stored --stable-pairing token with a fresh one")
}

// pairingToken returns the token this run will accept: a fresh in-memory one by
// default, or the stored one under --stable-pairing. Passing --reset-pairing
// without --stable-pairing is harmless but means nothing — every run already
// rotates — so say so instead of silently ignoring it.
func pairingToken(cmd *cobra.Command) (string, error) {
	if !serveStablePairing {
		if serveResetPairing {
			fmt.Fprintln(cmd.ErrOrStderr(),
				"note: --reset-pairing does nothing on its own — a fresh token is "+
					"generated every run by default. It applies to --stable-pairing.")
		}
		return serve.NewToken()
	}
	return serve.LoadOrCreateToken(serve.TokenPath(), serveResetPairing)
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

	// Default: a fresh in-memory token per run. --stable-pairing opts back into
	// the stored one, and only then does --reset-pairing mean anything.
	token, err := pairingToken(cmd)
	if err != nil {
		return err
	}

	cacheRoot, err := serve.DefaultCacheRoot(sess.cfg.ServerURL, sess.cfg.Username)
	if err != nil {
		return err
	}

	srv, err := serve.Listen(serve.Options{
		Port:      servePort,
		Token:     token,
		Origin:    origin,
		Upstream:  sess.client,
		ServerURL: sess.cfg.ServerURL,
		Username:  sess.cfg.Username,
		Materializer: serve.NewMaterializer(
			sess.client, sess.identity, sess.cfg.Username, cacheRoot),
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "gf serve listening on http://%s\n", srv.Addr())
	if serveStablePairing && serveResetPairing {
		fmt.Fprintln(out, "Pairing token rotated — previously paired dashboards must re-pair.")
	}
	fmt.Fprintf(out, "Pairing token: %s   (paste into the dashboard when prompted)\n", token)
	if serveStablePairing {
		fmt.Fprintln(out, "This token is stored and reused, so you only pair once.")
	} else {
		// Say plainly why a previously-working token stopped working, rather
		// than leaving the user to guess at the dashboard's 401.
		fmt.Fprintln(out, "New for this run and never written to disk — any earlier token is now dead,")
		fmt.Fprintln(out, "so pair the dashboard again. Use --stable-pairing to keep one token instead.")
	}
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
