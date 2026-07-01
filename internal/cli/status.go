package cli

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/config"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which account is logged in on this machine",
	Long: `Print the Ghostfork account currently logged in on this machine: the
username, the server it is registered with, and the local key's fingerprint.

This reads only local state — no network call. It exits non-zero when no
account is logged in, so it is safe to branch on in scripts.`,
	Example: `  gf status`,
	Args:    cobra.NoArgs,
	RunE:    runStatus,
}

func runStatus(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		// Not an error the user needs a stack trace for — print the plain state
		// and exit non-zero (ErrSilent) so scripts can detect "logged out".
		fmt.Fprintln(out, "Not logged in. Run 'gf login' to sign in.")
		return ErrSilent
	}

	fmt.Fprintf(out, "Logged in as %s on %s\n", cfg.Username, cfg.ServerURL)

	// The identity key is what actually authenticates every request; surface its
	// fingerprint (the same value in the login logs and the web dashboard) and
	// flag the odd state where the config exists but the key is gone.
	idPath := config.DefaultIdentityPath()
	id, err := crypto.LoadIdentity(idPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(out, "  ⚠ no identity key at %s — run 'gf login' to restore it\n", idPath)
			return nil
		}
		return fmt.Errorf("reading identity from %s: %w", idPath, err)
	}
	fmt.Fprintf(out, "  key fingerprint (SHA-256): %s\n", id.PublicKeyFingerprint())
	fmt.Fprintf(out, "  identity file: %s\n", idPath)
	return nil
}
