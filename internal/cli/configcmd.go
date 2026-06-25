package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Set up this machine from an existing private key",
	Long: `Configure gf on a new or wiped machine in one step: point it at your
backed-up private key and your server, and gf installs the key at the
right location and writes the config — no manual file editing or
OS-specific path juggling.

This is the explicit alternative to the recovery paths of 'gf login': it
reads the private key from the file you pass with --identity (rather than
stdin or a key already sitting at the default path). The key is verified
against the server before anything is written, exactly like
'gf login --recover'.

Refused if an identity already exists on this machine — gf config is for
fresh setup. Remove ~/.config/gf first to start over, or use 'gf login'
to recover from a key already in place.`,
	Example: `  # New machine: install your backed-up key and point at your server
  gf config --server https://api.example.com --username alice --identity ./alice.ed25519`,
	Args: cobra.NoArgs,
	RunE: runConfig,
}

func init() {
	configCmd.Flags().String("server", "", "server URL (required)")
	configCmd.Flags().String("username", "", "your username (required)")
	configCmd.Flags().String("identity", "", "path to your private key file (required)")
	configCmd.MarkFlagRequired("server")
	configCmd.MarkFlagRequired("username")
	configCmd.MarkFlagRequired("identity")
}

func runConfig(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	username, _ := cmd.Flags().GetString("username")
	keyPath, _ := cmd.Flags().GetString("identity")

	if err := apiclient.ValidateBaseURL(serverURL); err != nil {
		return err
	}

	identityPath := config.DefaultIdentityPath()
	cfgPath := config.DefaultPath()
	slog.Debug("config start",
		slog.String("server", serverURL),
		slog.String("username", username),
		slog.String("key_path", keyPath),
		slog.String("identity_path", identityPath),
		slog.String("config_path", cfgPath),
	)

	// gf config is for fresh setup; never clobber an existing key.
	if _, err := os.Stat(identityPath); err == nil {
		return fmt.Errorf(
			"an identity already exists at %s.\n"+
				"gf config is for setting up a fresh machine. To recover an account on a\n"+
				"machine that already has this key, run 'gf login'. To reconfigure from\n"+
				"scratch, remove %s first (destructive — back up the key).",
			identityPath, config.DefaultDir())
	}

	// Load the private key from the file the user pointed at.
	id, err := crypto.LoadIdentity(keyPath)
	if err != nil {
		return fmt.Errorf("reading private key from %s: %w", keyPath, err)
	}

	// Verify the key belongs to <username> on <server>, then install it at the
	// default identity path and write the config (shared with the login paths).
	if err := verifyAndStore(cmd, serverURL, username, identityPath, cfgPath, id); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nConfigured as %s on %s.\n", username, serverURL)
	fmt.Fprintf(cmd.OutOrStdout(), "Identity written to %s\n\n", identityPath)
	fmt.Fprintf(cmd.OutOrStdout(), "This machine is ready — use your gf:// remotes with git as usual.\n\n")
	return nil
}
