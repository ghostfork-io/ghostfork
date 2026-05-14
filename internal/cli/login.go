package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/crypto"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a GhostFork server",
	RunE:  runLogin,
}

func init() {
	loginCmd.Flags().String("server", "", "server URL (required)")
	loginCmd.Flags().String("username", "", "username to register or log in as (required)")
	loginCmd.MarkFlagRequired("server")
	loginCmd.MarkFlagRequired("username")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	username, _ := cmd.Flags().GetString("username")

	identityPath := config.DefaultIdentityPath()
	cfgPath := config.DefaultPath()

	// If an identity file is already on disk, this machine has been logged in
	// before. Decide what to do based on whether the saved config matches the
	// requested credentials.
	if _, err := os.Stat(identityPath); err == nil {
		cfg, cfgErr := config.Load(cfgPath)
		if cfgErr != nil {
			// Identity present but no usable config: the API key for the
			// previous account is unrecoverable in V1 (see CLAUDE.md threat
			// model on key loss). Refuse rather than silently re-register a
			// second server account against the same public key.
			return fmt.Errorf(
				"identity file already exists at %s but no usable config was found.\n"+
					"The API key for the previous account on this identity cannot be\n"+
					"recovered in V1. To start fresh with a new identity, delete\n"+
					"%s and run gf login again",
				identityPath, identityPath)
		}
		if cfg.Username == username && cfg.ServerURL == serverURL {
			fmt.Fprintf(cmd.OutOrStdout(), "Already logged in as %s.\n", username)
			return nil
		}
		return fmt.Errorf(
			"this machine is already logged in as %s on %s.\n"+
				"To log in as a different user, use a different machine or delete\n"+
				"%s first (destructive — see CLAUDE.md threat model on key loss)",
			cfg.Username, cfg.ServerURL, identityPath)
	}

	// No identity yet — fresh login. Generate the keypair in memory and
	// register with the server before writing anything to disk, so a Register
	// failure leaves no local state to clean up.
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}

	client := apiclient.New(serverURL, "")
	apiKey, err := client.Register(username, id.Recipient().String())
	if err != nil {
		return fmt.Errorf("registering with server: %w", err)
	}

	if err := crypto.SaveIdentity(identityPath, id); err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}

	cfg := &config.Config{
		Username:  username,
		APIKey:    apiKey,
		ServerURL: serverURL,
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Logged in as %s.\n", username)
	return nil
}
