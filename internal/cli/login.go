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

	// If both config and identity already exist for the same credentials, we're
	// already logged in — do nothing (avoids overwriting the identity file).
	if _, err := os.Stat(identityPath); err == nil {
		if cfg, err := config.Load(cfgPath); err == nil {
			if cfg.Username == username && cfg.ServerURL == serverURL {
				fmt.Fprintf(cmd.OutOrStdout(), "Already logged in as %s.\n", username)
				return nil
			}
		}
	}

	// Generate identity only if the file does not exist yet.
	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		id, err := crypto.GenerateIdentity()
		if err != nil {
			return fmt.Errorf("generating identity: %w", err)
		}
		if err := crypto.SaveIdentity(identityPath, id); err != nil {
			return fmt.Errorf("saving identity: %w", err)
		}
	}

	id, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	client := apiclient.New(serverURL, "")
	apiKey, err := client.Register(username, id.Recipient().String())
	if err != nil {
		return fmt.Errorf("registering with server: %w", err)
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
