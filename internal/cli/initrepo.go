package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/crypto"
)

var initRepoCmd = &cobra.Command{
	Use:   "init-repo <name>",
	Short: "Create a new encrypted repo on the server",
	Args:  cobra.ExactArgs(1),
	RunE:  runInitRepo,
}

func runInitRepo(cmd *cobra.Command, args []string) error {
	repoName := args[0]

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	id, err := crypto.LoadIdentity(config.DefaultIdentityPath())
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	repoKey, err := crypto.GenerateRepoKey()
	if err != nil {
		return fmt.Errorf("generating repo key: %w", err)
	}

	encKey, err := crypto.EncryptRepoKey(repoKey, id.Recipient())
	if err != nil {
		return fmt.Errorf("encrypting repo key: %w", err)
	}

	// In V1, init-repo defaults the org to the caller's username.
	org := cfg.Username
	client := apiclient.New(cfg.ServerURL, cfg.APIKey)
	if err := client.CreateRepo(org, repoName, encKey); err != nil {
		return fmt.Errorf("creating repo: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Repo created. Add as a remote with:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  git remote add origin gf://%s/%s\n", org, repoName)
	return nil
}
