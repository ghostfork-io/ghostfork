package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

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

	sess, err := loadSession()
	if err != nil {
		return err
	}
	slog.Debug("init-repo start", slog.String("name", repoName), slog.String("owner", sess.cfg.Username))

	repoKey, err := crypto.GenerateRepoKey()
	if err != nil {
		return fmt.Errorf("generating repo key: %w", err)
	}

	encKey, err := crypto.EncryptRepoKey(repoKey, sess.identity.PublicKey())
	if err != nil {
		return fmt.Errorf("encrypting repo key: %w", err)
	}
	slog.Debug("repo key generated and wrapped for owner")

	// The repo owner is always the caller; the server derives it from the
	// authenticated session, so we just pass the name.
	if err := sess.client.CreateRepo(repoName, encKey); err != nil {
		return fmt.Errorf("creating repo: %w", err)
	}
	slog.Debug("repo created on server", slog.String("name", repoName))

	fmt.Fprintf(cmd.OutOrStdout(), "Repo created. Add as a remote with:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  git remote add origin gf://%s/%s\n", sess.cfg.Username, repoName)
	return nil
}
