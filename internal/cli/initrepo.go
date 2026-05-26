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
	Long: `Create a new encrypted repo on the server you are logged into.

A fresh 256-bit symmetric key is generated locally, wrapped with your
public key, and uploaded to the server. The server never sees the
plaintext key. You become the repo's first (and only initial) member.

The repo's owner is always you — the wire format has no separate owner
field, so it is impossible to create a repo "for someone else." Grant
access to teammates afterwards with 'gf add-user'.

After init-repo succeeds, add the repo as a git remote and push as
normal:

    git remote add origin gf://<your-username>/<name>
    git push -u origin main`,
	Example: `  # Create a repo called 'my-project' owned by you
  gf init-repo my-project`,
	Args: cobra.ExactArgs(1),
	RunE: runInitRepo,
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

	fmt.Fprintf(cmd.OutOrStdout(), "\nRepo created: %s/%s\n\n", sess.cfg.Username, repoName)
	fmt.Fprintf(cmd.OutOrStdout(), "Add as a git remote with:\n\n")
	fmt.Fprintf(cmd.OutOrStdout(), "    git remote add origin gf://%s/%s\n", sess.cfg.Username, repoName)
	fmt.Fprintf(cmd.OutOrStdout(), "    git push -u origin main\n\n")
	return nil
}
