package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/crypto"
	"github.com/ghostfork/gf/protocol/auth"
)

var addUserCmd = &cobra.Command{
	Use:   "add-user <repo> <username>",
	Short: "Grant a user access to a repo",
	Long: `Grant another registered user access to a repo you can already reach.

What happens locally:
  1. Your client fetches the target user's public key from the server.
  2. Your client fetches and decrypts your own copy of the repo key.
  3. Your client re-encrypts the repo key with the target user's public
     key and uploads that new wrapped copy.

The server never sees the plaintext repo key. The target user must
have already run 'gf login' on their own machine so their public key
is on file.

<repo> can be either 'repo-name' (your own repo) or 'owner/repo-name'
(someone else's repo that you have access to and want to add another
member to).`,
	Example: `  # Add bob to your own repo
  gf add-user my-project bob

  # Add charlie to alice's repo (you must already be a member)
  gf add-user alice/my-project charlie`,
	Args: cobra.ExactArgs(2),
	RunE: runAddUser,
}

func runAddUser(cmd *cobra.Command, args []string) error {
	repoArg := args[0]
	targetUsername := args[1]

	sess, err := loadSession()
	if err != nil {
		return err
	}

	owner, repoName, err := parseRepoArg(repoArg, sess.cfg.Username)
	if err != nil {
		return err
	}
	slog.Debug("add-user start",
		slog.String("owner", owner),
		slog.String("repo", repoName),
		slog.String("target", targetUsername),
	)

	// Fetch the target user's public key from the server.
	targetUser, err := sess.client.GetUser(targetUsername)
	if err != nil {
		return fmt.Errorf("fetching user %q: %w", targetUsername, err)
	}

	targetPub, err := auth.DecodePublicKey(targetUser.PublicKey)
	if err != nil {
		return fmt.Errorf("parsing public key for %q: %w", targetUsername, err)
	}
	slog.Debug("target public key fetched")

	// Fetch and decrypt our own copy of the repo key.
	myEncKey, err := sess.client.GetKey(owner, repoName, sess.cfg.Username)
	if err != nil {
		return fmt.Errorf("fetching repo key: %w", err)
	}

	repoKey, err := crypto.DecryptRepoKey(myEncKey, sess.identity)
	if err != nil {
		return fmt.Errorf("decrypting repo key: %w", err)
	}
	slog.Debug("repo key decrypted locally")

	// Re-encrypt the repo key for the target user.
	newEncKey, err := crypto.EncryptRepoKey(repoKey, targetPub)
	if err != nil {
		return fmt.Errorf("encrypting repo key for %q: %w", targetUsername, err)
	}

	if err := sess.client.PutKey(owner, repoName, targetUsername, newEncKey); err != nil {
		return fmt.Errorf("storing key for %q: %w", targetUsername, err)
	}
	slog.Debug("wrapped repo key uploaded for target")

	fmt.Fprintf(cmd.OutOrStdout(), "\n%s added to %s/%s.\n\n", targetUsername, owner, repoName)
	return nil
}
