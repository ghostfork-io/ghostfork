package cli

import (
	"fmt"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/crypto"
)

var addUserCmd = &cobra.Command{
	Use:   "add-user <repo> <username>",
	Short: "Grant a user access to a repo",
	Args:  cobra.ExactArgs(2),
	RunE:  runAddUser,
}

func runAddUser(cmd *cobra.Command, args []string) error {
	repoArg := args[0]
	targetUsername := args[1]

	sess, err := loadSession()
	if err != nil {
		return err
	}
	id, err := loadIdentity()
	if err != nil {
		return err
	}

	owner, repoName, err := parseRepoArg(repoArg, sess.cfg.Username)
	if err != nil {
		return err
	}

	// Fetch the target user's public key from the server.
	targetUser, err := sess.client.GetUser(targetUsername)
	if err != nil {
		return fmt.Errorf("fetching user %q: %w", targetUsername, err)
	}

	targetRecipient, err := age.ParseX25519Recipient(targetUser.PublicKey)
	if err != nil {
		return fmt.Errorf("parsing public key for %q: %w", targetUsername, err)
	}

	// Fetch and decrypt our own copy of the repo key.
	myEncKey, err := sess.client.GetKey(owner, repoName, sess.cfg.Username)
	if err != nil {
		return fmt.Errorf("fetching repo key: %w", err)
	}

	repoKey, err := crypto.DecryptRepoKey(myEncKey, id)
	if err != nil {
		return fmt.Errorf("decrypting repo key: %w", err)
	}

	// Re-encrypt the repo key for the target user.
	newEncKey, err := crypto.EncryptRepoKey(repoKey, targetRecipient)
	if err != nil {
		return fmt.Errorf("encrypting repo key for %q: %w", targetUsername, err)
	}

	if err := sess.client.PutKey(owner, repoName, targetUsername, newEncKey); err != nil {
		return fmt.Errorf("storing key for %q: %w", targetUsername, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s added to %s/%s.\n", targetUsername, owner, repoName)
	return nil
}
