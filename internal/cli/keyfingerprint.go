package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/crypto"
)

var keyFingerprintCmd = &cobra.Command{
	Use:   "key-fingerprint <vault>",
	Short: "Print the fingerprint of a vault's encryption key",
	Long: `Print a short fingerprint of the key your machine decrypts a vault with.

This exists to be compared. The web dashboard's vault browser shows the same
fingerprint in its "how this works" dialog; if the two match, the plaintext in
your browser really was unwrapped with your own key by the helper on this
machine. A value the dashboard merely asserts proves nothing — two
independently produced values that agree do.

The fingerprint is a truncated, domain-separated SHA-256 of the vault key. It
identifies the key without exposing it, so it is safe to paste into an issue or
read out loud; the key itself never leaves this machine.`,
	Example: `  # Compare against the dashboard's session dialog
  gf key-fingerprint my-vault

  # A vault owned by someone else (or an org)
  gf key-fingerprint alice/my-vault`,
	Args: cobra.ExactArgs(1),
	RunE: runKeyFingerprint,
}

func runKeyFingerprint(cmd *cobra.Command, args []string) error {
	sess, err := loadSession()
	if err != nil {
		return err
	}
	owner, repo, err := parseRepoArg(args[0], sess.cfg.Username)
	if err != nil {
		return err
	}
	slog.Debug("key-fingerprint start", slog.String("owner", owner), slog.String("repo", repo))

	// The server hands over the key wrapped for this user; unwrapping happens
	// here, which is the whole point — the server cannot compute this itself.
	encKey, err := sess.client.GetKey(owner, repo, sess.cfg.Username)
	if err != nil {
		return fmt.Errorf("fetching your key for %s/%s (are you a member?): %w", owner, repo, err)
	}
	repoKey, err := crypto.DecryptRepoKey(encKey, sess.identity)
	if err != nil {
		return fmt.Errorf("decrypting the vault key with this machine's identity: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s/%s\n", owner, repo)
	fmt.Fprintf(out, "vault key: %s\n", crypto.RepoKeyFingerprint(repoKey))
	fmt.Fprintln(out, "\nThis should match the vault key shown in the dashboard's")
	fmt.Fprintln(out, "\"how this works\" dialog while browsing this vault.")
	return nil
}
