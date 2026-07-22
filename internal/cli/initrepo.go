package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/logging"
)

var initVaultCmd = &cobra.Command{
	Use:   "init-vault <name>",
	Short: "Create a new encrypted vault on the server",
	Long: `Create a new encrypted vault on the server you are logged into.

A vault is the encrypted container on Ghostfork that a git repo gets
pushed into — it is NOT a git repo itself. Its <name> is an arbitrary
label on Ghostfork and does not need to match the name of any git repo
you later push into it.

A fresh 256-bit symmetric key is generated locally, wrapped with your
public key, and uploaded to the server. The server never sees the
plaintext key. You become the vault's first (and only initial) member.

The vault's owner is always you — the wire format has no separate owner
field, so it is impossible to create a vault "for someone else." Grant
access to teammates afterwards with 'gf add-user'.

After init-vault succeeds, add the vault as a git remote of an existing
git repo and push as normal:

    git remote add <remote-name> gf://<your-username>/<name>
    git push -u <remote-name> <branch-name>`,
	Example: `  # Create a vault called 'myvault' owned by you
  gf init-vault myvault`,
	Args: cobra.ExactArgs(1),
	RunE: runInitVault,
}

// initRepoCmd is the deprecated alias of init-vault. It is hidden from help and
// prints Cobra's deprecation notice, but still works so existing scripts and
// muscle memory (`gf init-repo`) don't break after the repo→vault rename.
var initRepoCmd = &cobra.Command{
	Use:        "init-repo <name>",
	Short:      "Deprecated alias of init-vault",
	Hidden:     true,
	Deprecated: `use "gf init-vault" instead.`,
	Args:       cobra.ExactArgs(1),
	RunE:       runInitVault,
}

func runInitVault(cmd *cobra.Command, args []string) error {
	repoName := args[0]

	sess, err := loadSession()
	if err != nil {
		return err
	}
	slog.Debug("init-vault start", slog.String("name", repoName), slog.String("owner", sess.cfg.Username))

	repoKey, err := crypto.GenerateRepoKey()
	if err != nil {
		return fmt.Errorf("generating repo key: %w", err)
	}
	// Demo aid (see docs/sales-demo.md Act 3): show the raw key so a prospect
	// can watch it get wrapped client-side. Logging plaintext key material is
	// acceptable ONLY when the user explicitly opted into debug output — the
	// log file records DEBUG unconditionally, so this must be gated on
	// DebugRequested, never on the logger's level.
	if logging.DebugRequested(verbose) {
		slog.Debug("generated repo sym key (plaintext, hex): " + hex.EncodeToString(repoKey))
	}

	slog.Debug(fmt.Sprintf("encrypting repo sym key with %s's public key (client-side operation)", sess.cfg.Username))
	encKey, err := crypto.EncryptRepoKey(repoKey, sess.identity.PublicKey())
	if err != nil {
		return fmt.Errorf("encrypting repo key: %w", err)
	}
	// This blob is exactly what is uploaded to the server — ciphertext only.
	slog.Debug(fmt.Sprintf("encrypted repo sym key for %s (base64): %s",
		sess.cfg.Username, base64.StdEncoding.EncodeToString(encKey)))

	// The repo owner is always the caller; the server derives it from the
	// authenticated session, so we just pass the name.
	if err := sess.client.CreateRepo(repoName, encKey); err != nil {
		return fmt.Errorf("creating vault: %w", err)
	}
	slog.Debug("repo created on server", slog.String("name", repoName))

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "\nVault created: %s/%s\n\n", sess.cfg.Username, repoName)
	fmt.Fprintf(out, "This vault now exists on the server, empty and ready. Whenever you're\n")
	fmt.Fprintf(out, "ready, you can add it as a new remote to an existing git repo and push\n")
	fmt.Fprintf(out, "your code to it:\n\n")
	fmt.Fprintf(out, "    git remote add <remote-name> gf://%s/%s\n", sess.cfg.Username, repoName)
	fmt.Fprintf(out, "    git push -u <remote-name> <branch-name>\n\n")
	fmt.Fprintf(out, "<remote-name> is any name you want to give this remote locally\n")
	fmt.Fprintf(out, "(e.g. \"ghostfork\"). <branch-name> is the branch you want to push\n")
	fmt.Fprintf(out, "(e.g. \"main\"). Nothing happens until you run these yourself — do this\n")
	fmt.Fprintf(out, "whenever you're ready.\n\n")
	return nil
}
