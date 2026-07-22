package cli

import (
	"bufio"
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"
)

var deleteRepoYes bool

var deleteVaultCmd = &cobra.Command{
	Use:   "delete-vault <vault>",
	Short: "Permanently delete a vault from the server",
	Long: `Permanently delete a vault and everything the server holds for it —
every encrypted packfile, all collaborators' key grants, and its
branches.

This is IRREVERSIBLE. The server only ever holds ciphertext, so there
is nothing to recover once a vault is deleted; make sure any teammate
who needs the code has pulled it (or keep a local clone) first. Deleting
the vault does not touch any local git repo you pushed into it.

Only the vault's owner may delete it. For an org-owned vault, you must
be an admin of that org.

<vault> can be either 'vault-name' (your own vault) or 'owner/vault-name'
(an org vault you administer).

You are asked to re-type the vault name to confirm. Pass --yes to skip
the prompt (for scripts).`,
	Example: `  # Delete your own vault (asks for confirmation)
  gf delete-vault myvault

  # Delete an org vault you administer, without the prompt
  gf delete-vault acme/legacy-service --yes`,
	Args: cobra.ExactArgs(1),
	RunE: runDeleteVault,
}

// deleteRepoCmd is the deprecated alias of delete-vault — hidden and warned,
// but still functional so `gf delete-repo` keeps working after the rename.
var deleteRepoCmd = &cobra.Command{
	Use:        "delete-repo <vault>",
	Short:      "Deprecated alias of delete-vault",
	Hidden:     true,
	Deprecated: `use "gf delete-vault" instead.`,
	Args:       cobra.ExactArgs(1),
	RunE:       runDeleteVault,
}

func init() {
	deleteVaultCmd.Flags().BoolVarP(&deleteRepoYes, "yes", "y", false, "skip the confirmation prompt")
	// The deprecated alias needs its own --yes flag so scripts passing it keep working.
	deleteRepoCmd.Flags().BoolVarP(&deleteRepoYes, "yes", "y", false, "skip the confirmation prompt")
}

func runDeleteVault(cmd *cobra.Command, args []string) error {
	repoArg := args[0]

	sess, err := loadSession()
	if err != nil {
		return err
	}

	owner, repoName, err := parseRepoArg(repoArg, sess.cfg.Username)
	if err != nil {
		return err
	}
	slog.Debug("delete-vault start", slog.String("owner", owner), slog.String("repo", repoName))

	if !deleteRepoYes {
		ok, err := confirmDeleteVault(cmd, owner, repoName)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintf(cmd.OutOrStdout(), "\nAborted — %s/%s was not deleted.\n\n", owner, repoName)
			return nil
		}
	}

	if err := sess.client.DeleteRepo(owner, repoName); err != nil {
		return fmt.Errorf("deleting %s/%s: %w", owner, repoName, err)
	}
	slog.Debug("vault deleted on server", slog.String("owner", owner), slog.String("repo", repoName))

	fmt.Fprintf(cmd.OutOrStdout(), "\nVault deleted: %s/%s\n\n", owner, repoName)
	return nil
}

// confirmDeleteVault makes the user re-type the vault name before an
// irreversible delete, guarding against a fat-fingered argument. It reads from
// the command's input stream so tests can drive it; a non-matching answer
// (including empty) cancels. It returns (true) only on an exact match of the
// bare vault name.
func confirmDeleteVault(cmd *cobra.Command, owner, repo string) (bool, error) {
	fmt.Fprintf(cmd.ErrOrStderr(),
		"This permanently deletes %s/%s and all of its encrypted data. This cannot be undone.\n",
		owner, repo)
	fmt.Fprintf(cmd.ErrOrStderr(), "Type the vault name (%s) to confirm: ", repo)

	scanner := bufio.NewScanner(cmd.InOrStdin())
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, fmt.Errorf("reading confirmation: %w", err)
		}
		return false, nil // EOF / no input → treat as "no"
	}
	return strings.TrimSpace(scanner.Text()) == repo, nil
}
