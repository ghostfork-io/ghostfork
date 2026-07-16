package cli

import (
	"bufio"
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"
)

var deleteRepoYes bool

var deleteRepoCmd = &cobra.Command{
	Use:   "delete-repo <repo>",
	Short: "Permanently delete a repo from the server",
	Long: `Permanently delete a repo and everything the server holds for it —
every encrypted packfile, all collaborators' key grants, and its
branches.

This is IRREVERSIBLE. The server only ever holds ciphertext, so there
is nothing to recover once a repo is deleted; make sure any teammate
who needs the code has pulled it (or keep a local clone) first.

Only the repo's owner may delete it. For an org-owned repo, you must
be an admin of that org.

<repo> can be either 'repo-name' (your own repo) or 'owner/repo-name'
(an org repo you administer).

You are asked to re-type the repo name to confirm. Pass --yes to skip
the prompt (for scripts).`,
	Example: `  # Delete your own repo (asks for confirmation)
  gf delete-repo my-project

  # Delete an org repo you administer, without the prompt
  gf delete-repo acme/legacy-service --yes`,
	Args: cobra.ExactArgs(1),
	RunE: runDeleteRepo,
}

func init() {
	deleteRepoCmd.Flags().BoolVarP(&deleteRepoYes, "yes", "y", false, "skip the confirmation prompt")
}

func runDeleteRepo(cmd *cobra.Command, args []string) error {
	repoArg := args[0]

	sess, err := loadSession()
	if err != nil {
		return err
	}

	owner, repoName, err := parseRepoArg(repoArg, sess.cfg.Username)
	if err != nil {
		return err
	}
	slog.Debug("delete-repo start", slog.String("owner", owner), slog.String("repo", repoName))

	if !deleteRepoYes {
		ok, err := confirmDeleteRepo(cmd, owner, repoName)
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
	slog.Debug("repo deleted on server", slog.String("owner", owner), slog.String("repo", repoName))

	fmt.Fprintf(cmd.OutOrStdout(), "\nRepo deleted: %s/%s\n\n", owner, repoName)
	return nil
}

// confirmDeleteRepo makes the user re-type the repo name before an irreversible
// delete, guarding against a fat-fingered argument. It reads from the command's
// input stream so tests can drive it; a non-matching answer (including empty)
// cancels. It returns (true) only on an exact match of the bare repo name.
func confirmDeleteRepo(cmd *cobra.Command, owner, repo string) (bool, error) {
	fmt.Fprintf(cmd.ErrOrStderr(),
		"This permanently deletes %s/%s and all of its encrypted data. This cannot be undone.\n",
		owner, repo)
	fmt.Fprintf(cmd.ErrOrStderr(), "Type the repo name (%s) to confirm: ", repo)

	scanner := bufio.NewScanner(cmd.InOrStdin())
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, fmt.Errorf("reading confirmation: %w", err)
		}
		return false, nil // EOF / no input → treat as "no"
	}
	return strings.TrimSpace(scanner.Text()) == repo, nil
}
