package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var removeUserCmd = &cobra.Command{
	Use:   "remove-user <repo> <username>",
	Short: "Revoke a user's access to a repo",
	Long: `Revoke a user's access to a repo by deleting their wrapped copy of the
repo key from the server.

After remove-user, the target's next API request to this repo returns
403 Forbidden — they cannot push, pull, or read refs.

V1 limitation: the removed user may already hold the plaintext repo
key in memory or local cache from a previous session, in which case
they can still decrypt history they have already downloaded. Key
rotation to invalidate past access is planned for V2.

<repo> can be either 'repo-name' (your own repo) or 'owner/repo-name'
(someone else's repo that you administer).`,
	Example: `  # Remove bob from your own repo
  gf remove-user my-project bob

  # Remove charlie from alice's repo (you must be a member)
  gf remove-user alice/my-project charlie`,
	Args: cobra.ExactArgs(2),
	RunE: runRemoveUser,
}

func runRemoveUser(cmd *cobra.Command, args []string) error {
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
	slog.Debug("remove-user start",
		slog.String("owner", owner),
		slog.String("repo", repoName),
		slog.String("target", targetUsername),
	)

	if err := sess.client.DeleteKey(owner, repoName, targetUsername); err != nil {
		return fmt.Errorf("removing %q from %s/%s: %w", targetUsername, owner, repoName, err)
	}
	slog.Debug("target key deleted on server")

	fmt.Fprintf(cmd.OutOrStdout(), "\n%s removed from %s/%s.\n\n", targetUsername, owner, repoName)
	return nil
}
