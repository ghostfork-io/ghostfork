package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var removeUserCmd = &cobra.Command{
	Use:   "remove-user <repo> <username>",
	Short: "Revoke a user's access to a repo",
	Args:  cobra.ExactArgs(2),
	RunE:  runRemoveUser,
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

	fmt.Fprintf(cmd.OutOrStdout(), "%s removed from %s/%s.\n", targetUsername, owner, repoName)
	return nil
}
