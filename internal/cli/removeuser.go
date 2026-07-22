package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var removeUserCmd = &cobra.Command{
	Use:   "remove-user <vault> <username>",
	Short: "Revoke a user's access to a vault",
	Long: `Revoke a user's access to a vault by deleting their wrapped copy of the
vault's key from the server.

After remove-user, the target's next API request to this vault returns
403 Forbidden — they cannot push, pull, or read refs.

V1 limitation: the removed user may already hold the plaintext key in
memory or local cache from a previous session, in which case they can
still decrypt history they have already downloaded. Key rotation to
invalidate past access is planned for V2.

<vault> can be either 'vault-name' (your own vault) or 'owner/vault-name'
(someone else's vault that you administer).`,
	Example: `  # Remove bob from your own vault
  gf remove-user myvault bob

  # Remove charlie from alice's vault (you must be a member)
  gf remove-user alice/myvault charlie`,
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
