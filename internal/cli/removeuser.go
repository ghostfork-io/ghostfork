package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/apiclient"
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

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	org, repoName := parseRepoArg(repoArg, cfg.Username)
	client := apiclient.New(cfg.ServerURL, cfg.APIKey)

	if err := client.DeleteKey(org, repoName, targetUsername); err != nil {
		return fmt.Errorf("removing %q from %s/%s: %w", targetUsername, org, repoName, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s removed from %s/%s.\n", targetUsername, org, repoName)
	return nil
}
