package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gf",
	Short: "GhostFork — zero-trust encrypted Git remote",
	SilenceUsage:  true,
	SilenceErrors: true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(initRepoCmd)
	rootCmd.AddCommand(addUserCmd)
	rootCmd.AddCommand(removeUserCmd)
}

// Execute runs the root command. It is called from cmd/gf/main.go.
func Execute() error {
	return rootCmd.Execute()
}
