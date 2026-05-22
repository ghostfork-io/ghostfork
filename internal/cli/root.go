package cli

import (
	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/logging"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:               "gf",
	Short:             "Ghostfork — zero-trust encrypted Git remote",
	SilenceUsage:      true,
	SilenceErrors:     true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logging.SetDefault(logging.NewCLI(verbose))
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "log debug-level details to stderr")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(initRepoCmd)
	rootCmd.AddCommand(addUserCmd)
	rootCmd.AddCommand(removeUserCmd)
}

// Execute runs the root command. It is called from cmd/gf/main.go.
func Execute() error {
	return rootCmd.Execute()
}
