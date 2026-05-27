package cli

import (
	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/logging"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   "gf",
	Short: "Ghostfork — zero-trust encrypted Git remote",
	Long: `Ghostfork (gf) is a hosted Git remote where the server never sees your
plaintext code, filenames, or commit messages.

All encryption and decryption happens locally on your machine. After
'gf login', your encryption key never leaves the device. You use git
exactly as you would with any other remote — gf intercepts push and
pull traffic transparently via the gf:// URL scheme.

Typical workflow:

    gf login --server https://api.example.com --username alice
    gf init-repo my-project
    git remote add origin gf://alice/my-project
    git push -u origin main

To add a teammate to a repo you already own:

    gf add-user my-project bob

See https://github.com/ghostfork/gf for the full documentation.`,
	Example: `  # First-time setup on a new machine
  gf login --server https://api.example.com --username alice

  # Create an encrypted repo on the server
  gf init-repo my-project

  # Use as a normal git remote
  git remote add origin gf://alice/my-project
  git push -u origin main

  # Grant a teammate access
  gf add-user my-project bob

  # Revoke access
  gf remove-user my-project bob`,
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
	rootCmd.AddCommand(switchUserCmd)
}

// Execute runs the root command. It is called from cmd/gf/main.go.
func Execute() error {
	return rootCmd.Execute()
}
