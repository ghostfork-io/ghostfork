package cli

import (
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/logging"
	"github.com/ghostfork/gf/internal/version"
)

var verbose bool

// DocsURL is the Ghostfork documentation site. It is shown at the foot of every
// command's help output and whenever a command errors, so users always have a
// pointer to the docs one click away. Printed as a bare URL so terminals
// linkify it and it stays copy-pasteable everywhere (macOS Terminal, iTerm2,
// GNOME Terminal, Konsole, Windows Terminal, VS Code, …).
const DocsURL = "https://ghostfork.io/docs/"

var rootCmd = &cobra.Command{
	Use:   "gf",
	Short: "Ghostfork — zero-trust encrypted Git remote",
	// Enables `gf --version`. Cobra renders this as "gf version <Version>",
	// where Version carries both the semver and the build commit, e.g.
	// "gf version 0.1.0 (commit 9f3a2bc)".
	Version: version.String(),
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

    gf add-user my-project bob`,
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
		logging.SetDefault(logging.NewCLI(verbose, config.DefaultLogPath()))
		// First line of every operation's audit trail: which command ran and
		// with which inputs. Lands in the log file even without -v.
		slog.Debug("command received",
			slog.String("command", cmd.Name()),
			slog.String("args", strings.Join(args, " ")),
		)
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "log debug-level details to stderr")

	// Append a docs link to the foot of every command's help output. Set on the
	// root only: Cobra falls back to the parent's template for any command that
	// has none of its own, so this one line covers `gf --help` and every
	// `gf <command> --help`. rootCmd.HelpTemplate() returns Cobra's default here
	// (the root has no parent and no template set yet), which we extend.
	rootCmd.SetHelpTemplate(rootCmd.HelpTemplate() + "\nDocs: " + DocsURL + "\n")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(initRepoCmd)
	rootCmd.AddCommand(deleteRepoCmd)
	rootCmd.AddCommand(addUserCmd)
	rootCmd.AddCommand(removeUserCmd)
	rootCmd.AddCommand(switchUserCmd)
	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(verifyCmd)
}

// Execute runs the root command. It is called from cmd/gf/main.go.
func Execute() error {
	// Install a file-backed logger before parsing so even flag/usage errors
	// reach the log file; PersistentPreRun re-installs it once -v is known.
	logging.SetDefault(logging.NewCLI(false, config.DefaultLogPath()))
	err := rootCmd.Execute()
	if err != nil {
		// Never fail silently: the log file must record the failure. FileOnly
		// keeps it off stderr, where main.go already prints "Error: …".
		slog.Error("command failed", logging.FileOnly(), slog.Any("err", err))
	}
	return err
}
