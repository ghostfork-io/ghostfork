package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/config"
)

var switchUserCmd = &cobra.Command{
	Use:   "switch-user <username>",
	Short: "Switch the active local account to a previously parked one",
	Long: `Switch between local Ghostfork accounts kept under the gf config
directory (~/.config/gf by default).

The active account's files live directly in the config directory. Other
accounts are "parked" in a subdirectory named after their username:

    ~/.config/gf/                  <- active account (config + identity)
    ~/.config/gf/bob/              <- parked account "bob"

'gf switch-user bob' swaps the two:

  1. ~/.config/gf/bob/ must already exist (otherwise there is nothing to
     switch to).
  2. The current account's files are moved into ~/.config/gf/<current>/.
  3. bob's files are moved from ~/.config/gf/bob/ up to ~/.config/gf/.

Everything stays on your machine and nothing is deleted — accounts are
only moved between the active slot and their parked subdirectory.`,
	Example: `  # Switch to the parked account "bob"
  gf switch-user bob`,
	Args: cobra.ExactArgs(1),
	RunE: runSwitchUser,
}

// usernameDirRe restricts the target to a plain directory name so a crafted
// argument can't escape the config directory (e.g. "../../etc").
var usernameDirRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func runSwitchUser(cmd *cobra.Command, args []string) error {
	target := args[0]
	if target == "." || target == ".." || !usernameDirRe.MatchString(target) {
		return fmt.Errorf("invalid username %q: expected letters, digits, '.', '_' or '-'", target)
	}

	configDir := config.DefaultDir()
	targetDir := filepath.Join(configDir, target)

	// 1. The parked profile we're switching to must exist.
	if info, err := os.Stat(targetDir); err != nil || !info.IsDir() {
		return fmt.Errorf(
			"no parked profile for %q at %s.\n"+
				"Parked profiles are subdirectories named after the user. Create one by\n"+
				"moving that account's config + identity into %s, then try again",
			target, targetDir, targetDir)
	}

	// 2. Figure out who is active right now, so we know where to park them.
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return fmt.Errorf("no active account to switch from — run 'gf login' first (%w)", err)
	}
	current := cfg.Username
	if current == "" {
		return fmt.Errorf("active config at %s has no username; cannot park it", config.DefaultPath())
	}
	if current == target {
		return fmt.Errorf("%q is already the active account", target)
	}

	currentDir := filepath.Join(configDir, current)
	if _, err := os.Stat(currentDir); err == nil {
		return fmt.Errorf(
			"cannot park current account %q: %s already exists.\n"+
				"Resolve it manually (it may be a stale profile) and try again",
			current, currentDir)
	}

	slog.Debug("switch-user",
		slog.String("from", current),
		slog.String("to", target),
		slog.String("config_dir", configDir),
	)

	// 3. Park the active account: move its top-level files into currentDir.
	//    Only regular files are moved, so parked-profile subdirectories
	//    (including targetDir) are never disturbed.
	if err := os.Mkdir(currentDir, 0o700); err != nil {
		return fmt.Errorf("creating parked profile dir for %q: %w", current, err)
	}
	if err := moveRegularFiles(configDir, currentDir); err != nil {
		return fmt.Errorf("parking current account %q: %w", current, err)
	}

	// 4. Promote the target account into the active slot.
	if err := moveRegularFiles(targetDir, configDir); err != nil {
		return fmt.Errorf(
			"promoting %q (the previous account is already parked at %s): %w",
			target, currentDir, err)
	}

	// 5. Best-effort cleanup of the now-empty parked dir. A failure here does
	//    not undo the switch, so it's non-fatal.
	if err := os.Remove(targetDir); err != nil {
		slog.Debug("could not remove emptied parked dir",
			slog.String("dir", targetDir), slog.Any("err", err))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nSwitched active account from %s to %s.\n", current, target)
	fmt.Fprintf(cmd.OutOrStdout(), "Previous account parked at %s\n\n", currentDir)
	return nil
}

// moveRegularFiles moves every regular file directly inside src into dst,
// keeping its name. Subdirectories are skipped so other parked profiles are
// left in place.
func moveRegularFiles(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		from := filepath.Join(src, e.Name())
		to := filepath.Join(dst, e.Name())
		if err := os.Rename(from, to); err != nil {
			return fmt.Errorf("moving %s -> %s: %w", from, to, err)
		}
	}
	return nil
}
