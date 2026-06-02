package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/installer"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install gf into a directory already on your PATH (no shell config needed)",
	Long: `Copy the gf binary into a directory that is already on your PATH and set up
the git-remote-gf helper next to it, so 'gf' and 'gf://' remotes work
immediately — no editing of your shell configuration.

gf inspects your live PATH, finds the directories writable by your user, and
picks the most appropriate one (user-owned locations first, so no sudo is
needed). If none of your PATH directories are writable, it installs into
~/.local/bin and tells you the one line to add to your shell config.`,
	Example: `  # Auto-detect a writable PATH directory and install there
  gf install

  # See where it would install, without changing anything
  gf install --dry-run

  # Force a specific directory
  gf install --dir /usr/local/bin`,
	Args: cobra.NoArgs,
	RunE: runInstall,
}

func init() {
	installCmd.Flags().String("dir", "", "install into this directory instead of auto-detecting one on PATH")
	installCmd.Flags().Bool("dry-run", false, "print where gf would be installed without writing anything")
}

func runInstall(cmd *cobra.Command, _ []string) error {
	dirFlag, _ := cmd.Flags().GetString("dir")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	out := cmd.OutOrStdout()

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the running gf binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	pathEnv := os.Getenv("PATH")
	home, _ := os.UserHomeDir()

	// Decide the target directory. We only ever auto-install silently into a
	// conventional, general-purpose bin dir; if the only writable PATH dir is a
	// tool/SDK directory (e.g. ~/flutter/bin) we fall back to ~/.local/bin and
	// suggest --dir, rather than dropping gf into a directory that belongs to
	// another tool.
	var targetDir, toolHint string
	if dirFlag != "" {
		targetDir = dirFlag // an explicit choice is always honored as-is
	} else {
		sel := installer.Select(pathEnv, byte(os.PathListSeparator), home, dirWritable)
		if sel.Found && sel.Conventional {
			targetDir = sel.Dir
		} else {
			targetDir = filepath.Join(home, ".local", "bin")
			if sel.Found {
				toolHint = sel.Dir // writable, on PATH, but tool-specific
			}
		}
	}
	targetDir = filepath.Clean(targetDir)

	binName, helperName := "gf", "git-remote-gf"
	if runtime.GOOS == "windows" {
		binName, helperName = "gf.exe", "git-remote-gf.exe"
	}
	binPath := filepath.Join(targetDir, binName)
	helperPath := filepath.Join(targetDir, helperName)
	onPath := dirOnPath(targetDir, pathEnv, home)

	if dryRun {
		fmt.Fprintf(out, "Would install:\n")
		fmt.Fprintf(out, "    %s\n    %s\n\n", binPath, helperPath)
		if onPath {
			fmt.Fprintf(out, "%s is already on your PATH — no shell config needed.\n", targetDir)
		} else {
			fmt.Fprintf(out, "%s is NOT on your PATH; you'd need to add it (see below).\n", targetDir)
		}
		if toolHint != "" {
			printToolHint(out, toolHint)
		}
		return nil
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", targetDir, err)
	}

	// Copy the binary unless we're already running from the target path.
	if same, _ := sameFile(self, binPath); !same {
		if err := copyExecutable(self, binPath); err != nil {
			return fmt.Errorf("installing %s: %w", binPath, err)
		}
	}

	helperKind, err := installHelper(binPath, helperPath)
	if err != nil {
		return fmt.Errorf("setting up the git-remote-gf helper: %w", err)
	}

	fmt.Fprintf(out, "\n✓  Installed gf       → %s\n", binPath)
	fmt.Fprintf(out, "✓  git-remote-gf     → %s (%s)\n\n", helperPath, helperKind)

	if onPath {
		fmt.Fprintf(out, "%s is already on your PATH — nothing else to do.\n", targetDir)
		fmt.Fprintf(out, "Open a new terminal (or run 'hash -r') and try:\n")
		fmt.Fprintf(out, "    gf login --server <url> --username <name>\n\n")
		return nil
	}

	// Explicit --dir not on PATH, or the fallback when no conventional PATH dir
	// was writable.
	printAddToPath(out, targetDir)
	if toolHint != "" {
		printToolHint(out, toolHint)
	}
	return nil
}

// dirWritable reports whether dir exists and the current user can create files
// in it. It probes by creating and removing a temp file, which reflects real
// permissions/ACLs on every OS (more reliable than checking mode bits).
func dirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".gf-writable-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// dirOnPath reports whether dir is one of the directories listed in pathEnv.
func dirOnPath(dir, pathEnv, home string) bool {
	target := filepath.Clean(dir)
	for _, raw := range strings.Split(pathEnv, string(os.PathListSeparator)) {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if filepath.Clean(expandHome(e, home)) == target {
			return true
		}
	}
	return false
}

// expandHome resolves a leading "~" against home (PATH entries are normally
// already absolute, but this keeps dirOnPath consistent with the selector).
func expandHome(dir, home string) string {
	if home == "" {
		return dir
	}
	if dir == "~" {
		return home
	}
	if strings.HasPrefix(dir, "~/") || strings.HasPrefix(dir, `~\`) {
		return filepath.Join(home, dir[2:])
	}
	return dir
}

func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}

// copyExecutable copies src to dst (0755) via a temp file + rename so an
// interrupted copy never leaves a half-written binary on PATH.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".gf-install-tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Re-assert the mode (umask may have masked the exec bits at create time).
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// installHelper makes git-remote-gf resolve to the gf binary. On Unix that's a
// symlink (falling back to a copy if the filesystem refuses symlinks); on
// Windows, where symlinks need elevation, it's a copy.
func installHelper(binPath, helperPath string) (string, error) {
	if runtime.GOOS == "windows" {
		return "copy", copyExecutable(binPath, helperPath)
	}
	_ = os.Remove(helperPath)
	if err := os.Symlink(binPath, helperPath); err != nil {
		if cerr := copyExecutable(binPath, helperPath); cerr != nil {
			return "", cerr
		}
		return "copy", nil
	}
	return "symlink", nil
}

func printAddToPath(out io.Writer, dir string) {
	fmt.Fprintf(out, "%s is not on your PATH yet. Add it once:\n\n", dir)
	if runtime.GOOS == "windows" {
		fmt.Fprintf(out, "    setx PATH \"%%PATH%%;%s\"\n\n", dir)
		fmt.Fprintf(out, "Then open a new terminal and run: gf login --server <url> --username <name>\n\n")
		return
	}
	fmt.Fprintf(out, "    echo 'export PATH=\"%s:$PATH\"' >> ~/.zshrc   # or ~/.bashrc\n", dir)
	fmt.Fprintf(out, "    source ~/.zshrc\n\n")
	fmt.Fprintf(out, "Then run: gf login --server <url> --username <name>\n\n")
}

// printToolHint mentions a writable, on-PATH directory that gf declined to use
// because it looks tool/SDK-specific, and shows how to force it if the user
// really wants it there.
func printToolHint(out io.Writer, dir string) {
	fmt.Fprintf(out, "(%s is on your PATH and writable, but it looks like it belongs to\n", dir)
	fmt.Fprintf(out, " another tool, so gf didn't install there. To use it anyway:\n")
	fmt.Fprintf(out, "     gf install --dir %s)\n\n", shellQuote(dir))
}
