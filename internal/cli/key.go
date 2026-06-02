package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/crypto"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage your Ghostfork identity key",
	Long: `Work with the Ed25519 private key that identifies your account.

The key is the whole account: there is no password and no server-side
recovery (V1). Keep a backup somewhere safe, and use 'gf key export' to
move your account to another machine.`,
}

var keyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export your private key to move your account to another machine",
	Long: `Export your private key so you can move your Ghostfork account to a new
machine (or recover it after losing your config).

Three modes:

  gf key export              Show where the key file is and exactly how to
                             copy it to a new machine. Does NOT print the key.
  gf key export --clipboard  Copy the key onto your system clipboard, ready to
                             paste into 'gf login --recover' on the new machine.
  gf key export --show       Print just the key (and nothing else) to stdout —
                             for piping, or to copy it by hand on a headless box.

Whichever you use, the command finishes by telling you the exact next step to
run on the new machine.`,
	Example: `  # See the key file path and step-by-step move instructions
  gf key export

  # Put the key on the clipboard, then paste it into --recover elsewhere
  gf key export --clipboard

  # Print the key for manual copy (e.g. over SSH where there's no clipboard)
  gf key export --show`,
	Args: cobra.NoArgs,
	RunE: runKeyExport,
}

func init() {
	keyExportCmd.Flags().BoolP("clipboard", "c", false, "copy the private key to the system clipboard")
	keyExportCmd.Flags().Bool("show", false, "print only the raw private key to stdout (for piping / manual copy)")
	keyCmd.AddCommand(keyExportCmd)
}

func runKeyExport(cmd *cobra.Command, _ []string) error {
	clip, _ := cmd.Flags().GetBool("clipboard")
	show, _ := cmd.Flags().GetBool("show")
	if clip && show {
		return fmt.Errorf("--clipboard and --show cannot be used together")
	}

	identityPath := config.DefaultIdentityPath()
	id, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf(
				"no identity found at %s — there is nothing to export yet.\n"+
					"Run 'gf login --server <url> --username <name>' first to create your account",
				identityPath)
		}
		return fmt.Errorf("reading identity from %s: %w", identityPath, err)
	}

	// The exported string is the base64-std Ed25519 seed — byte-for-byte what
	// the identity file holds and exactly what 'gf login --recover' expects.
	keyStr := base64.StdEncoding.EncodeToString(id.Signer().Seed())

	// --show: emit only the key, so the output can be piped or copied cleanly.
	// Any surrounding prose would corrupt a pipe, so there is none.
	if show {
		fmt.Fprintln(cmd.OutOrStdout(), keyStr)
		return nil
	}

	// Pre-fill the recovery command with this account's server + username so
	// the printed instructions are copy-paste ready. Best-effort: fall back to
	// obvious placeholders if there's no config to read.
	server, username := "https://api.example.com", "<your-username>"
	if cfg, cfgErr := config.Load(config.DefaultPath()); cfgErr == nil {
		if cfg.ServerURL != "" {
			server = cfg.ServerURL
		}
		if cfg.Username != "" {
			username = cfg.Username
		}
	}

	if clip {
		if err := copyToClipboard(keyStr); err != nil {
			return fmt.Errorf(
				"could not copy to the clipboard: %w\n\n"+
					"This is normal over SSH or on a headless machine. Instead:\n"+
					"  • gf key export --show   print the key, then copy it yourself, or\n"+
					"  • gf key export          copy the key *file* to the new machine",
				err)
		}
		printClipboardInstructions(cmd, server, username)
		return nil
	}

	printFileInstructions(cmd, identityPath, server, username)
	return nil
}

// printFileInstructions is the default mode: it reveals the key file's path
// (never its contents) and walks the user through copying the file to a new
// machine and recovering there.
func printFileInstructions(cmd *cobra.Command, identityPath, server, username string) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "\nYour Ghostfork private key is stored in this file:\n\n")
	fmt.Fprintf(w, "    %s\n\n", identityPath)
	fmt.Fprintf(w, "Move your account to a NEW machine in 3 steps:\n\n")
	fmt.Fprintf(w, "  1. Copy the key file to the new machine. For example, over SSH:\n\n")
	fmt.Fprintf(w, "         scp %s \\\n             USER@NEW_HOST:~/.config/gf/identity.ed25519\n\n", identityPath)
	fmt.Fprintf(w, "     First make sure the folder exists on the new machine:\n")
	fmt.Fprintf(w, "         mkdir -p ~/.config/gf && chmod 700 ~/.config/gf\n\n")
	fmt.Fprintf(w, "  2. Log in on the new machine. gf finds the copied key and recovers\n")
	fmt.Fprintf(w, "     your account automatically — no extra flags needed:\n\n")
	fmt.Fprintf(w, "         gf login --server %s --username %s\n\n", server, username)
	fmt.Fprintf(w, "  3. Done — 'git push' and 'git pull' work exactly as before.\n\n")
	fmt.Fprintf(w, "Prefer copy-paste over copying a file?\n")
	fmt.Fprintf(w, "    gf key export --clipboard   put the key on your clipboard, then run\n")
	fmt.Fprintf(w, "                                'gf login ... --recover' on the new machine\n")
	fmt.Fprintf(w, "    gf key export --show        print the key so you can copy it by hand\n\n")
}

// printClipboardInstructions is shown after the key has been placed on the
// clipboard: it tells the user exactly what to run and paste on the new machine.
func printClipboardInstructions(cmd *cobra.Command, server, username string) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "\n✓  Your private key is now on the clipboard.\n\n")
	fmt.Fprintf(w, "Recover your account on a NEW machine in 3 steps:\n\n")
	fmt.Fprintf(w, "  1. Install gf on the new machine.\n\n")
	fmt.Fprintf(w, "  2. Run this, and paste the key when prompted:\n\n")
	fmt.Fprintf(w, "         gf login --server %s --username %s --recover\n\n", server, username)
	fmt.Fprintf(w, "     Paste with Ctrl+Shift+V (most terminals) or Cmd+V (macOS), then Enter.\n\n")
	fmt.Fprintf(w, "  3. Done — 'git push' and 'git pull' work exactly as before.\n\n")
	fmt.Fprintf(w, "⚠  The clipboard now holds your secret key. After pasting it on the new\n")
	fmt.Fprintf(w, "   machine, copy something else to clear it.\n\n")
}

// copyToClipboard writes s to the system clipboard using whichever standard
// tool is available, trying the common ones across macOS, Linux (Wayland/X11),
// and Windows/WSL. Returns an error if none are found or the tool fails.
func copyToClipboard(s string) error {
	candidates := [][]string{
		{"pbcopy"},                           // macOS
		{"wl-copy"},                          // Linux / Wayland
		{"xclip", "-selection", "clipboard"}, // Linux / X11
		{"xsel", "--clipboard", "--input"},   // Linux / X11
		{"clip.exe"},                         // Windows / WSL
	}
	for _, c := range candidates {
		path, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		proc := exec.Command(path, c[1:]...)
		proc.Stdin = strings.NewReader(s)
		if err := proc.Run(); err != nil {
			return fmt.Errorf("clipboard tool %q failed: %w", c[0], err)
		}
		return nil
	}
	return errors.New("no clipboard tool found (looked for pbcopy, wl-copy, xclip, xsel, clip.exe)")
}
