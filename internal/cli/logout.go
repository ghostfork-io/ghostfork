package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/config"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Back up your key, then clear this machine's session",
	Long: `Log out of Ghostfork on this machine.

Your Ed25519 private key IS your account — there is no password and no
server-side recovery (V1), so deleting the key without a copy means losing
access to every repo forever. Logout therefore copies the key to a timestamped
backup under ~/.ghostfork/backup/ BEFORE removing anything; if that backup
fails, nothing is cleared. Keep the backup file safe.

After logout, gf has no local identity, so further commands require 'gf login'
again. To log back in — here or on another machine — use the backed-up key:

    gf login --server <url> --username <name> --recover    # paste the key, or
    # copy the backup file into gf's config dir, then run gf login`,
	Example: `  gf logout`,
	Args:    cobra.NoArgs,
	RunE:    runLogout,
}

func runLogout(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	identityPath := config.DefaultIdentityPath()
	cfgPath := config.DefaultPath()

	keyBytes, err := os.ReadFile(identityPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No key to back up. Still remove any stray config so the machine
			// ends in a clean, logged-out state.
			_ = os.Remove(cfgPath)
			fmt.Fprintln(out, "  not logged in — nothing to do")
			return nil
		}
		return fmt.Errorf("reading identity from %s: %w", identityPath, err)
	}

	// 1) Back up the key BEFORE touching anything. If this fails we abort with
	//    the session fully intact, so the user can never lose access here.
	backupPath, err := backUpPrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("backing up private key (nothing was cleared): %w", err)
	}
	slog.Debug("private key backed up", slog.String("path", backupPath))
	fmt.Fprintf(out, "  private key backed up to %s\n", tildeCollapse(backupPath))

	// 2) Clear local session credentials: the identity (the key) and the
	//    config (username + server URL). A missing file is fine — we only need
	//    the end state to be "logged out".
	if err := os.Remove(identityPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing identity %s (your key backup is safe at %s): %w", identityPath, backupPath, err)
	}
	if err := os.Remove(cfgPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing config %s (your key backup is safe at %s): %w", cfgPath, backupPath, err)
	}
	slog.Debug("session cleared", slog.String("identity", identityPath), slog.String("config", cfgPath))
	fmt.Fprintln(out, "  session cleared")
	return nil
}

// backUpPrivateKey writes keyBytes verbatim to a timestamped file under
// ~/.ghostfork/backup/ and returns the path. The bytes are copied as-is (the
// base64 Ed25519 seed exactly as the identity file holds it) so the backup is a
// drop-in for 'gf login --recover' or a straight file copy back into place. The
// directory is 0700 and the file 0600 — it holds the secret that is the account.
func backUpPrivateKey(keyBytes []byte) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	dir := filepath.Join(home, ".ghostfork", "backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, time.Now().Format("20060102-150405")+".key")
	if err := os.WriteFile(path, keyBytes, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// tildeCollapse rewrites a path under the home directory to use "~" for display,
// so the printed backup location reads ~/.ghostfork/backup/<ts>.key rather than
// an absolute path. Paths outside home are returned unchanged.
func tildeCollapse(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	rel, err := filepath.Rel(home, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p
	}
	return "~/" + filepath.ToSlash(rel)
}
