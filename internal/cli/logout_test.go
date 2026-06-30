package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/config"
)

func TestLogoutBacksUpKeyThenClearsSession(t *testing.T) {
	dir := setupGFDir(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	const seed = "alice-secret-seed\n"
	writeActive(t, dir, "alice", seed)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	if err := runLogout(cmd, nil); err != nil {
		t.Fatalf("logout: %v", err)
	}

	// Backup: exactly one timestamped file holding the verbatim key bytes, 0600.
	matches, _ := filepath.Glob(filepath.Join(home, ".ghostfork", "backup", "*.key"))
	if len(matches) != 1 {
		t.Fatalf("want exactly one backup .key file, got %v", matches)
	}
	if got := readFile(t, matches[0]); got != seed {
		t.Errorf("backup content = %q, want the identity bytes %q", got, seed)
	}
	fi, err := os.Stat(matches[0])
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("backup perm = %o, want 0600", perm)
	}

	// Credentials cleared: identity and config are gone.
	if _, err := os.Stat(config.DefaultIdentityPath()); !os.IsNotExist(err) {
		t.Errorf("identity should be removed after logout; stat err = %v", err)
	}
	if _, err := os.Stat(config.DefaultPath()); !os.IsNotExist(err) {
		t.Errorf("config should be removed after logout; stat err = %v", err)
	}

	// Subsequent commands must require login again.
	if _, err := loadSession(); err == nil {
		t.Error("loadSession should fail after logout (gf login required)")
	}

	// Output matches the demo wording.
	out := buf.String()
	for _, want := range []string{"private key backed up to ~/.ghostfork/backup/", "session cleared"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got: %q", want, out)
		}
	}
}

func TestLogoutWhenNotLoggedIn(t *testing.T) {
	setupGFDir(t) // GF_CONFIG/GF_IDENTITY point at an empty temp dir (no files)
	home := t.TempDir()
	t.Setenv("HOME", home)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	if err := runLogout(cmd, nil); err != nil {
		t.Fatalf("logout when not logged in should be a no-op, got: %v", err)
	}
	if !strings.Contains(buf.String(), "not logged in") {
		t.Errorf("want a 'not logged in' message; got: %q", buf.String())
	}
	// No backup directory should be created when there was no key to back up.
	if _, err := os.Stat(filepath.Join(home, ".ghostfork")); !os.IsNotExist(err) {
		t.Errorf("no backup dir should be created when not logged in; stat err = %v", err)
	}
}
