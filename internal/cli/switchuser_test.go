package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// writeActive creates the active config + identity files directly in the gf
// config dir, with the given username.
func writeActive(t *testing.T, dir, username, identity string) {
	t.Helper()
	cfg := "username = \"" + username + "\"\nserver_url = \"http://localhost:4640\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity.ed25519"), []byte(identity), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeParked creates a parked profile subdirectory <dir>/<username> holding
// that account's config + identity.
func writeParked(t *testing.T, dir, username, identity string) {
	t.Helper()
	sub := filepath.Join(dir, username)
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	writeActive(t, sub, username, identity)
}

// setupGFDir points GF_CONFIG/GF_IDENTITY at a fresh temp gf dir and returns it.
func setupGFDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GF_CONFIG", filepath.Join(dir, "config"))
	t.Setenv("GF_IDENTITY", filepath.Join(dir, "identity.ed25519"))
	return dir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSwitchUserSwapsActiveAndParked(t *testing.T) {
	dir := setupGFDir(t)
	writeActive(t, dir, "alice", "alice-key")
	writeParked(t, dir, "bob", "bob-key")

	if err := runSwitchUser(switchUserCmd, []string{"bob"}); err != nil {
		t.Fatalf("switch-user: %v", err)
	}

	// bob is now active at the top level.
	if got := readFile(t, filepath.Join(dir, "identity.ed25519")); got != "bob-key" {
		t.Fatalf("active identity = %q, want bob-key", got)
	}
	// alice is parked.
	if got := readFile(t, filepath.Join(dir, "alice", "identity.ed25519")); got != "alice-key" {
		t.Fatalf("parked alice identity = %q, want alice-key", got)
	}
	// bob's parked dir is gone.
	if _, err := os.Stat(filepath.Join(dir, "bob")); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed, stat err = %v", filepath.Join(dir, "bob"), err)
	}
}

func TestSwitchUserMissingParkedProfile(t *testing.T) {
	dir := setupGFDir(t)
	writeActive(t, dir, "alice", "alice-key")

	err := runSwitchUser(switchUserCmd, []string{"bob"})
	if err == nil {
		t.Fatal("expected error for missing parked profile")
	}
	// Active account must be untouched.
	if got := readFile(t, filepath.Join(dir, "identity.ed25519")); got != "alice-key" {
		t.Fatalf("active identity changed to %q after failed switch", got)
	}
}

func TestSwitchUserRejectsPathTraversal(t *testing.T) {
	setupGFDir(t)
	if err := runSwitchUser(switchUserCmd, []string{"../evil"}); err == nil {
		t.Fatal("expected error for path-traversal username")
	}
}

func TestSwitchUserRejectsCurrentUser(t *testing.T) {
	dir := setupGFDir(t)
	writeActive(t, dir, "alice", "alice-key")
	writeParked(t, dir, "alice", "alice-key") // contrived, but should be refused

	if err := runSwitchUser(switchUserCmd, []string{"alice"}); err == nil {
		t.Fatal("expected error when switching to the already-active user")
	}
}
