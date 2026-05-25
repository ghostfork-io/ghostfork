package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghostfork/gf/internal/config"
)

// ── DefaultPath ───────────────────────────────────────────────────────────────

func TestDefaultPathUsesGFCONFIGEnvVar(t *testing.T) {
	expected := "/tmp/custom/gf/config"
	t.Setenv("GF_CONFIG", expected)

	if got := config.DefaultPath(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestDefaultPathFallsBackToUserConfigDir(t *testing.T) {
	t.Setenv("GF_CONFIG", "")

	got := config.DefaultPath()
	if got == "" {
		t.Fatal("expected non-empty default path")
	}
	if filepath.Base(got) != "config" {
		t.Fatalf("expected filename to be 'config', got %q", filepath.Base(got))
	}
}

// ── DefaultIdentityPath ───────────────────────────────────────────────────────

func TestDefaultIdentityPathUsesGFIDENTITYEnvVar(t *testing.T) {
	expected := "/tmp/custom/gf/identity.ed25519"
	t.Setenv("GF_IDENTITY", expected)

	if got := config.DefaultIdentityPath(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestDefaultIdentityPathFallsBackToUserConfigDir(t *testing.T) {
	t.Setenv("GF_IDENTITY", "")

	got := config.DefaultIdentityPath()
	if got == "" {
		t.Fatal("expected non-empty default identity path")
	}
	if filepath.Base(got) != "identity.ed25519" {
		t.Fatalf("expected filename to be 'identity.ed25519', got %q", filepath.Base(got))
	}
}

// ── Save ──────────────────────────────────────────────────────────────────────

func TestConfigSaveCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "config")

	err := config.Save(path, &config.Config{
		Username:  "alice",
		ServerURL: "https://api.gf.dev",
	})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config file not created: %v", err)
	}
}

func TestConfigSaveWritesAllFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	cfg := &config.Config{
		Username:  "alice",
		ServerURL: "https://api.gf.dev",
	}

	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	for _, want := range []string{"alice", "https://api.gf.dev"} {
		if !strings.Contains(content, want) {
			t.Errorf("saved file missing %q\nfile content:\n%s", want, content)
		}
	}
}

// ── Load ──────────────────────────────────────────────────────────────────────

func TestConfigLoadMissingFileReturnsError(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("expected error loading missing file, got nil")
	}
}

func TestConfigLoadRefusesOldAPIKeyFormat(t *testing.T) {
	// Pre-signature configs included api_key; they must not silently load
	// because the identity that authenticated them is gone.
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path,
		[]byte("username = \"alice\"\nserver_url = \"https://example\"\napi_key = \"old-token\"\n"),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for legacy api_key config, got nil")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Fatalf("expected error to mention api_key, got: %v", err)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	original := &config.Config{
		Username:  "alice",
		ServerURL: "https://api.gf.dev",
	}

	if err := config.Save(path, original); err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Username != original.Username {
		t.Errorf("Username: got %q, want %q", loaded.Username, original.Username)
	}
	if loaded.ServerURL != original.ServerURL {
		t.Errorf("ServerURL: got %q, want %q", loaded.ServerURL, original.ServerURL)
	}
}

func TestConfigSaveOverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")

	config.Save(path, &config.Config{Username: "alice", ServerURL: "old"})         //nolint:errcheck
	config.Save(path, &config.Config{Username: "alice", ServerURL: "new-server"}) //nolint:errcheck

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ServerURL != "new-server" {
		t.Fatalf("expected ServerURL=new-server after overwrite, got %q", loaded.ServerURL)
	}
}
