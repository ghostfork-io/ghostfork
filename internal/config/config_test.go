package config_test

import (
	"os"
	"path/filepath"
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
	expected := "/tmp/custom/gf/identity.age"
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
	if filepath.Base(got) != "identity.age" {
		t.Fatalf("expected filename to be 'identity.age', got %q", filepath.Base(got))
	}
}

// ── Save ──────────────────────────────────────────────────────────────────────

func TestConfigSaveCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "config")

	err := config.Save(path, &config.Config{
		Username:  "alice",
		APIKey:    "key123",
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
		APIKey:    "secretkey",
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
	for _, want := range []string{"alice", "secretkey", "https://api.gf.dev"} {
		if !contains(content, want) {
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

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	original := &config.Config{
		Username:  "alice",
		APIKey:    "myapikey",
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
	if loaded.APIKey != original.APIKey {
		t.Errorf("APIKey: got %q, want %q", loaded.APIKey, original.APIKey)
	}
	if loaded.ServerURL != original.ServerURL {
		t.Errorf("ServerURL: got %q, want %q", loaded.ServerURL, original.ServerURL)
	}
}

func TestConfigSaveOverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")

	config.Save(path, &config.Config{Username: "alice", APIKey: "old"}) //nolint:errcheck
	config.Save(path, &config.Config{Username: "alice", APIKey: "new"}) //nolint:errcheck

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.APIKey != "new" {
		t.Fatalf("expected APIKey=new after overwrite, got %q", loaded.APIKey)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
