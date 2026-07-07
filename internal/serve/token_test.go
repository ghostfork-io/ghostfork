package serve

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateTokenLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.token")

	first, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("first LoadOrCreateToken: %v", err)
	}
	if !isValidToken(first) {
		t.Fatalf("generated token %q is not %d hex chars", first, tokenHexLen)
	}

	// Stable across runs: the user pairs the dashboard once.
	second, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("second LoadOrCreateToken: %v", err)
	}
	if second != first {
		t.Errorf("token changed between runs without reset: %q → %q", first, second)
	}

	// --reset-pairing rotates it.
	rotated, err := LoadOrCreateToken(path, true)
	if err != nil {
		t.Fatalf("LoadOrCreateToken(reset): %v", err)
	}
	if rotated == first {
		t.Error("reset did not change the token")
	}
	if !isValidToken(rotated) {
		t.Errorf("rotated token %q is not valid", rotated)
	}

	// And the rotated token is what subsequent runs load.
	after, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("LoadOrCreateToken after reset: %v", err)
	}
	if after != rotated {
		t.Errorf("loaded %q after reset, want the rotated token %q", after, rotated)
	}
}

func TestTokenFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "serve.token")
	if _, err := LoadOrCreateToken(path, false); err != nil {
		t.Fatalf("LoadOrCreateToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("token file mode = %o, want 0600 — the token must share the identity key's permission boundary", mode)
	}
}

func TestCorruptTokenFileRegenerates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.token")
	if err := os.WriteFile(path, []byte("not-a-token\n"), 0600); err != nil {
		t.Fatalf("seeding corrupt file: %v", err)
	}

	token, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("LoadOrCreateToken on corrupt file: %v", err)
	}
	if !isValidToken(token) {
		t.Errorf("token %q after corrupt-file recovery is not valid", token)
	}
}
