package version_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommitInjectedAtBuildTime proves the full build-time path end to end:
// building the real gf binary with -ldflags overriding version.Commit must
// surface that exact value (dirty suffix and all) through `gf --version`.
// This is what the Makefile relies on, exercised through an actual go build
// rather than by poking the package variable.
func TestCommitInjectedAtBuildTime(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles a binary; skipped under -short")
	}

	bin := filepath.Join(t.TempDir(), "gf")
	build := exec.Command("go", "build",
		"-ldflags", "-X github.com/ghostfork/gf/internal/version.Commit=abc1234-dirty",
		"-o", bin, "github.com/ghostfork/gf/cmd/gf")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building gf: %v\n%s", err, out)
	}

	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("gf --version: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	want := "gf version 0.1.0 (commit abc1234-dirty)"
	if got != want {
		t.Errorf("gf --version = %q, want %q", got, want)
	}
}
