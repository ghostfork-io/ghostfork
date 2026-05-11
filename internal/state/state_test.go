package state_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ghostfork/gf/internal/state"
)

// ── Path ──────────────────────────────────────────────────────────────────────

func TestPathReturnsCorrectLocation(t *testing.T) {
	got := state.Path("/repo/.git")
	want := filepath.Join("/repo/.git", "gf", "state")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// ── Load ──────────────────────────────────────────────────────────────────────

func TestLoadMissingFileReturnsZeroState(t *testing.T) {
	gitDir := t.TempDir()

	s, err := state.Load(gitDir)
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if s.LastSeq != 0 {
		t.Fatalf("expected LastSeq=0, got %d", s.LastSeq)
	}
	if s.Repo != "" {
		t.Fatalf("expected empty Repo, got %q", s.Repo)
	}
	if s.ServerURL != "" {
		t.Fatalf("expected empty ServerURL, got %q", s.ServerURL)
	}
}

func TestLoadReturnsCorrectValues(t *testing.T) {
	gitDir := t.TempDir()
	original := state.State{
		Repo:      "alice/myrepo",
		ServerURL: "https://api.gf.dev",
		LastSeq:   42,
	}
	if err := state.Save(gitDir, original); err != nil {
		t.Fatal(err)
	}

	loaded, err := state.Load(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Repo != original.Repo {
		t.Errorf("Repo: got %q, want %q", loaded.Repo, original.Repo)
	}
	if loaded.ServerURL != original.ServerURL {
		t.Errorf("ServerURL: got %q, want %q", loaded.ServerURL, original.ServerURL)
	}
	if loaded.LastSeq != original.LastSeq {
		t.Errorf("LastSeq: got %d, want %d", loaded.LastSeq, original.LastSeq)
	}
}

// ── Save ──────────────────────────────────────────────────────────────────────

func TestSaveCreatesDirectory(t *testing.T) {
	gitDir := t.TempDir()

	if err := state.Save(gitDir, state.State{LastSeq: 1}); err != nil {
		t.Fatalf("Save should create the gf/ directory: %v", err)
	}

	if _, err := os.Stat(state.Path(gitDir)); err != nil {
		t.Fatalf("state file not created: %v", err)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	gitDir := t.TempDir()
	original := state.State{
		Repo:      "org/project",
		ServerURL: "https://api.gf.dev",
		LastSeq:   99,
	}

	if err := state.Save(gitDir, original); err != nil {
		t.Fatal(err)
	}

	loaded, err := state.Load(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != original {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", loaded, original)
	}
}

func TestSaveUpdatesLastSeq(t *testing.T) {
	gitDir := t.TempDir()

	state.Save(gitDir, state.State{LastSeq: 5})  //nolint:errcheck
	state.Save(gitDir, state.State{LastSeq: 10}) //nolint:errcheck

	loaded, _ := state.Load(gitDir)
	if loaded.LastSeq != 10 {
		t.Fatalf("expected LastSeq=10, got %d", loaded.LastSeq)
	}
}

// ── Atomicity ─────────────────────────────────────────────────────────────────

func TestSaveLeavesNoTempFile(t *testing.T) {
	gitDir := t.TempDir()

	if err := state.Save(gitDir, state.State{LastSeq: 7}); err != nil {
		t.Fatal(err)
	}

	tmpPath := filepath.Join(gitDir, "gf", "state.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal(".tmp file still exists after Save — write was not atomic")
	}
}

func TestSaveDoesNotCorruptOnReread(t *testing.T) {
	gitDir := t.TempDir()
	first := state.State{Repo: "a/b", LastSeq: 3}
	second := state.State{Repo: "a/b", LastSeq: 7}

	state.Save(gitDir, first)  //nolint:errcheck
	state.Save(gitDir, second) //nolint:errcheck

	loaded, err := state.Load(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastSeq != 7 {
		t.Fatalf("expected LastSeq=7 after two saves, got %d", loaded.LastSeq)
	}
}
