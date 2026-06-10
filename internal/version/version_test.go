package version

import (
	"regexp"
	"testing"
)

// withCommit temporarily overrides the build-injected Commit for one test and
// restores it afterward, so tests don't leak state into one another.
func withCommit(t *testing.T, c string) {
	t.Helper()
	prev := Commit
	Commit = c
	t.Cleanup(func() { Commit = prev })
}

func TestVersionIsSemver(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(Version) {
		t.Errorf("Version = %q, want a bare semver like 1.2.3", Version)
	}
}

func TestCommitDefaultsToUnknown(t *testing.T) {
	// The package default (no -ldflags) must be the graceful fallback, so a
	// `go run`/`go build` dev binary reports "unknown" rather than empty.
	if Commit != "unknown" {
		t.Errorf("default Commit = %q, want \"unknown\"", Commit)
	}
}

func TestStringFormat(t *testing.T) {
	withCommit(t, "9f3a2bc")
	if got, want := String(), "0.1.0 (commit 9f3a2bc)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringFormatDirty(t *testing.T) {
	withCommit(t, "9f3a2bc-dirty")
	if got, want := String(), "0.1.0 (commit 9f3a2bc-dirty)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestUserAgentFormat(t *testing.T) {
	withCommit(t, "9f3a2bc")
	if got, want := UserAgent(), "gf/0.1.0 (commit 9f3a2bc)"; got != want {
		t.Errorf("UserAgent() = %q, want %q", got, want)
	}
}

func TestUserAgentUnknown(t *testing.T) {
	withCommit(t, "unknown")
	if got, want := UserAgent(), "gf/0.1.0 (commit unknown)"; got != want {
		t.Errorf("UserAgent() = %q, want %q", got, want)
	}
}
