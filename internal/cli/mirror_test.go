package cli

import (
	"strings"
	"testing"
)

func TestVaultNameFromURL(t *testing.T) {
	cases := map[string]string{
		"git@github.com:alice/proj.git":       "proj",
		"https://github.com/alice/proj":       "proj",
		"https://github.com/alice/proj.git/":  "proj",
		"ssh://git@github.com/alice/proj.git": "proj",
		"/srv/git/proj.git":                   "proj",
		"proj":                                "proj",
	}
	for in, want := range cases {
		got, err := vaultNameFromURL(in)
		if err != nil || got != want {
			t.Errorf("vaultNameFromURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/", "https://github.com/", "git@github.com:"} {
		if got, err := vaultNameFromURL(in); err == nil {
			t.Errorf("vaultNameFromURL(%q) = %q; want an error", in, got)
		}
	}
}

func TestRedactURLHidesCredentials(t *testing.T) {
	got := redactURL("https://alice:ghp_secret123@github.com/alice/proj.git")
	if strings.Contains(got, "ghp_secret123") || strings.Contains(got, "alice:") {
		t.Fatalf("credentials survived redaction: %s", got)
	}
	if !strings.Contains(got, "github.com/alice/proj.git") {
		t.Fatalf("redaction lost the repo path: %s", got)
	}
	for _, in := range []string{"git@github.com:alice/proj.git", "https://github.com/alice/proj"} {
		if got := redactURL(in); got != in {
			t.Errorf("redactURL(%q) = %q; want it unchanged", in, got)
		}
	}
}

func TestMirrorCacheDirRejectsTraversal(t *testing.T) {
	for _, bad := range [][2]string{{"..", "x"}, {"alice", ".."}, {"alice", "a/b"}, {"alice", `a\b`}} {
		if _, err := mirrorCacheDir(bad[0], bad[1]); err == nil {
			t.Errorf("mirrorCacheDir(%q, %q) succeeded; want an error", bad[0], bad[1])
		}
	}
}
