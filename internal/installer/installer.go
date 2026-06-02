// Package installer chooses where to drop the gf binary so it is immediately
// found on the user's PATH — no sudo, no editing shell config. The directory
// selection is a pure function (Select) so it can be unit-tested across
// platforms without touching the real filesystem or environment.
package installer

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// versionSeg matches a path segment that looks like a version-manager's
// versioned directory (e.g. "v25.9.0", "20.11.1", "v1.21").
var versionSeg = regexp.MustCompile(`^v?\d+\.\d+`)

// Selection is the outcome of scanning PATH for an install target.
type Selection struct {
	// Dir is the best writable directory found, or "" if none was.
	Dir string
	// Conventional is true when Dir is a standard, general-purpose location
	// for user binaries (e.g. ~/go/bin, ~/.local/bin, /usr/local/bin) rather
	// than a directory that belongs to a specific tool or SDK (e.g.
	// ~/flutter/bin, a version manager's bin). Callers should only auto-install
	// silently when this is true.
	Conventional bool
	// Found is true when any writable directory was found on PATH.
	Found bool
}

// Select scans PATH for the best directory to install a user binary into. It is
// pure and deterministic for testability: the caller supplies the raw PATH
// value, the list separator (os.PathListSeparator), the user's home directory,
// and a predicate reporting whether a directory is writable by the current
// user.
//
// Ranking (lower score wins; ties break toward earlier PATH entries, honoring
// the shell's own lookup precedence):
//   - a conventional, general-purpose bin directory is strongly preferred — so
//     gf never silently lands in a tool/SDK directory like ~/flutter/bin just
//     because it happened to come first on PATH;
//   - among those, user-owned (home) directories beat system ones (no sudo);
//   - version-manager "shims" and versioned (…/v25.9.0/bin) directories are
//     deprioritized as managed/ephemeral.
//
// Whether the winner is conventional is reported in Selection.Conventional, so
// the caller can decide to fall back (rather than pollute a tool directory)
// when only non-conventional dirs are writable. No specific directory is ever
// hardcoded as an install target — every candidate comes from the live PATH;
// the conventional-dir shapes are used only to rank what PATH already contains.
func Select(pathEnv string, listSep byte, homeDir string, writable func(string) bool) Selection {
	var best Selection
	bestScore := 0
	seen := map[string]bool{}

	for _, raw := range strings.Split(pathEnv, string(listSep)) {
		dir := strings.TrimSpace(raw)
		if dir == "" {
			continue
		}
		dir = filepath.Clean(expandHome(dir, homeDir))
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if !writable(dir) {
			continue
		}
		conv := conventionalBinDir(dir, homeDir)
		// Strictly-less keeps the FIRST entry among equal scores, so ties fall
		// to the earlier PATH position automatically.
		if score := scoreDir(dir, homeDir, conv); !best.Found || score < bestScore {
			best = Selection{Dir: dir, Conventional: conv, Found: true}
			bestScore = score
		}
	}
	return best
}

func scoreDir(dir, home string, conventional bool) int {
	score := 0
	if !conventional {
		score += 10 // strongly prefer standard bin dirs over tool/SDK dirs
	}
	if !underHome(dir, home) {
		score++ // among equals, prefer user-owned dirs (no sudo)
	}
	segs := splitSegments(dir)
	if slices.Contains(segs, "shims") {
		score += 2
	}
	if slices.ContainsFunc(segs, versionSeg.MatchString) {
		score += 4
	}
	return score
}

// conventionalBinDir reports whether dir is a standard, general-purpose
// location for user binaries — as opposed to a directory owned by a specific
// tool or SDK (e.g. ~/flutter/bin, ~/.nvm/.../bin). Recognized by well-known
// shape, never by absolute path, and used only to rank directories that are
// already on PATH.
func conventionalBinDir(dir, home string) bool {
	dir = filepath.Clean(dir)
	if home != "" {
		home = filepath.Clean(home)
		for _, rel := range []string{"bin", filepath.Join(".local", "bin"), filepath.Join("go", "bin")} {
			if dir == filepath.Join(home, rel) {
				return true
			}
		}
	}
	switch dir {
	case filepath.Clean("/usr/local/bin"), filepath.Clean("/usr/local/sbin"),
		filepath.Clean("/opt/homebrew/bin"), filepath.Clean("/opt/homebrew/sbin"):
		return true
	}
	return false
}

func underHome(dir, home string) bool {
	if home == "" {
		return false
	}
	home = filepath.Clean(home)
	return dir == home || strings.HasPrefix(dir, home+string(filepath.Separator))
}

// splitSegments splits a path into its components on either separator so the
// same logic works for Unix ("/") and Windows ("\") paths.
func splitSegments(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
}

// expandHome resolves a leading "~" (rare in a real PATH, but cheap to honor)
// against homeDir.
func expandHome(dir, home string) string {
	if home == "" {
		return dir
	}
	if dir == "~" {
		return home
	}
	if strings.HasPrefix(dir, "~/") || strings.HasPrefix(dir, `~\`) {
		return filepath.Join(home, dir[2:])
	}
	return dir
}
