// Package wininstall implements the Windows install/uninstall actions for the
// gf client: it copies gf.exe (and the git-remote-gf.exe helper, which is the
// same binary dispatched by name) into a per-user directory, puts that
// directory on the user's PATH, and registers an Add/Remove Programs entry.
// Everything is per-user (HKCU + %LOCALAPPDATA%), so it needs no administrator
// rights and never triggers a UAC prompt.
//
// The PATH-string manipulation below is OS-independent and pure so it can be
// unit-tested on any platform; the registry writes, file copies, and the
// WM_SETTINGCHANGE broadcast live in the //go:build windows file.
package wininstall

import "strings"

// pathSep is the Windows PATH list separator, hardcoded so the pure logic can
// be exercised from tests on any host OS.
const pathSep = ";"

// addToPath returns pathEnv with dir appended, plus whether it changed. It is
// idempotent (Windows comparison: case-insensitive, ignoring surrounding spaces
// and a trailing backslash). A single separator joins, and trailing separators
// are collapsed so we never grow an empty tail entry.
func addToPath(pathEnv, dir string) (string, bool) {
	if dir == "" {
		return pathEnv, false
	}
	for _, e := range splitPath(pathEnv) {
		if pathEntryEqual(e, dir) {
			return pathEnv, false
		}
	}
	if strings.TrimRight(pathEnv, pathSep) == "" {
		return dir, true
	}
	return strings.TrimRight(pathEnv, pathSep) + pathSep + dir, true
}

// removeFromPath drops every entry equal to dir, returning the new value and
// whether anything was removed. Non-matching entries (including empty ones) are
// preserved in order.
func removeFromPath(pathEnv, dir string) (string, bool) {
	if dir == "" {
		return pathEnv, false
	}
	parts := splitPath(pathEnv)
	kept := make([]string, 0, len(parts))
	changed := false
	for _, e := range parts {
		if pathEntryEqual(e, dir) {
			changed = true
			continue
		}
		kept = append(kept, e)
	}
	if !changed {
		return pathEnv, false
	}
	return strings.Join(kept, pathSep), true
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, pathSep)
}

// pathEntryEqual reports whether two PATH entries name the same directory under
// Windows' rules: case-insensitive, ignoring surrounding whitespace and a
// single trailing backslash.
func pathEntryEqual(a, b string) bool { return normalizeEntry(a) == normalizeEntry(b) }

func normalizeEntry(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, `\`)
	return strings.ToLower(s)
}
