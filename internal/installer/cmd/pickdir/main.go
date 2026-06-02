// Command pickdir is a build-time helper used by `make install`. It prints, on
// stdout, the directory `make install` should drop the gf binary into — a
// writable, conventional directory already on the user's PATH (so gf works
// with no shell-config changes), or ~/.local/bin as a fallback. Any advisory
// note (e.g. a tool/SDK dir was skipped) is written to stderr so it reaches the
// user without polluting the captured stdout value.
//
// This is NOT shipped in the gf binary and is not a user-facing command — it
// exists only so the Makefile can reuse the tested directory-selection logic in
// internal/installer rather than reimplementing it in shell.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ghostfork/gf/internal/installer"
)

func main() {
	home, _ := os.UserHomeDir()
	sel := installer.Select(os.Getenv("PATH"), byte(os.PathListSeparator), home, dirWritable)

	if sel.Found && sel.Conventional {
		fmt.Println(sel.Dir)
		return
	}

	// No conventional writable dir on PATH. Fall back to ~/.local/bin; if the
	// only writable PATH dir was a tool/SDK directory, point the user at the
	// PREFIX override instead of silently using it.
	if sel.Found {
		fmt.Fprintf(os.Stderr,
			"note: %s is writable and on your PATH but looks tool-specific, so gf was not\n"+
				"      installed there. To use it anyway:  make install PREFIX=%s\n",
			sel.Dir, filepath.Dir(sel.Dir))
	}
	fmt.Println(filepath.Join(home, ".local", "bin"))
}

// dirWritable reports whether dir exists and the current user can create files
// in it, probed by creating and removing a temp file (reflects real perms/ACLs
// on every OS).
func dirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".gf-writable-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}
