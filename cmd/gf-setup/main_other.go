//go:build !windows

// gf-setup is the Windows-only graphical installer for the gf client. On other
// platforms it just says so — Unix users install via `make install` in the
// client module. This stub keeps `go build ./...` green on every OS.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "gf-setup is the Windows installer and only runs on Windows.")
	fmt.Fprintln(os.Stderr, "On macOS/Linux, install with:  make -C client install")
	os.Exit(1)
}
