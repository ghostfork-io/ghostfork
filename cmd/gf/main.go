package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghostfork/gf/internal/cli"
	"github.com/ghostfork/gf/internal/helper"
)

func main() {
	// Git invokes the remote helper by the basename "git-remote-gf". On Windows
	// the on-disk name carries a ".exe" suffix, so trim it before comparing —
	// otherwise the helper dispatch would never fire there.
	invoked := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	if invoked == "git-remote-gf" {
		helper.Run()
		return
	}
	if err := cli.Execute(); err != nil {
		// ErrSilent means the command already printed its own user-facing
		// failure output (e.g. gf verify's "decryption aborted") — just exit
		// non-zero without crowding it with an "Error:" line.
		if !errors.Is(err, cli.ErrSilent) {
			// Pad the error like the commands pad their success output: a leading
			// blank line and a trailing blank line so it doesn't crowd the command
			// or the next prompt. The "Error:" prefix labels what follows, which
			// may be a multi-line message.
			fmt.Fprintf(os.Stderr, "\nError: %v\n\n", err)
		}
		os.Exit(1)
	}
}
