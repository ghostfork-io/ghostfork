package main

import (
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
