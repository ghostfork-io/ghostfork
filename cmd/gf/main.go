package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ghostfork/gf/internal/cli"
)

func main() {
	if filepath.Base(os.Args[0]) == "git-remote-gf" {
		fmt.Fprintln(os.Stderr, "git-remote-gf: not yet implemented")
		os.Exit(1)
	}
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
