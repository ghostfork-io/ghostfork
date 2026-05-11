package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if filepath.Base(os.Args[0]) == "git-remote-gf" {
		fmt.Fprintln(os.Stderr, "git-remote-gf: not yet implemented")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "gf: CLI not yet implemented")
	os.Exit(1)
}
