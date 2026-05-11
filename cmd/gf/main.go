package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ghostfork/gf/internal/cli"
	"github.com/ghostfork/gf/internal/helper"
)

func main() {
	if filepath.Base(os.Args[0]) == "git-remote-gf" {
		helper.Run()
		return
	}
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
