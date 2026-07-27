//go:build windows && !embedgf

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// gfPayload returns the gf.exe image to install. In the default (non-embedded)
// build the installer expects gf.exe next to it — ship gf-setup.exe and gf.exe
// together. The distributable single-file installer embeds gf.exe instead
// (build with -tags embedgf; see the Makefile).
func gfPayload() ([]byte, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	sibling := filepath.Join(filepath.Dir(self), "gf.exe")
	b, err := os.ReadFile(sibling)
	if err != nil {
		return nil, fmt.Errorf("gf.exe not found next to the installer (%s): %w", sibling, err)
	}
	return b, nil
}
