//go:build windows && embedgf

package main

import _ "embed"

// gfExeBytes is the gf.exe baked into the self-contained installer. The
// build-windows-installer target copies the freshly built gf.exe to
// assets/gf.exe before compiling with -tags embedgf, so this only compiles
// when that asset exists.
//
//go:embed assets/gf.exe
var gfExeBytes []byte

func gfPayload() ([]byte, error) { return gfExeBytes, nil }
