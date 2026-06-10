// Package version exposes the build identity of the gf binary: a semver
// release version baked into the source, plus the git commit the binary was
// built from.
//
// Commit is injected at build time via the linker — it is NOT read from the
// git repository at runtime, so a gf binary copied to a machine with no repo
// (or no git at all) still reports the commit it was built from. See the
// client Makefile for the -ldflags wiring.
package version

import "fmt"

// Version is the semver release version of gf. It is baked into the source
// and bumped by hand on a release; it is not injected at build time.
const Version = "0.1.0"

// Commit is the git commit the binary was built from, in short form with a
// "-dirty" suffix when the working tree had uncommitted changes at build time
// (e.g. "9f3a2bc" or "9f3a2bc-dirty"). It is overridden at build time via:
//
//	-ldflags "-X github.com/ghostfork/gf/internal/version.Commit=<commit>"
//
// Builds that don't set it — most importantly `go run .` and `go build`
// during development — fall back to "unknown".
var Commit = "unknown"

// String returns the version line shown by `gf --version` (cobra prepends
// "gf version "), e.g. "0.1.0 (commit 9f3a2bc)".
func String() string {
	return fmt.Sprintf("%s (commit %s)", Version, Commit)
}

// UserAgent returns the value sent in the User-Agent header on every request
// to the server, e.g. "gf/0.1.0 (commit 9f3a2bc)". Server logs use it to
// correlate client behaviour to a specific build.
func UserAgent() string {
	return fmt.Sprintf("gf/%s (commit %s)", Version, Commit)
}
