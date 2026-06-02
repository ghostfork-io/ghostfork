package installer

import (
	"strings"
	"testing"
)

// writableSet returns a predicate that reports true only for the given dirs.
func writableSet(dirs ...string) func(string) bool {
	set := map[string]bool{}
	for _, d := range dirs {
		set[d] = true
	}
	return func(d string) bool { return set[d] }
}

// The headline case: the real-Mac PATH from the issue. The system dirs aren't
// writable; among the writable ones, the user-local ~/go/bin must win over
// homebrew, /usr/local, the goenv shims dir, and the versioned nvm dir.
func TestSelectPicksUserLocalBinOnRealMacPath(t *testing.T) {
	home := "/Users/loquitus"
	path := strings.Join([]string{
		"/usr/bin", "/bin", "/usr/sbin", "/sbin",
		home + "/go/bin",
		"/opt/homebrew/bin", "/opt/homebrew/sbin",
		"/usr/local/bin",
		home + "/.goenv/shims",
		home + "/.nvm/versions/node/v25.9.0/bin",
	}, ":")
	writable := writableSet(
		home+"/go/bin", "/opt/homebrew/bin", "/opt/homebrew/sbin",
		"/usr/local/bin", home+"/.goenv/shims",
		home+"/.nvm/versions/node/v25.9.0/bin",
	) // /usr/bin, /bin, /usr/sbin, /sbin are NOT writable

	sel := Select(path, ':', home, writable)
	if !sel.Found || !sel.Conventional {
		t.Fatalf("expected a conventional dir, got %+v", sel)
	}
	if want := home + "/go/bin"; sel.Dir != want {
		t.Fatalf("Select.Dir = %q, want %q", sel.Dir, want)
	}
}

// The reported regression: a tool/SDK bin dir (~/flutter/bin) that is under
// $HOME and earlier on PATH must NOT win over a conventional dir like ~/go/bin.
func TestSelectPrefersConventionalBinOverToolSDKBin(t *testing.T) {
	home := "/home/smart"
	path := strings.Join([]string{
		home + "/flutter/bin", // user-added SDK dir, first on PATH
		home + "/go/bin",
		"/usr/local/bin",
	}, ":")
	w := writableSet(home+"/flutter/bin", home+"/go/bin", "/usr/local/bin")

	sel := Select(path, ':', home, w)
	if sel.Dir != home+"/go/bin" {
		t.Fatalf("Select.Dir = %q, want %s/go/bin (conventional must beat an SDK bin)", sel.Dir, home)
	}
	if !sel.Conventional {
		t.Fatal("expected the chosen dir to be reported conventional")
	}
}

// When ONLY a tool/SDK dir is writable, it is still returned (so we know a
// usable dir exists) but flagged non-conventional, so the caller can fall back
// rather than silently install into it.
func TestSelectFlagsToolDirAsNonConventional(t *testing.T) {
	home := "/home/smart"
	path := "/usr/bin:" + home + "/flutter/bin"
	sel := Select(path, ':', home, writableSet(home+"/flutter/bin"))
	if !sel.Found {
		t.Fatal("expected Found=true (flutter/bin is writable)")
	}
	if sel.Dir != home+"/flutter/bin" {
		t.Fatalf("Select.Dir = %q, want %s/flutter/bin", sel.Dir, home)
	}
	if sel.Conventional {
		t.Fatal("a tool/SDK bin dir must not be reported conventional")
	}
}

func TestSelectReturnsNotFoundWhenNothingWritable(t *testing.T) {
	sel := Select("/usr/bin:/bin:/sbin", ':', "/home/me", writableSet( /* none */ ))
	if sel.Found {
		t.Fatalf("expected Found=false, got %+v", sel)
	}
}

func TestSelectDeprioritizesShimsAndVersionedDirs(t *testing.T) {
	home := "/home/me"
	path := strings.Join([]string{
		home + "/.goenv/shims",
		home + "/.nvm/versions/node/v20.11.1/bin",
		"/usr/local/bin",
	}, ":")
	w := writableSet(home+"/.goenv/shims", home+"/.nvm/versions/node/v20.11.1/bin", "/usr/local/bin")
	sel := Select(path, ':', home, w)
	if sel.Dir != "/usr/local/bin" || !sel.Conventional {
		t.Fatalf("Select = %+v, want /usr/local/bin (conventional) over shims/versioned dirs", sel)
	}
}

func TestSelectPrefersHomeConventionalOverSystemConventional(t *testing.T) {
	home := "/home/me"
	// /usr/local/bin comes first but ~/.local/bin needs no sudo → preferred.
	path := "/usr/local/bin:" + home + "/.local/bin"
	w := writableSet("/usr/local/bin", home+"/.local/bin")
	sel := Select(path, ':', home, w)
	if sel.Dir != home+"/.local/bin" {
		t.Fatalf("Select.Dir = %q, want %s/.local/bin", sel.Dir, home)
	}
}

func TestSelectTieBreaksByPathOrder(t *testing.T) {
	home := "/home/me"
	// Two equally-good conventional home bin dirs; earlier PATH entry wins.
	path := home + "/bin:" + home + "/go/bin"
	sel := Select(path, ':', home, writableSet(home+"/bin", home+"/go/bin"))
	if sel.Dir != home+"/bin" {
		t.Fatalf("Select.Dir = %q, want %q (earlier PATH entry)", sel.Dir, home+"/bin")
	}
}

func TestSelectExpandsTilde(t *testing.T) {
	home := "/Users/me"
	sel := Select("~/go/bin", ':', home, writableSet(home+"/go/bin"))
	if !sel.Found || sel.Dir != home+"/go/bin" {
		t.Fatalf("Select = %+v, want dir %q", sel, home+"/go/bin")
	}
}

func TestSelectSkipsEmptyAndDuplicateEntries(t *testing.T) {
	home := "/home/me"
	path := ":" + home + "/go/bin::" + home + "/go/bin:"
	sel := Select(path, ':', home, writableSet(home+"/go/bin"))
	if !sel.Found || sel.Dir != home+"/go/bin" {
		t.Fatalf("Select = %+v, want dir %q", sel, home+"/go/bin")
	}
}

func TestSelectWindowsSeparator(t *testing.T) {
	home := `C:\Users\me`
	path := `C:\Windows\System32;C:\Users\me\bin`
	sel := Select(path, ';', home, writableSet(`C:\Users\me\bin`))
	if !sel.Found || sel.Dir != `C:\Users\me\bin` {
		t.Fatalf("Select = %+v, want dir %q", sel, `C:\Users\me\bin`)
	}
}
