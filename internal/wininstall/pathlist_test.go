package wininstall

import "testing"

func TestAddToPath(t *testing.T) {
	cases := []struct {
		name, pathEnv, dir, want string
		wantChanged              bool
	}{
		{"empty path", "", `C:\gf`, `C:\gf`, true},
		{"append", `C:\Windows`, `C:\gf`, `C:\Windows;C:\gf`, true},
		{"already present exact", `C:\Windows;C:\gf`, `C:\gf`, `C:\Windows;C:\gf`, false},
		{"already present case-insensitive", `C:\Windows;c:\GF`, `C:\gf`, `C:\Windows;c:\GF`, false},
		{"already present trailing backslash", `C:\gf\`, `C:\gf`, `C:\gf\`, false},
		{"collapse trailing separators", `C:\Windows;`, `C:\gf`, `C:\Windows;C:\gf`, true},
		{"all-separator path", ";;", `C:\gf`, `C:\gf`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := addToPath(tc.pathEnv, tc.dir)
			if got != tc.want || changed != tc.wantChanged {
				t.Fatalf("addToPath(%q,%q) = (%q,%v), want (%q,%v)", tc.pathEnv, tc.dir, got, changed, tc.want, tc.wantChanged)
			}
			if again, changed2 := addToPath(got, tc.dir); again != got || changed2 {
				t.Fatalf("addToPath not idempotent: (%q,%v)", again, changed2)
			}
		})
	}
}

func TestRemoveFromPath(t *testing.T) {
	cases := []struct {
		name, pathEnv, dir, want string
		wantChanged              bool
	}{
		{"remove middle", `C:\Windows;C:\gf;C:\Other`, `C:\gf`, `C:\Windows;C:\Other`, true},
		{"remove only", `C:\gf`, `C:\gf`, "", true},
		{"absent", `C:\Windows`, `C:\gf`, `C:\Windows`, false},
		{"case-insensitive + trailing slash", `C:\Windows;c:\GF\`, `C:\gf`, `C:\Windows`, true},
		{"removes all duplicates", `C:\gf;C:\Windows;C:\gf`, `C:\gf`, `C:\Windows`, true},
		{"preserves empty entries", `C:\Windows;;C:\gf`, `C:\gf`, `C:\Windows;`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := removeFromPath(tc.pathEnv, tc.dir)
			if got != tc.want || changed != tc.wantChanged {
				t.Fatalf("removeFromPath(%q,%q) = (%q,%v), want (%q,%v)", tc.pathEnv, tc.dir, got, changed, tc.want, tc.wantChanged)
			}
		})
	}
}

func TestAddRemoveRoundTrip(t *testing.T) {
	const base = `C:\Windows;C:\System32`
	const dir = `C:\Users\me\AppData\Local\Programs\ghostfork`
	added, ok := addToPath(base, dir)
	if !ok {
		t.Fatal("expected add to change PATH")
	}
	if back, ok := removeFromPath(added, dir); !ok || back != base {
		t.Fatalf("round-trip = (%q,%v), want (%q,true)", back, ok, base)
	}
}
