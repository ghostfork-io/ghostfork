package serve

import (
	"encoding/hex"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateTokenLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.token")

	first, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("first LoadOrCreateToken: %v", err)
	}
	if !isValidToken(first) {
		t.Fatalf("generated token %q is not %d hex chars", first, tokenHexLen)
	}

	// Stable across runs: the user pairs the dashboard once.
	second, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("second LoadOrCreateToken: %v", err)
	}
	if second != first {
		t.Errorf("token changed between runs without reset: %q → %q", first, second)
	}

	// --reset-pairing rotates it.
	rotated, err := LoadOrCreateToken(path, true)
	if err != nil {
		t.Fatalf("LoadOrCreateToken(reset): %v", err)
	}
	if rotated == first {
		t.Error("reset did not change the token")
	}
	if !isValidToken(rotated) {
		t.Errorf("rotated token %q is not valid", rotated)
	}

	// And the rotated token is what subsequent runs load.
	after, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("LoadOrCreateToken after reset: %v", err)
	}
	if after != rotated {
		t.Errorf("loaded %q after reset, want the rotated token %q", after, rotated)
	}
}

func TestTokenFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "serve.token")
	if _, err := LoadOrCreateToken(path, false); err != nil {
		t.Fatalf("LoadOrCreateToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("token file mode = %o, want 0600 — the token must share the identity key's permission boundary", mode)
	}
}

func TestCorruptTokenFileRegenerates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.token")
	if err := os.WriteFile(path, []byte("not-a-token\n"), 0600); err != nil {
		t.Fatalf("seeding corrupt file: %v", err)
	}

	token, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("LoadOrCreateToken on corrupt file: %v", err)
	}
	if !isValidToken(token) {
		t.Errorf("token %q after corrupt-file recovery is not valid", token)
	}
}

// TestTokenGeneratorQuality is the regression guard the pairing token's threat
// model asks for: this token is the only thing between any other local process
// and a decrypted view of the user's vaults, so a swap to a weak generator must
// fail loudly here.
//
// It cannot prove entropy, and does not try. What it does is fail for every
// cheap way a generator gets weakened in practice:
//
//   - uniqueness alone is deliberately NOT the only check — a counter or a
//     clock-derived token is unique too, and would sail through it. The
//     shared-prefix check below is what catches those, since sequential and
//     time-based values differ only in their last few digits.
//   - the byte-coverage check catches a generator drawing from a narrow
//     alphabet or a small modulus, which uniqueness and prefixes both miss.
//
// Every threshold is chosen so a correct CSPRNG cannot realistically trip it;
// the probabilities are worked out at each assertion.
func TestTokenGeneratorQuality(t *testing.T) {
	const samples = 1000

	// The entropy floor is asserted against a literal, NOT against tokenBytes.
	// Checking the generated length against the package's own constant would
	// pass happily if someone lowered both together, which is exactly how a
	// token quietly shrinks to a brute-forceable size. 16 bytes = 128 bits is
	// the documented minimum; we currently ship double that.
	const minEntropyBytes = 16
	if tokenBytes < minEntropyBytes {
		t.Fatalf("tokenBytes = %d (%d bits), below the %d-bit floor this token needs",
			tokenBytes, tokenBytes*8, minEntropyBytes*8)
	}

	seen := make(map[string]bool, samples)
	var seenByte [256]bool
	prev := ""

	for i := range samples {
		// NewToken is the default path for `gf serve` and the sole minting
		// point both modes share, so testing it covers the stored token too.
		token, err := NewToken()
		if err != nil {
			t.Fatalf("generation %d: %v", i, err)
		}

		// Format: exactly 64 lowercase hex characters. Anything else means the
		// encoding or the length changed, and a shorter token is a weaker one.
		if len(token) != tokenHexLen {
			t.Fatalf("generation %d: length %d, want %d", i, len(token), tokenHexLen)
		}
		raw, err := hex.DecodeString(token)
		if err != nil {
			t.Fatalf("generation %d: %q is not hex: %v", i, token, err)
		}
		if len(raw) != tokenBytes {
			t.Fatalf("generation %d: %d bytes of entropy, want %d", i, len(raw), tokenBytes)
		}
		if len(raw) < minEntropyBytes {
			t.Fatalf("generation %d: only %d bits of entropy, floor is %d",
				i, len(raw)*8, minEntropyBytes*8)
		}
		if token != strings.ToLower(token) {
			t.Fatalf("generation %d: %q is not lowercase hex", i, token)
		}

		// Uniqueness. A repeat inside 1000 draws from a 256-bit space is not
		// bad luck — a birthday collision needs ~2^128 draws — so this only
		// ever fires on a broken generator.
		if seen[token] {
			t.Fatalf("generation %d: token %q already seen — the generator is repeating", i, token)
		}
		seen[token] = true

		// Successive tokens must not share a long prefix. A counter or a
		// clock-derived value shares nearly all of it; two independent random
		// tokens share more than 8 hex characters with probability 16^-8 ≈
		// 2e-10, so across 999 pairs this is ~2e-7 likely to flake.
		if prev != "" {
			if n := commonPrefixLen(prev, token); n > 8 {
				t.Fatalf("generations %d and %d share a %d-character prefix (%q vs %q) — "+
					"that is the signature of a counter or clock-seeded generator, not a CSPRNG",
					i-1, i, n, prev, token)
			}
		}
		prev = token

		for _, b := range raw {
			seenByte[b] = true
		}
	}

	// Across 1000 × 32 = 32000 bytes, every one of the 256 byte values should
	// appear: the chance a given value is absent is (255/256)^32000 ≈ 1e-54.
	// A generator restricted to, say, ASCII or a small modulus fails here even
	// though its output is unique and prefix-free.
	missing := 0
	for _, ok := range seenByte {
		if !ok {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d of 256 byte values never appeared across %d tokens — "+
			"the generator is not drawing from the full byte range", missing, samples)
	}
}

// commonPrefixLen returns how many leading characters a and b share.
func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// TestTokenSourceIsCryptoRand guards the one regression no statistical test can
// catch. A seeded math/rand stream is uniformly distributed: it produces unique,
// prefix-free tokens covering the full byte range, so it passes every check in
// TestTokenGeneratorQuality while being trivially predictable to anyone who
// learns the seed. The only reliable way to catch that swap is to read the
// imports, so this asserts on the package's source directly: crypto/rand must be
// there, math/rand must not be, in any non-test file of the package.
func TestTokenSourceIsCryptoRand(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing package source: %v", err)
	}

	cryptoRandFiles := []string{}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "math/rand" || path == "math/rand/v2" {
					t.Errorf("%s imports %q — the pairing token must come from a CSPRNG. "+
						"If this import is for something unrelated, it still doesn't belong in "+
						"the package that mints the token: move it out.", name, path)
				}
				if path == "crypto/rand" {
					cryptoRandFiles = append(cryptoRandFiles, name)
				}
			}
		}
	}

	if len(cryptoRandFiles) == 0 {
		t.Error("no file in this package imports crypto/rand — the pairing token's " +
			"documented entropy source is gone")
	}
}

// TestNewTokenIsEphemeral pins the default `gf serve` behaviour: a fresh token
// per run, and nothing written to disk. The no-file half matters as much as the
// freshness — the point of rotating per run is that no credential is left at
// rest, so a regression that "helpfully" persisted the token would defeat it
// while every uniqueness check still passed.
func TestNewTokenIsEphemeral(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GF_CONFIG", filepath.Join(dir, "config"))

	first, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	second, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken (second): %v", err)
	}

	if !isValidToken(first) || !isValidToken(second) {
		t.Fatalf("malformed tokens: %q, %q", first, second)
	}
	if first == second {
		t.Error("two NewToken calls returned the same token — the default must rotate every run")
	}

	// Nothing may appear on disk, at the token path or anywhere in the config dir.
	if _, err := os.Stat(TokenPath()); !os.IsNotExist(err) {
		t.Errorf("NewToken wrote %s — the default token must never be persisted", TokenPath())
	}
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) > 0 {
		t.Errorf("NewToken left %d file(s) in the config dir; want none", len(entries))
	}
}

// TestStablePairingStillPersists guards the --stable-pairing escape hatch, so
// the opt-out keeps working after the default flipped.
func TestStablePairingStillPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.token")

	first, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("LoadOrCreateToken: %v", err)
	}
	again, err := LoadOrCreateToken(path, false)
	if err != nil {
		t.Fatalf("LoadOrCreateToken (second): %v", err)
	}
	if again != first {
		t.Errorf("--stable-pairing token changed between runs: %q → %q", first, again)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("--stable-pairing did not persist the token: %v", err)
	}
}
