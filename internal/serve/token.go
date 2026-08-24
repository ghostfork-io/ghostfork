package serve

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghostfork/gf/internal/atomicfile"
	"github.com/ghostfork/gf/internal/config"
)

// tokenFileName is the pairing-token file, stored next to the config file in
// the gf config directory. Mode 0600 ties API access to the same filesystem
// permission boundary that already protects the identity key: a local process
// that cannot read the user's files cannot read the token either.
const tokenFileName = "serve.token"

// tokenHexLen is the length of the hex-encoded pairing token: 64 lowercase hex
// characters carrying tokenBytes of entropy.
const tokenHexLen = 64

// tokenBytes is how many random bytes back a token — 32, i.e. 256 bits, double
// the 128-bit floor we hold ourselves to. This token is the only thing between
// any other local process (or any web page the user has open, which can also
// reach 127.0.0.1) and a decrypted view of their vaults, so it is sized to be
// hopeless to brute force rather than merely inconvenient.
const tokenBytes = tokenHexLen / 2

// TokenPath returns the pairing-token path, following GF_CONFIG isolation the
// same way the config and log files do.
func TokenPath() string {
	return filepath.Join(config.DefaultDir(), tokenFileName)
}

// NewToken mints a fresh pairing token and does not touch the disk. This is
// the default for `gf serve`: the token lives only in the running process's
// memory, so there is no credential at rest to leak, and a token seen over a
// shoulder or a screen share dies with the process. The cost is real — the
// dashboard must be re-paired on every start — which is why
// LoadOrCreateToken still exists behind --stable-pairing.
func NewToken() (string, error) {
	return generateToken()
}

// LoadOrCreateToken returns the PERSISTENT pairing token (gf serve
// --stable-pairing), generating and saving a fresh one when the file is
// missing, unreadable as a token, or when reset is true (--reset-pairing).
// This token is stable across runs, so the user pairs the dashboard once, at
// the price of a long-lived secret sitting in the config directory.
func LoadOrCreateToken(path string, reset bool) (string, error) {
	if !reset {
		raw, err := os.ReadFile(path)
		if err == nil {
			token := strings.TrimSpace(string(raw))
			if isValidToken(token) {
				return token, nil
			}
			// A corrupt token file can't have a working pairing to preserve —
			// regenerate rather than refusing to start.
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("reading pairing token %s: %w", path, err)
		}
	}

	token, err := generateToken()
	if err != nil {
		return "", err
	}
	if err := atomicfile.Write(path, 0600, func(w io.Writer) error {
		_, err := io.WriteString(w, token+"\n")
		return err
	}); err != nil {
		return "", fmt.Errorf("saving pairing token %s: %w", path, err)
	}
	return token, nil
}

// generateToken is the single place a pairing token is minted, whether it is
// about to be persisted or kept in memory for one run.
func generateToken() (string, error) {
	// ENTROPY SOURCE (audit note — do not swap this for anything else).
	//
	// crypto/rand.Read, Go's CSPRNG, is the only input: 32 bytes = 256 bits,
	// straight from the operating system's secure random device, hex-encoded
	// without further transformation. Per crypto/rand.Reader that is
	// getrandom(2) on Linux/FreeBSD/Dragonfly/Solaris, arc4random_buf(3) on
	// macOS/iOS/OpenBSD, the kern.arandom sysctl on NetBSD, and ProcessPrng on
	// Windows.
	//
	// Nothing predictable feeds in: no clock, no PID, no hostname, no username,
	// no counter, no per-machine seed, and no math/rand anywhere in this binary.
	// Two tokens generated a microsecond apart on the same machine share no
	// structure. Never reach for math/rand here even for "just" padding — a
	// seeded generator would make the token guessable from public facts and
	// hand a local attacker the whole vault.
	//
	// rand.Read never returns an error on any supported platform (it crashes the
	// process if the OS source fails, rather than silently yielding weak bytes).
	// The error is still checked: correct on principle, and cheap.
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating pairing token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// isValidToken accepts only the exact shape LoadOrCreateToken writes: 64 hex
// characters. It gates reuse of a persisted token, so a truncated or otherwise
// mangled file is rejected and regenerated rather than serving as a
// short — and therefore weak — token.
func isValidToken(s string) bool {
	if len(s) != tokenHexLen {
		return false
	}
	// DecodeString accepts either case; the tokens we generate are lowercase.
	_, err := hex.DecodeString(s)
	return err == nil
}
