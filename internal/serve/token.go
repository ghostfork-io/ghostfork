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

// tokenHexLen is the length of the hex-encoded 256-bit pairing token.
const tokenHexLen = 64

// TokenPath returns the pairing-token path, following GF_CONFIG isolation the
// same way the config and log files do.
func TokenPath() string {
	return filepath.Join(config.DefaultDir(), tokenFileName)
}

// LoadOrCreateToken returns the persistent pairing token, generating and
// saving a fresh one when the file is missing, unreadable as a token, or when
// reset is true (gf serve --reset-pairing). The token is stable across runs so
// the user pairs the dashboard once, not on every start.
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

	buf := make([]byte, tokenHexLen/2)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating pairing token: %w", err)
	}
	token := hex.EncodeToString(buf)
	if err := atomicfile.Write(path, 0600, func(w io.Writer) error {
		_, err := io.WriteString(w, token+"\n")
		return err
	}); err != nil {
		return "", fmt.Errorf("saving pairing token %s: %w", path, err)
	}
	return token, nil
}

func isValidToken(s string) bool {
	if len(s) != tokenHexLen {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
