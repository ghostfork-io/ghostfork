package state

import (
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/ghostfork/gf/internal/atomicfile"
)

// State is the per-clone state stored in .git/gf/state.
// It tracks which packfiles have already been downloaded so incremental
// pulls only fetch new ones.
type State struct {
	Repo      string `toml:"repo"` // "owner/name"
	ServerURL string `toml:"server_url"`
	LastSeq   int64  `toml:"last_seq"`
	// Generation is the repo's key generation last materialized. A rotation
	// bumps it and re-encrypts history under a new key, so cached objects from
	// an older generation are stale; `gf serve` wipes and re-materializes when
	// the server reports a different generation. Zero for state written before
	// this field existed / by the plain pull path (which keys off LastSeq only).
	Generation int `toml:"generation"`
}

// Path returns the absolute path of the state file for a given git directory.
func Path(gitDir string) string {
	return filepath.Join(gitDir, "gf", "state")
}

// Load reads the state file for gitDir.
// If the file does not exist a zero State is returned (LastSeq=0),
// which causes the next fetch to download all packfiles from the beginning.
func Load(gitDir string) (State, error) {
	var s State
	path := Path(gitDir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return s, nil
	}
	_, err := toml.DecodeFile(path, &s)
	return s, err
}

// Save writes s atomically to the state file for gitDir.
func Save(gitDir string, s State) error {
	return atomicfile.Write(Path(gitDir), 0600, func(w io.Writer) error {
		return toml.NewEncoder(w).Encode(s)
	})
}
