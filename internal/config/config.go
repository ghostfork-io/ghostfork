package config

import (
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/ghostfork/gf/internal/atomicfile"
)

// Config holds the user's persistent client configuration.
type Config struct {
	Username  string `toml:"username"`
	APIKey    string `toml:"api_key"`
	ServerURL string `toml:"server_url"`
}

// DefaultPath returns the path to the config file.
// Overridable via GF_CONFIG env var (used in tests to avoid touching ~/.config).
//
// os.UserConfigDir's error is intentionally dropped: it only fires when
// neither $HOME nor $XDG_CONFIG_HOME is set (or the platform equivalent),
// which is effectively unreachable on a real user machine. In that case
// the returned path is relative ("gf/config") and the user should set
// GF_CONFIG to override.
func DefaultPath() string {
	if p := os.Getenv("GF_CONFIG"); p != "" {
		return p
	}
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "gf", "config")
}

// DefaultIdentityPath returns the path to the age private key file.
// Overridable via GF_IDENTITY env var. The os.UserConfigDir error is
// dropped for the same reason as DefaultPath.
func DefaultIdentityPath() string {
	if p := os.Getenv("GF_IDENTITY"); p != "" {
		return p
	}
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "gf", "identity.age")
}

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes cfg to path atomically in TOML format, creating parent
// directories as needed. A crash or encode error never corrupts an existing
// config file — important because the file holds the user's API key.
func Save(path string, cfg *Config) error {
	return atomicfile.Write(path, 0600, func(w io.Writer) error {
		return toml.NewEncoder(w).Encode(cfg)
	})
}
