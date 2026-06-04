package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/ghostfork/gf/internal/atomicfile"
)

// Config holds the user's persistent client configuration. Note that the
// signing private key lives in a separate file (DefaultIdentityPath); this
// file never contains secret material.
type Config struct {
	Username  string `toml:"username"`
	ServerURL string `toml:"server_url"`
}

// rawConfig is used to detect old-format files that still hold an api_key.
// We refuse to load such files and direct the user to re-run gf login.
type rawConfig struct {
	Username  string `toml:"username"`
	ServerURL string `toml:"server_url"`
	APIKey    string `toml:"api_key"`
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

// DefaultDir returns the gf config directory — the parent of DefaultPath.
// The active account's config and identity live directly here; other
// accounts are parked in a subdirectory named after their username (see
// the switch-user command).
func DefaultDir() string {
	return filepath.Dir(DefaultPath())
}

// DefaultLogPath returns the path to the CLI/helper log file, which lives in
// the gf config directory next to the config file (e.g. ~/.config/gf/gf.log
// on Linux). GHOSTFORK_LOG_FILE overrides it (handled in internal/logging).
// Following DefaultDir means tests that set GF_CONFIG get an isolated log too.
func DefaultLogPath() string {
	return filepath.Join(DefaultDir(), "gf.log")
}

// DefaultIdentityPath returns the path to the Ed25519 identity file.
// Overridable via GF_IDENTITY env var.
func DefaultIdentityPath() string {
	if p := os.Getenv("GF_IDENTITY"); p != "" {
		return p
	}
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "gf", "identity.ed25519")
}

// Load reads and parses the config file at path. Refuses old api_key-based
// configs with a clear error so the user knows to wipe state and re-login.
func Load(path string) (*Config, error) {
	var raw rawConfig
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return nil, err
	}
	if raw.APIKey != "" {
		return nil, fmt.Errorf(
			"config at %s is from a pre-signature build (contains api_key).\n"+
				"Delete the gf config directory and run 'gf login' again to migrate", path)
	}
	return &Config{Username: raw.Username, ServerURL: raw.ServerURL}, nil
}

// Save writes cfg to path atomically in TOML format, creating parent
// directories as needed. The config holds no secret material, but a crash
// or encode error still must not corrupt the existing file.
func Save(path string, cfg *Config) error {
	return atomicfile.Write(path, 0600, func(w io.Writer) error {
		return toml.NewEncoder(w).Encode(cfg)
	})
}
