package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds the user's persistent client configuration.
type Config struct {
	Username  string `toml:"username"`
	APIKey    string `toml:"api_key"`
	ServerURL string `toml:"server_url"`
}

// DefaultPath returns the path to the config file.
// Overridable via GF_CONFIG env var (used in tests to avoid touching ~/.config).
func DefaultPath() string {
	if p := os.Getenv("GF_CONFIG"); p != "" {
		return p
	}
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "gf", "config")
}

// DefaultIdentityPath returns the path to the age private key file.
// Overridable via GF_IDENTITY env var.
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

// Save writes cfg to path in TOML format, creating parent directories as needed.
func Save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(cfg)
}
