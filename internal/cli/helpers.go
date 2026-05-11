package cli

import (
	"fmt"
	"strings"

	"github.com/ghostfork/gf/internal/config"
)

// loadConfig loads the config file from the default path and returns a helpful
// error if it is missing (i.e. the user has not run gf login yet).
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return nil, fmt.Errorf("not logged in — run 'gf login' first (%w)", err)
	}
	return cfg, nil
}

// parseRepoArg accepts either "reponame" or "org/reponame". When no org is
// present the caller's own username is used as the org (V1 convention).
func parseRepoArg(arg, defaultOrg string) (org, repo string) {
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		return arg[:i], arg[i+1:]
	}
	return defaultOrg, arg
}
