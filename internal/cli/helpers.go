package cli

import (
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/crypto"
)

// session is the per-invocation context every authenticated CLI command
// shares: loaded config plus a ready-to-use API client.
type session struct {
	cfg    *config.Config
	client *apiclient.Client
}

// loadSession reads the saved config and constructs the API client. Returns
// a clear error when the user has not yet run gf login.
func loadSession() (*session, error) {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return nil, fmt.Errorf("not logged in — run 'gf login' first (%w)", err)
	}
	return &session{
		cfg:    cfg,
		client: apiclient.New(cfg.ServerURL, cfg.APIKey),
	}, nil
}

// loadIdentity reads the user's age private key from the default location,
// wrapping the error so the CLI surface stays consistent.
func loadIdentity() (*age.X25519Identity, error) {
	id, err := crypto.LoadIdentity(config.DefaultIdentityPath())
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}
	return id, nil
}

// parseRepoArg accepts either "reponame" or "org/reponame". When no org is
// present the caller's own username is used as the default org.
// Returns an error if either component is empty after parsing.
func parseRepoArg(arg, defaultOrg string) (org, repo string, err error) {
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		org, repo = arg[:i], arg[i+1:]
	} else {
		org, repo = defaultOrg, arg
	}
	if org == "" || repo == "" {
		return "", "", fmt.Errorf("invalid repo argument %q: org and repo name must both be non-empty", arg)
	}
	return org, repo, nil
}
