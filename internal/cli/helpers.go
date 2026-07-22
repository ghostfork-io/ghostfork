package cli

import (
	"fmt"
	"strings"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
)

// session is the per-invocation context every authenticated CLI command
// shares: loaded config, loaded identity, and a ready-to-use signed API client.
type session struct {
	cfg      *config.Config
	identity *crypto.Identity
	client   *apiclient.Client
}

// loadSession reads the saved config and identity and constructs a signed
// API client. Returns a clear error when the user has not yet run gf login.
func loadSession() (*session, error) {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return nil, fmt.Errorf("not logged in — run 'gf login' first (%w)", err)
	}
	id, err := crypto.LoadIdentity(config.DefaultIdentityPath())
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}
	return &session{
		cfg:      cfg,
		identity: id,
		client:   apiclient.NewAuthenticated(cfg.ServerURL, cfg.Username, id.Signer()),
	}, nil
}

// parseRepoArg accepts either "reponame" or "owner/reponame". When no owner is
// present the caller's own username is used as the default owner.
// Returns an error if either component is empty after parsing.
func parseRepoArg(arg, defaultOwner string) (owner, repo string, err error) {
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		owner, repo = arg[:i], arg[i+1:]
	} else {
		owner, repo = defaultOwner, arg
	}
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("invalid vault argument %q: owner and vault name must both be non-empty", arg)
	}
	return owner, repo, nil
}
