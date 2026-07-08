package serve

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/helper"
	"github.com/ghostfork/gf/internal/state"
)

// nameRE mirrors the server's storage.ValidateName character set. owner and
// repo arrive from the request URL and become local directory names, so the
// helper enforces the same rules rather than trusting the caller — anything
// else is treated as a repo that doesn't exist.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// errBadName marks an owner/repo that fails validation; handlers surface it
// as repo_not_found, indistinguishable from a missing repo.
var errBadName = fmt.Errorf("invalid owner or repo name")

// MaterializeUpstream is the slice of the signed API client the Materializer
// needs to pull a repo's encrypted history.
type MaterializeUpstream interface {
	GetKey(owner, repo, username string) ([]byte, error)
	ListPackfiles(owner, repo string, afterSeq int64) (seqs []int64, generation int, err error)
	DownloadPackfile(owner, repo string, seq int64) (io.ReadCloser, error)
}

// Materializer maintains hidden bare git repos under root, one per browsed
// repo, holding the decrypted object store the read endpoints (tree, blob,
// history) run git plumbing against. It reuses the normal fetch pipeline:
// download encrypted packfiles, decrypt + Poly1305-verify on the fly, pipe
// into git index-pack. Plaintext exists only inside these local directories,
// never in transit to the server.
type Materializer struct {
	up       MaterializeUpstream
	identity *crypto.Identity
	username string
	root     string

	mu    sync.Mutex             // guards repos
	repos map[string]*sync.Mutex // per-repo sync lock
}

// NewMaterializer returns a Materializer caching under root (created lazily,
// 0700 — the contents are decrypted repo data).
func NewMaterializer(up MaterializeUpstream, identity *crypto.Identity, username, root string) *Materializer {
	return &Materializer{
		up:       up,
		identity: identity,
		username: username,
		root:     root,
		repos:    make(map[string]*sync.Mutex),
	}
}

// DefaultCacheRoot returns where `gf serve` materializes repos for a given
// server: <user-cache-dir>/gf/serve/<server-host>/<username>. Host and
// username are part of the path so caches from different servers or accounts
// never mix. GF_SERVE_CACHE overrides it (tests, unusual setups).
func DefaultCacheRoot(serverURL, username string) (string, error) {
	if p := os.Getenv("GF_SERVE_CACHE"); p != "" {
		return p, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory (set GF_SERVE_CACHE): %w", err)
	}
	origin, err := Origin(serverURL)
	if err != nil {
		return "", err
	}
	host := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	host = strings.ReplaceAll(host, ":", "_")
	return filepath.Join(base, "gf", "serve", host, username), nil
}

// lockRepo returns the mutex serializing syncs of one repo, locked. Concurrent
// dashboard requests for the same repo would otherwise download the same
// packfiles twice; different repos still sync in parallel.
func (m *Materializer) lockRepo(key string) *sync.Mutex {
	m.mu.Lock()
	l, ok := m.repos[key]
	if !ok {
		l = &sync.Mutex{}
		m.repos[key] = l
	}
	m.mu.Unlock()
	l.Lock()
	return l
}

// Sync brings the local bare repo for owner/repo up to date with the server
// and returns its git directory. The first sync of a repo downloads and
// decrypts its full history and can take a while; later syncs only fetch
// packfiles with seq > the recorded last_seq (a key rotation replaces history
// at a higher seq, so the incremental path picks it up naturally, same as a
// normal pull).
func (m *Materializer) Sync(owner, repo string) (gitDir string, err error) {
	if !nameRE.MatchString(owner) || !nameRE.MatchString(repo) {
		return "", errBadName
	}
	key := owner + "/" + repo
	l := m.lockRepo(key)
	defer l.Unlock()

	gitDir = filepath.Join(m.root, owner, repo+".git")
	if err := ensureBareRepo(gitDir); err != nil {
		return "", err
	}

	st, err := state.Load(gitDir)
	if err != nil {
		return "", fmt.Errorf("loading cache state: %w", err)
	}

	encKey, err := m.up.GetKey(owner, repo, m.username)
	if err != nil {
		return "", fmt.Errorf("fetching repo key: %w", err)
	}
	repoKey, err := crypto.DecryptRepoKey(encKey, m.identity)
	if err != nil {
		return "", fmt.Errorf("decrypting repo key: %w", err)
	}

	seqs, generation, err := m.up.ListPackfiles(owner, repo, st.LastSeq)
	if err != nil {
		return "", fmt.Errorf("listing packfiles: %w", err)
	}
	if len(seqs) == 0 {
		return gitDir, nil
	}
	slog.Info("serve: materializing repo",
		slog.String("repo", key),
		slog.Int("packfiles", len(seqs)),
		slog.Int64("after_seq", st.LastSeq),
		slog.Int("generation", generation),
	)

	for _, seq := range seqs {
		body, err := m.up.DownloadPackfile(owner, repo, seq)
		if err != nil {
			return "", fmt.Errorf("downloading packfile seq=%d: %w", seq, err)
		}
		_, _, err = helper.UnpackEncrypted(body, repoKey, gitDir)
		body.Close()
		if err != nil {
			return "", fmt.Errorf("unpacking packfile seq=%d: %w", seq, err)
		}
		st.LastSeq = seq
	}

	st.Repo = key
	if err := state.Save(gitDir, st); err != nil {
		return "", fmt.Errorf("saving cache state: %w", err)
	}
	return gitDir, nil
}

// ensureBareRepo creates a bare git repo at dir if none exists yet. A bare
// repo (not a working copy) because nothing is ever checked out — the read
// endpoints only run plumbing against the object store.
func ensureBareRepo(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "objects")); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	cmd := exec.Command("git", "init", "--bare", "--quiet", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git init --bare: %w\n%s", err, out)
	}
	return nil
}
