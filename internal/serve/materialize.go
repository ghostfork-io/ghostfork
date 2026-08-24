package serve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
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

	mu    sync.Mutex             // guards repos and stats
	repos map[string]*sync.Mutex // per-repo sync lock
	stats map[string]*VaultStats // per-repo transfer counters, this session
}

// VaultStats is what this session's decryption pipeline actually moved for one
// vault: measured by the same counting readers that drive the unpack, not
// estimated. The session endpoint reports these so a user can see real numbers
// for the page in front of them instead of a reassuring sentence.
type VaultStats struct {
	// PackfilesFetched is how many encrypted packfiles were pulled from the
	// server.
	PackfilesFetched int64
	// CiphertextBytes is what came off the wire; PlaintextBytes is what came
	// out of decryption locally and never left this machine.
	CiphertextBytes int64
	PlaintextBytes  int64
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
		stats:    make(map[string]*VaultStats),
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
	return m.sync(owner, repo, false)
}

// Rebuild discards the cached mirror and re-materializes the repo from packfile
// seq 0. The caller uses it when an incremental Sync leaves the cache pinned to
// history the server no longer has: the vault was deleted and re-created, so its
// packfile sequence restarted at or below our recorded last_seq and
// ListPackfiles (which returns only seqs greater than last_seq) reports nothing
// new even though every cached object is stale. Key rotation is handled inside
// sync via the generation field; this covers the reset case, which keeps
// generation == 1 and so is invisible to that check.
func (m *Materializer) Rebuild(owner, repo string) (gitDir string, err error) {
	return m.sync(owner, repo, true)
}

func (m *Materializer) sync(owner, repo string, forceFull bool) (gitDir string, err error) {
	if !nameRE.MatchString(owner) || !nameRE.MatchString(repo) {
		return "", errBadName
	}
	key := owner + "/" + repo
	l := m.lockRepo(key)
	defer l.Unlock()

	gitDir = filepath.Join(m.root, owner, repo+".git")
	// forceFull wipes the mirror before we touch it, so the state below loads
	// empty (LastSeq/Generation zero) and every packfile is re-fetched from 0.
	if forceFull {
		if err := os.RemoveAll(gitDir); err != nil {
			return "", fmt.Errorf("clearing cache for rebuild: %w", err)
		}
	}
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

	// Key rotation: the server re-encrypted history under a new key and bumped
	// the generation. Everything cached so far was decrypted with the retired
	// key, so it is stale — wipe the mirror and re-materialize from scratch
	// under the new key. (st.Generation == 0 means a first sync or pre-field
	// state, nothing to invalidate.)
	if st.Generation != 0 && generation != st.Generation {
		slog.Info("serve: key rotation detected, rebuilding cache",
			slog.String("repo", key),
			slog.Int("cached_generation", st.Generation),
			slog.Int("server_generation", generation),
		)
		if err := os.RemoveAll(gitDir); err != nil {
			return "", fmt.Errorf("clearing stale cache: %w", err)
		}
		if err := ensureBareRepo(gitDir); err != nil {
			return "", err
		}
		st = state.State{} // reset LastSeq/Generation; repacked below
		seqs, generation, err = m.up.ListPackfiles(owner, repo, 0)
		if err != nil {
			return "", fmt.Errorf("listing packfiles: %w", err)
		}
	}

	if len(seqs) == 0 {
		// Nothing to fetch, but still record the (possibly first-seen)
		// generation so a later rotation is detected.
		if st.Generation != generation {
			st.Generation = generation
			st.Repo = key
			if err := state.Save(gitDir, st); err != nil {
				return "", fmt.Errorf("saving cache state: %w", err)
			}
		}
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
		plainBytes, cipherBytes, err := helper.UnpackEncrypted(body, repoKey, gitDir)
		body.Close()
		if err != nil {
			return "", fmt.Errorf("unpacking packfile seq=%d: %w", seq, err)
		}
		m.record(key, plainBytes, cipherBytes)
		st.LastSeq = seq
	}

	st.Repo = key
	st.Generation = generation
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

// ── Session reporting ────────────────────────────────────────────────────────

// record adds one packfile's measured transfer to a vault's session counters.
func (m *Materializer) record(key string, plaintext, ciphertext int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.stats[key]
	if st == nil {
		st = &VaultStats{}
		m.stats[key] = st
	}
	st.PackfilesFetched++
	st.CiphertextBytes += ciphertext
	st.PlaintextBytes += plaintext
}

// Stats returns a vault's counters for this session. A vault that has not been
// fetched yet reports zeroes, which is the honest answer rather than an error.
func (m *Materializer) Stats(owner, repo string) VaultStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st := m.stats[owner+"/"+repo]; st != nil {
		return *st
	}
	return VaultStats{}
}

// keyFingerprintLabel domain-separates the fingerprint hash so its output can
// never be mistaken for, or used as, key material.
const keyFingerprintLabel = "ghostfork-repo-key-fingerprint\x00"

// KeyFingerprint returns a short, stable fingerprint of the vault key this
// machine decrypts with — the SSH-style "is this the key I think it is?"
// check, letting a user confirm the browser is showing data unwrapped with
// their own key. It is a truncated domain-separated SHA-256 over a 256-bit
// key, so it identifies the key without weakening it.
func (m *Materializer) KeyFingerprint(owner, repo string) (string, error) {
	if !nameRE.MatchString(owner) || !nameRE.MatchString(repo) {
		return "", errBadName
	}
	encKey, err := m.up.GetKey(owner, repo, m.username)
	if err != nil {
		return "", fmt.Errorf("fetching repo key: %w", err)
	}
	repoKey, err := crypto.DecryptRepoKey(encKey, m.identity)
	if err != nil {
		return "", fmt.Errorf("decrypting repo key: %w", err)
	}
	sum := sha256.Sum256(append([]byte(keyFingerprintLabel), repoKey...))
	return "SHA256:" + hex.EncodeToString(sum[:8]), nil
}

// CacheBytes reports how much decrypted data for a vault is already on this
// machine: the size of its bare mirror. The session dialog needs this because
// the transfer counters above are per-process, so a vault materialized on an
// earlier run legitimately reports zero bytes fetched — and a bare "0 B" in a
// trust panel reads as a broken number rather than the reassurance it is.
// Together they say the true thing: nothing was fetched because everything was
// already here, decrypted.
func (m *Materializer) CacheBytes(owner, repo string) int64 {
	if !nameRE.MatchString(owner) || !nameRE.MatchString(repo) {
		return 0
	}
	var total int64
	root := filepath.Join(m.root, owner, repo+".git")
	// A missing mirror (never browsed) sums to zero, which is correct; any
	// other walk error is not worth failing the whole dialog over.
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // partial size beats no dialog
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
