// Package helper implements the git-remote-gf remote helper protocol.
//
// Git spawns this process for any remote with a gf:// URL, communicating
// over stdin/stdout using the standard git remote helper line protocol.
package helper

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/crypto"
	"github.com/ghostfork/gf/internal/logging"
	"github.com/ghostfork/gf/internal/state"
	"github.com/ghostfork/gf/shared/types"
)

// Run is the entry point called from cmd/gf/main.go when the binary is
// invoked as git-remote-gf. Git passes: git-remote-gf <remote-name> <url>
func Run() {
	// git invokes us directly, so we have no -v flag to honour — verbosity is
	// controlled by GHOSTFORK_LOG_LEVEL (see internal/logging).
	logging.SetDefault(logging.NewCLI(false))

	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: git-remote-gf <remote-name> <url>")
		os.Exit(1)
	}

	remoteURL := os.Args[2]
	owner, repo, err := parseURL(remoteURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-gf: invalid URL %q: %v\n", remoteURL, err)
		os.Exit(1)
	}

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-gf: not logged in — run 'gf login' first\n")
		os.Exit(1)
	}
	id, err := crypto.LoadIdentity(config.DefaultIdentityPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-gf: loading identity: %v\n", err)
		os.Exit(1)
	}

	slog.Debug("helper start",
		slog.String("owner", owner),
		slog.String("repo", repo),
		slog.String("server", cfg.ServerURL),
		slog.String("username", cfg.Username),
	)

	h := &helper{
		owner:    owner,
		repo:     repo,
		cfg:      cfg,
		identity: id,
		client:   apiclient.NewAuthenticated(cfg.ServerURL, cfg.Username, id.Signer()),
	}

	if err := h.run(os.Stdin, os.Stdout); err != nil {
		slog.Error("helper exited with error", slog.Any("err", err))
		fmt.Fprintf(os.Stderr, "git-remote-gf: %v\n", err)
		os.Exit(1)
	}
}

type helper struct {
	owner    string
	repo     string
	cfg      *config.Config
	identity *crypto.Identity
	client   *apiclient.Client
}

// run drives the line-protocol loop with git over r/w.
func (h *helper) run(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case line == "capabilities":
			fmt.Fprintf(w, "fetch\npush\n\n")

		case line == "list" || line == "list for-push":
			if err := h.handleList(w); err != nil {
				return err
			}

		case strings.HasPrefix(line, "fetch "):
			batch := []string{line}
			for scanner.Scan() {
				if l := scanner.Text(); l == "" {
					break
				} else {
					batch = append(batch, l)
				}
			}
			if err := h.handleFetch(w, batch); err != nil {
				return err
			}

		case strings.HasPrefix(line, "push "):
			batch := []string{line}
			for scanner.Scan() {
				if l := scanner.Text(); l == "" {
					break
				} else {
					batch = append(batch, l)
				}
			}
			if err := h.handlePush(w, batch); err != nil {
				return err
			}

		case strings.HasPrefix(line, "option "):
			fmt.Fprintln(w, "unsupported")

		case line == "":
			// trailing blank line — ignore

		default:
			return fmt.Errorf("unknown command: %q", line)
		}
	}
	return scanner.Err()
}

// ── list ──────────────────────────────────────────────────────────────────────

func (h *helper) handleList(w io.Writer) error {
	slog.Debug("list refs", slog.String("owner", h.owner), slog.String("repo", h.repo))
	refs, err := h.client.GetRefs(h.owner, h.repo)
	if err != nil {
		return fmt.Errorf("listing refs: %w", err)
	}
	slog.Debug("refs fetched", slog.Int("count", len(refs)))

	for _, ref := range refs {
		fmt.Fprintf(w, "%s refs/heads/%s\n", ref.CommitSHA, ref.Branch)
	}

	// Advertise HEAD → main when main exists so `git clone` checks out correctly.
	for _, ref := range refs {
		if ref.Branch == "main" {
			fmt.Fprintf(w, "@refs/heads/main HEAD\n")
			break
		}
	}

	fmt.Fprintln(w) // blank line terminates the list
	return nil
}

// ── fetch ─────────────────────────────────────────────────────────────────────

func (h *helper) handleFetch(w io.Writer, _ []string) error {
	gitDir, err := findGitDir()
	if err != nil {
		return err
	}

	st, err := state.Load(gitDir)
	if err != nil {
		return fmt.Errorf("loading state: %w", err)
	}
	slog.Debug("fetch start",
		slog.String("git_dir", gitDir),
		slog.Int64("last_seq", st.LastSeq),
	)

	encKey, err := h.client.GetKey(h.owner, h.repo, h.cfg.Username)
	if err != nil {
		return fmt.Errorf("fetching repo key: %w", err)
	}

	repoKey, err := crypto.DecryptRepoKey(encKey, h.identity)
	if err != nil {
		return fmt.Errorf("decrypting repo key: %w", err)
	}
	slog.Debug("repo key decrypted")

	seqs, err := h.client.ListPackfiles(h.owner, h.repo, st.LastSeq)
	if err != nil {
		return fmt.Errorf("listing packfiles: %w", err)
	}
	slog.Debug("packfiles to fetch", slog.Int("count", len(seqs)))

	for _, seq := range seqs {
		body, err := h.client.DownloadPackfile(h.owner, h.repo, seq)
		if err != nil {
			return fmt.Errorf("downloading packfile seq=%d: %w", seq, err)
		}
		slog.Debug("packfile download started", slog.Int64("seq", seq))

		if err := unpackEncrypted(body, repoKey, gitDir); err != nil {
			body.Close()
			return fmt.Errorf("unpacking packfile seq=%d: %w", seq, err)
		}
		body.Close()
		slog.Debug("packfile unpacked", slog.Int64("seq", seq))

		st.LastSeq = seq
	}

	// Persist state only after every packfile has been successfully unpacked.
	st.Repo = h.owner + "/" + h.repo
	st.ServerURL = h.cfg.ServerURL
	if err := state.Save(gitDir, st); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}
	slog.Debug("fetch complete", slog.Int64("last_seq", st.LastSeq))

	fmt.Fprintln(w) // blank line = fetch complete
	return nil
}

// unpackEncrypted streams encrypted packfile bytes from src, decrypts them on
// the fly, and pipes the plaintext pack into `git index-pack --stdin`, which
// writes it into the local object store as a pack (plus index).
//
// index-pack is used rather than unpack-objects: it keeps the objects packed
// instead of exploding them into the loose-object directory, which is what
// real git does on fetch and is the only form that scales to large packs.
//
// Decryption runs in a goroutine writing to a pipe so neither the ciphertext
// nor the plaintext is ever fully buffered in memory.
func unpackEncrypted(src io.Reader, repoKey []byte, gitDir string) error {
	pr, pw := io.Pipe()

	cmd := exec.Command("git", "index-pack", "--stdin")
	cmd.Stdin = pr
	cmd.Env = append(os.Environ(), "GIT_DIR="+gitDir)
	cmd.Stderr = os.Stderr
	cmd.Stdout = io.Discard // index-pack prints the pack SHA we don't need

	if err := cmd.Start(); err != nil {
		pr.Close()
		return fmt.Errorf("starting index-pack: %w", err)
	}

	// Decrypt into the pipe. Any decryption error is propagated to index-pack
	// by closing the write end with that error, so cmd.Wait observes a broken
	// stdin and fails rather than indexing a truncated pack.
	decErr := make(chan error, 1)
	go func() {
		err := crypto.DecryptPackfile(pw, src, repoKey)
		pw.CloseWithError(err)
		decErr <- err
	}()

	waitErr := cmd.Wait()
	if err := <-decErr; err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}
	if waitErr != nil {
		return fmt.Errorf("index-pack: %w", waitErr)
	}
	return nil
}

// ── push ──────────────────────────────────────────────────────────────────────

func (h *helper) handlePush(w io.Writer, batch []string) error {
	gitDir, err := findGitDir()
	if err != nil {
		return err
	}
	slog.Debug("push start",
		slog.String("git_dir", gitDir),
		slog.Int("specs", len(batch)),
	)

	encKey, err := h.client.GetKey(h.owner, h.repo, h.cfg.Username)
	if err != nil {
		return fmt.Errorf("fetching repo key: %w", err)
	}

	repoKey, err := crypto.DecryptRepoKey(encKey, h.identity)
	if err != nil {
		return fmt.Errorf("decrypting repo key: %w", err)
	}
	slog.Debug("repo key decrypted")

	serverRefs, err := h.client.GetRefs(h.owner, h.repo)
	if err != nil {
		return fmt.Errorf("getting server refs: %w", err)
	}
	slog.Debug("server refs fetched", slog.Int("count", len(serverRefs)))

	for _, line := range batch {
		// "push refs/heads/main:refs/heads/main" or "+refs/heads/main:refs/heads/main" (force)
		spec := strings.TrimPrefix(line, "push ")
		colon := strings.Index(spec, ":")
		if colon < 0 {
			fmt.Fprintf(w, "error %s malformed push spec\n", spec)
			continue
		}
		src := spec[:colon]
		dst := spec[colon+1:]

		// Strip force-push marker; we always overwrite the remote ref tip.
		src = strings.TrimPrefix(src, "+")

		// Branch deletion (empty src) is not supported in V1.
		if src == "" {
			fmt.Fprintf(w, "error %s branch deletion not supported\n", dst)
			continue
		}

		if err := h.doPush(w, src, dst, repoKey, serverRefs, gitDir); err != nil {
			fmt.Fprintf(w, "error %s %v\n", dst, err)
		}
	}

	fmt.Fprintln(w) // blank line ends push response
	return nil
}

func (h *helper) doPush(w io.Writer, src, dst string, repoKey []byte, serverRefs []types.Ref, gitDir string) error {
	gitEnv := append(os.Environ(), "GIT_DIR="+gitDir)

	// Resolve the local ref to a commit SHA.
	revParseCmd := exec.Command("git", "rev-parse", src)
	revParseCmd.Env = gitEnv
	shaOut, err := revParseCmd.Output()
	if err != nil {
		return fmt.Errorf("resolving %q: %w", src, err)
	}
	newSHA := strings.TrimSpace(string(shaOut))
	slog.Debug("resolved local ref",
		slog.String("src", src),
		slog.String("sha", newSHA),
	)

	// Build pack-objects input: include new SHA, exclude everything the server knows.
	var revInput bytes.Buffer
	revInput.WriteString(newSHA + "\n")
	for _, ref := range serverRefs {
		revInput.WriteString("^" + ref.CommitSHA + "\n")
	}

	packCmd := exec.Command("git", "pack-objects",
		"--stdout",
		"--delta-base-offset",
		"--revs",
	)
	packCmd.Stdin = &revInput
	packCmd.Env = gitEnv
	packCmd.Stderr = os.Stderr
	packOut, err := packCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pack-objects stdout: %w", err)
	}
	if err := packCmd.Start(); err != nil {
		return fmt.Errorf("starting pack-objects: %w", err)
	}

	// Stage the encrypted pack in a temp file while hashing it, so we can set
	// Content-Length and sign the body without holding the whole pack in RAM.
	// pack-objects streams its output straight through the encrypting writer.
	tmp, err := os.CreateTemp("", "gf-push-*.pack.enc")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	hasher := sha256.New()
	if err := crypto.EncryptPackfile(io.MultiWriter(tmp, hasher), packOut, repoKey); err != nil {
		tmp.Close()
		_ = packCmd.Wait()
		return fmt.Errorf("encrypting packfile: %w", err)
	}
	if err := packCmd.Wait(); err != nil {
		tmp.Close()
		return fmt.Errorf("pack-objects: %w", err)
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		return err
	}
	bodyHash := hex.EncodeToString(hasher.Sum(nil))
	slog.Debug("packfile encrypted", slog.Int64("encrypted_bytes", size))

	// The branch this push targets, recorded with the packfile so the server
	// can report per-branch packfile counts, and reused for the ref update.
	branch := strings.TrimPrefix(dst, "refs/heads/")

	// Upload by streaming the temp file. UploadPackfile reads it to EOF; we
	// keep the handle open until the call returns, then defer removes it.
	seq, err := h.client.UploadPackfile(h.owner, h.repo, branch, tmp, size, bodyHash)
	tmp.Close()
	if err != nil {
		return fmt.Errorf("uploading packfile: %w", err)
	}
	slog.Debug("packfile uploaded", slog.Int64("seq", seq))

	// Update the remote ref tip.
	if err := h.client.UpdateRef(h.owner, h.repo, branch, newSHA); err != nil {
		return fmt.Errorf("updating ref: %w", err)
	}
	slog.Debug("remote ref updated",
		slog.String("branch", branch),
		slog.String("sha", newSHA),
	)

	fmt.Fprintf(w, "ok %s\n", dst)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parseURL parses a gf://owner/repo URL into its components.
func parseURL(rawURL string) (owner, repo string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "gf" {
		return "", "", fmt.Errorf("expected gf:// scheme, got %q", u.Scheme)
	}
	owner = u.Host
	repo = strings.TrimPrefix(u.Path, "/")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("URL must be gf://<owner>/<repo>")
	}
	return owner, repo, nil
}

// findGitDir returns the absolute path of the .git directory for the current
// repository by running `git rev-parse --git-dir`.
func findGitDir() (string, error) {
	// git sets GIT_DIR in the environment when it spawns the helper.
	if dir := os.Getenv("GIT_DIR"); dir != "" {
		return dir, nil
	}
	out, err := exec.Command("git", "rev-parse", "--git-dir").Output()
	if err != nil {
		return "", fmt.Errorf("finding git dir: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
