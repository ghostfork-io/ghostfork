// Package helper implements the git-remote-gf remote helper protocol.
//
// Git spawns this process for any remote with a gf:// URL, communicating
// over stdin/stdout using the standard git remote helper line protocol.
package helper

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/crypto"
	"github.com/ghostfork/gf/internal/state"
	"github.com/ghostfork/gf/shared/types"
)

// Run is the entry point called from cmd/gf/main.go when the binary is
// invoked as git-remote-gf. Git passes: git-remote-gf <remote-name> <url>
func Run() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: git-remote-gf <remote-name> <url>")
		os.Exit(1)
	}

	remoteURL := os.Args[2]
	org, repo, err := parseURL(remoteURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-gf: invalid URL %q: %v\n", remoteURL, err)
		os.Exit(1)
	}

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-gf: not logged in — run 'gf login' first\n")
		os.Exit(1)
	}

	h := &helper{
		org:    org,
		repo:   repo,
		cfg:    cfg,
		client: apiclient.New(cfg.ServerURL, cfg.APIKey),
	}

	if err := h.run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-gf: %v\n", err)
		os.Exit(1)
	}
}

type helper struct {
	org    string
	repo   string
	cfg    *config.Config
	client *apiclient.Client
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
	refs, err := h.client.GetRefs(h.org, h.repo)
	if err != nil {
		return fmt.Errorf("listing refs: %w", err)
	}

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

	id, err := crypto.LoadIdentity(config.DefaultIdentityPath())
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	encKey, err := h.client.GetKey(h.org, h.repo, h.cfg.Username)
	if err != nil {
		return fmt.Errorf("fetching repo key: %w", err)
	}

	repoKey, err := crypto.DecryptRepoKey(encKey, id)
	if err != nil {
		return fmt.Errorf("decrypting repo key: %w", err)
	}

	seqs, err := h.client.ListPackfiles(h.org, h.repo, st.LastSeq)
	if err != nil {
		return fmt.Errorf("listing packfiles: %w", err)
	}

	for _, seq := range seqs {
		data, err := h.client.DownloadPackfile(h.org, h.repo, seq)
		if err != nil {
			return fmt.Errorf("downloading packfile seq=%d: %w", seq, err)
		}

		if err := unpackEncrypted(data, repoKey, gitDir); err != nil {
			return fmt.Errorf("unpacking packfile seq=%d: %w", seq, err)
		}

		st.LastSeq = seq
	}

	// Persist state only after every packfile has been successfully unpacked.
	st.Repo = h.org + "/" + h.repo
	st.ServerURL = h.cfg.ServerURL
	if err := state.Save(gitDir, st); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	fmt.Fprintln(w) // blank line = fetch complete
	return nil
}

// unpackEncrypted decrypts data into a temp pack file and runs
// git unpack-objects to import the objects into the local object store.
func unpackEncrypted(data, repoKey []byte, gitDir string) error {
	tmp, err := os.CreateTemp("", "gf-pack-*.pack")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := crypto.DecryptPackfile(tmp, bytes.NewReader(data), repoKey); err != nil {
		tmp.Close()
		return fmt.Errorf("decrypting: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	f, err := os.Open(tmpName)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.Command("git", "unpack-objects")
	cmd.Stdin = f
	cmd.Env = append(os.Environ(), "GIT_DIR="+gitDir)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ── push ──────────────────────────────────────────────────────────────────────

func (h *helper) handlePush(w io.Writer, batch []string) error {
	gitDir, err := findGitDir()
	if err != nil {
		return err
	}

	id, err := crypto.LoadIdentity(config.DefaultIdentityPath())
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	encKey, err := h.client.GetKey(h.org, h.repo, h.cfg.Username)
	if err != nil {
		return fmt.Errorf("fetching repo key: %w", err)
	}

	repoKey, err := crypto.DecryptRepoKey(encKey, id)
	if err != nil {
		return fmt.Errorf("decrypting repo key: %w", err)
	}

	serverRefs, err := h.client.GetRefs(h.org, h.repo)
	if err != nil {
		return fmt.Errorf("getting server refs: %w", err)
	}

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
	packData, err := packCmd.Output()
	if err != nil {
		return fmt.Errorf("pack-objects: %w", err)
	}

	// Encrypt.
	var encrypted bytes.Buffer
	if err := crypto.EncryptPackfile(&encrypted, bytes.NewReader(packData), repoKey); err != nil {
		return fmt.Errorf("encrypting packfile: %w", err)
	}

	// Upload.
	if _, err := h.client.UploadPackfile(h.org, h.repo, encrypted.Bytes()); err != nil {
		return fmt.Errorf("uploading packfile: %w", err)
	}

	// Update the remote ref tip.
	branch := strings.TrimPrefix(dst, "refs/heads/")
	if err := h.client.UpdateRef(h.org, h.repo, branch, newSHA); err != nil {
		return fmt.Errorf("updating ref: %w", err)
	}

	fmt.Fprintf(w, "ok %s\n", dst)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parseURL parses a gf://org/repo URL into its components.
func parseURL(rawURL string) (org, repo string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "gf" {
		return "", "", fmt.Errorf("expected gf:// scheme, got %q", u.Scheme)
	}
	org = u.Host
	repo = strings.TrimPrefix(u.Path, "/")
	if org == "" || repo == "" {
		return "", "", fmt.Errorf("URL must be gf://<org>/<repo>")
	}
	return org, repo, nil
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
