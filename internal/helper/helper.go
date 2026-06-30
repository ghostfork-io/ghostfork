// Package helper implements the git-remote-gf remote helper protocol.
//
// Git spawns this process for any remote with a gf:// URL, communicating
// over stdin/stdout using the standard git remote helper line protocol.
package helper

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
	"github.com/ghostfork/gf/internal/logging"
	"github.com/ghostfork/gf/internal/state"
	"github.com/ghostfork/gf/protocol/types"
)

// packfilePreviewLimit is how many leading bytes of the encrypted packfile
// the debug preview logs. Matches the admin panel's Inspect window so the
// two renderings can be compared byte for byte during a demo.
const packfilePreviewLimit = 10 * 1024

// Run is the entry point called from cmd/gf/main.go when the binary is
// invoked as git-remote-gf. Git passes: git-remote-gf <remote-name> <url>
func Run() {
	// git invokes us directly, so we have no -v flag to honour — stderr
	// verbosity is controlled by GHOSTFORK_LOG_LEVEL (see internal/logging).
	// The log file captures every step at DEBUG regardless.
	logging.SetDefault(logging.NewCLI(false, config.DefaultLogPath()))

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
		owner:     owner,
		repo:      repo,
		cfg:       cfg,
		identity:  id,
		client:    apiclient.NewAuthenticated(cfg.ServerURL, cfg.Username, id.Signer()),
		progress:  true, // git turns this off via `option progress false` (--quiet / non-tty)
		verbosity: 1,
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

	// Display options git negotiates over the helper protocol before fetch/push.
	// When progress is on (a normal interactive clone/pull), we narrate the
	// encrypted transfer on stderr like a git server's `remote:` sideband;
	// --quiet or a non-terminal turns it off. Defaults match git's own: progress
	// on, verbosity 1.
	progress  bool
	verbosity int
}

// run drives the line-protocol loop with git over r/w.
func (h *helper) run(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case line == "capabilities":
			// `option` lets git negotiate progress/verbosity with us before fetch.
			fmt.Fprintf(w, "option\nfetch\npush\n\n")

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
			h.handleOption(w, strings.TrimPrefix(line, "option "))

		case line == "":
			// trailing blank line — ignore

		default:
			return fmt.Errorf("unknown command: %q", line)
		}
	}
	return scanner.Err()
}

// handleOption records the display options git negotiates before a transfer.
// We honour `progress` and `verbosity` (they gate our remote: narration) and
// report every other option as unsupported so git keeps its default behaviour.
func (h *helper) handleOption(w io.Writer, arg string) {
	name, value, _ := strings.Cut(arg, " ")
	switch name {
	case "progress":
		h.progress = value == "true"
		fmt.Fprintln(w, "ok")
	case "verbosity":
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			h.verbosity = n
		}
		fmt.Fprintln(w, "ok")
	default:
		fmt.Fprintln(w, "unsupported")
	}
}

// showProgress reports whether to print user-facing transfer narration, matching
// git: on for an interactive clone/pull, off under --quiet or a non-terminal.
func (h *helper) showProgress() bool { return h.progress && h.verbosity >= 1 }

// remotef prints a human-facing progress line to stderr, prefixed `remote:` the
// way a git server's sideband messages appear — so a `git clone`/`git pull` over
// a gf:// remote shows the encrypted transfer happening instead of sitting
// silent. stdout is the helper protocol channel, so this must go to stderr.
func (h *helper) remotef(format string, args ...any) {
	if !h.showProgress() {
		return
	}
	fmt.Fprintf(os.Stderr, "remote: "+format+"\n", args...)
}

// ── list ──────────────────────────────────────────────────────────────────────

func (h *helper) handleList(w io.Writer) error {
	slog.Debug("list refs", slog.String("owner", h.owner), slog.String("repo", h.repo))
	refs, err := h.client.GetRefs(h.owner, h.repo)
	if err != nil {
		return fmt.Errorf("listing refs: %w", err)
	}
	slog.Debug("refs fetched", slog.Int("count", len(refs)))

	// ref.Branch is the full ref name (refs/heads/<branch>, refs/tags/<tag>),
	// so advertise it verbatim — anything else would misclassify tags as
	// branches (or vice versa) on the receiving git.
	for _, ref := range refs {
		fmt.Fprintf(w, "%s %s\n", ref.CommitSHA, ref.Branch)
	}

	// Advertise HEAD → main when main exists so `git clone` checks out correctly.
	for _, ref := range refs {
		if ref.Branch == "refs/heads/main" {
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
	slog.Info("unwrapped repo key [age: X25519 + ChaCha20-Poly1305] ✓ — server cannot read it")

	seqs, err := h.client.ListPackfiles(h.owner, h.repo, st.LastSeq)
	if err != nil {
		return fmt.Errorf("listing packfiles: %w", err)
	}
	slog.Debug("packfiles to fetch", slog.Int("count", len(seqs)))

	if len(seqs) == 0 {
		h.remotef("already up to date — no new packfiles")
	} else {
		h.remotef("%d encrypted packfile(s) to fetch", len(seqs))
	}

	for i, seq := range seqs {
		h.remotef("receiving packfile %d/%d...", i+1, len(seqs))
		body, err := h.client.DownloadPackfile(h.owner, h.repo, seq)
		if err != nil {
			return fmt.Errorf("downloading packfile seq=%d: %w", seq, err)
		}
		slog.Info(fmt.Sprintf("decrypting [XChaCha20-Poly1305] packfile seq=%d", seq))

		plainN, cipherN, err := unpackEncrypted(body, repoKey, gitDir)
		if err != nil {
			body.Close()
			return fmt.Errorf("unpacking packfile seq=%d: %w", seq, err)
		}
		body.Close()
		// DecryptPackfile verified every chunk's Poly1305 tag on the way through;
		// reaching here means the ciphertext was authentic and untampered.
		slog.Info(fmt.Sprintf(
			"decrypted [XChaCha20-Poly1305] seq=%d ✓ authentication tag verified — %s ciphertext → %s plaintext in %d chunk(s)",
			seq, humanBytes(cipherN), humanBytes(plainN), chunkCount(plainN)))
		h.remotef("packfile %d/%d decrypted [XChaCha20-Poly1305] ✓ tag verified, %s → %s, unpacked",
			i+1, len(seqs), humanBytes(cipherN), humanBytes(plainN))

		st.LastSeq = seq
	}

	if len(seqs) > 0 {
		h.remotef("done — %d packfile(s) received and authenticated", len(seqs))
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
func unpackEncrypted(src io.Reader, repoKey []byte, gitDir string) (plaintextBytes, ciphertextBytes int64, err error) {
	cipher := &countingReader{r: src} // counts ciphertext bytes read off the wire
	pr, pw := io.Pipe()
	plain := &countingWriter{w: pw} // counts plaintext bytes produced

	cmd := exec.Command("git", "index-pack", "--stdin")
	cmd.Stdin = pr
	cmd.Env = append(os.Environ(), "GIT_DIR="+gitDir)
	cmd.Stderr = os.Stderr
	cmd.Stdout = io.Discard // index-pack prints the pack SHA we don't need

	if err := cmd.Start(); err != nil {
		pr.Close()
		return 0, 0, fmt.Errorf("starting index-pack: %w", err)
	}

	// Decrypt into the pipe. DecryptPackfile verifies each chunk's Poly1305
	// authentication tag as it goes; a bad tag (tampered/truncated ciphertext or
	// wrong key) surfaces here and is propagated to index-pack by closing the
	// write end with that error, so cmd.Wait observes a broken stdin and fails
	// rather than indexing a forged pack.
	decErr := make(chan error, 1)
	go func() {
		e := crypto.DecryptPackfile(plain, cipher, repoKey)
		pw.CloseWithError(e)
		decErr <- e
	}()

	waitErr := cmd.Wait()
	if e := <-decErr; e != nil {
		return 0, 0, fmt.Errorf("decrypting: %w", e)
	}
	if waitErr != nil {
		return 0, 0, fmt.Errorf("index-pack: %w", waitErr)
	}
	return plain.n, cipher.n, nil
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
	slog.Info("unwrapped repo key [age: X25519 + ChaCha20-Poly1305] ✓ — server cannot read it")

	serverRefs, err := h.client.GetRefs(h.owner, h.repo)
	if err != nil {
		return fmt.Errorf("getting server refs: %w", err)
	}
	// Narrate what the server's refs mean for this push: nothing known yet →
	// the whole history goes up; otherwise pack-objects excludes what the
	// server already has (see doPush's revInput).
	if len(serverRefs) == 0 {
		slog.Debug("refs fetched from server — remote is empty, full push")
	} else {
		slog.Debug(fmt.Sprintf(
			"refs fetched from server — %d existing ref(s), incremental push", len(serverRefs)))
	}

	failed := 0
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
			// Never fail silently: git relays the protocol error to the user,
			// but the log must record it too (helper.Run only sees fatal errors,
			// not per-ref failures).
			slog.Error("push failed", slog.String("ref", dst), slog.Any("err", err))
			fmt.Fprintf(w, "error %s %v\n", dst, err)
			failed++
		}
	}
	if failed == 0 {
		slog.Info("push complete")
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
	slog.Debug("git pack-objects: building packfile locally")
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

	// plain counts the plaintext pack bytes flowing into the encryptor, so the
	// narration below can report both sizes. Building and encrypting overlap
	// (one stream), which is why this line precedes the size lines.
	plain := &countingReader{r: packOut}
	hasher := sha256.New()
	slog.Info("encrypting [XChaCha20-Poly1305] — 256-bit repo key, 192-bit random nonce, 64 KiB chunks, per-chunk Poly1305 auth tag")
	if err := crypto.EncryptPackfile(io.MultiWriter(tmp, hasher), plain, repoKey); err != nil {
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
	slog.Info(fmt.Sprintf(
		"encrypted [XChaCha20-Poly1305] ✓ %s plaintext → %s ciphertext in %d chunk(s) (+24-byte nonce, per-chunk Poly1305 tag)",
		humanBytes(plain.n), humanBytes(size), chunkCount(plain.n)),
		slog.Int64("plaintext_bytes", plain.n), slog.Int64("encrypted_bytes", size))

	// Demo aid (docs/sales-demo.md Act 4): log the ciphertext hash and a
	// preview AFTER encryption and BEFORE any byte goes over the wire, so an
	// observer can match them live against the admin panel's Inspect view.
	// Everything here is ciphertext — safe to log. The hash line is small and
	// always lands in the audit log; the ~13 KB base64 preview is emitted only
	// under explicit debug (GHOSTFORK_LOG_LEVEL=debug) to keep gf.log lean.
	slog.Info("encrypted packfile SHA-256: " + bodyHash + " (matches the server's stored blob — nothing is re-encrypted in transit)")
	if logging.DebugRequested(false) {
		preview := make([]byte, packfilePreviewLimit)
		n, err := io.ReadFull(tmp, preview)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			tmp.Close()
			return fmt.Errorf("reading packfile preview: %w", err)
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			return err
		}
		// Hex dump in the exact xxd format the admin panel renders (toXxd) so a
		// demo viewer can compare client and server byte for byte. slog's text
		// handler would escape the newlines into one unreadable, "\n"-littered
		// line, so write the multi-line block straight to stderr — where the
		// user watches a debug push — framed by blank lines for readability.
		// A copy still lands in the gf.log audit trail via slog, marked FileOnly
		// so it does not also print the escaped version to stderr.
		dump := toXxd(preview[:n])
		fmt.Fprintf(os.Stderr, "\nencrypted packfile hex dump (first 10 KB):\n%s\n\n", dump)
		slog.Debug("encrypted packfile hex dump (first 10 KB):\n"+dump, logging.FileOnly())
		slog.Debug("encrypted packfile preview (first 10 KB, base64): " +
			base64.StdEncoding.EncodeToString(preview[:n]))
	}

	// The full ref name this push targets (refs/heads/<branch> or
	// refs/tags/<tag>). Stored verbatim so tags — and branch names containing
	// slashes — survive a round-trip; it also labels the packfile for the
	// server's per-ref counts.
	refName := dst

	// Upload by streaming the temp file. UploadPackfile reads it to EOF; we
	// keep the handle open until the call returns, then defer removes it.
	seq, err := h.client.UploadPackfile(h.owner, h.repo, refName, tmp, size, bodyHash)
	tmp.Close()
	if err != nil {
		return fmt.Errorf("uploading packfile: %w", err)
	}
	slog.Debug("upload complete — server assigned seq", slog.Int64("seq", seq))

	// Update the remote ref tip.
	if err := h.client.UpdateRef(h.owner, h.repo, refName, newSHA); err != nil {
		return fmt.Errorf("updating ref: %w", err)
	}
	slog.Debug("ref updated",
		slog.String("ref", refName),
		slog.String("sha", newSHA),
	)

	fmt.Fprintf(w, "ok %s\n", dst)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// countingReader counts the bytes read through it. Used to report the
// plaintext packfile size while it streams into the encryptor.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// countingWriter counts the bytes written through it. Used on fetch to report
// how many plaintext bytes came out of decryption.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// chunkCount reports how many 64 KiB plaintext chunks a packfile of the given
// plaintext size was encrypted in — purely for the crypto narration.
func chunkCount(plaintextBytes int64) int64 {
	if plaintextBytes <= 0 {
		return 0
	}
	return (plaintextBytes + crypto.ChunkSize - 1) / crypto.ChunkSize
}

// humanBytes renders n like "4.1 KB" for the demo narration lines. Sizes
// beyond TB don't occur in packfile pushes, so the unit list stops there.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// toXxd renders b as an xxd-style hex dump. It is a deliberate, byte-for-byte
// port of the admin panel's toXxd (web/admin/src/components/PackfileInspectModal.tsx)
// so the client log and the server's Inspect view can be diffed line by line:
//
//	00000000  9f 3a 2b c4 7d 81 e0 59  a4 f2 13 86 cd 90 5e 72  |.:+.}..Y......^r|
func toXxd(b []byte) string {
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[off:end]
		cols := make([]string, 16)
		var ascii strings.Builder
		for i := 0; i < 16; i++ {
			if i < len(chunk) {
				c := chunk[i]
				cols[i] = fmt.Sprintf("%02x", c)
				if c >= 0x20 && c <= 0x7e {
					ascii.WriteByte(c)
				} else {
					ascii.WriteByte('.')
				}
			} else {
				cols[i] = "  "
			}
		}
		if off > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "%08x  %s  %s  |%s|",
			off, strings.Join(cols[:8], " "), strings.Join(cols[8:], " "), ascii.String())
	}
	return sb.String()
}

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
