package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/crypto"
)

// ErrSilent signals that a command has already printed its own user-facing
// failure output and the process should exit non-zero WITHOUT main.go adding
// an "Error: …" line on top. Used by `gf verify` so a failed decryption shows
// the clean on-camera output and nothing else.
var ErrSilent = errors.New("")

// verifyInput, when set via --input, makes `gf verify` decrypt a local file
// instead of fetching the latest packfile from the server. Used in the demo's
// failing case (decrypting the already-decrypted ./decrypted.pack a second
// time, which fails the Poly1305 authentication check).
var verifyInput string

// decryptedPackName is the fixed on-disk artifact `gf verify` writes on
// success — a real, git-readable packfile recovered entirely client-side.
const decryptedPackName = "decrypted.pack"

var verifyCmd = &cobra.Command{
	Use:   "verify <owner>/<vault>",
	Short: "Prove server-stored data was encrypted client-side",
	Long: `Fetch the latest encrypted packfile for a vault and prove, end to end, that
the bytes the server holds are ciphertext only you can open:

  1. download the packfile and show its SHA-256 matches the server's record
  2. decrypt it locally with XChaCha20-Poly1305 and verify the Poly1305
     authentication tag
  3. pipe the plaintext into 'git unpack-objects' so git itself confirms the
     recovered objects are valid, and list the file names inside
  4. write the decrypted packfile to ./decrypted.pack

The repo key is unwrapped on your machine from your Ed25519 identity; the
server never sees it. If the ciphertext was tampered with, served the wrong
bytes, or you lack the key, the Poly1305 tag fails and verification aborts.

Use --input <file> to decrypt a local file instead of fetching from the
server (e.g. to show that the already-decrypted ./decrypted.pack is not valid
ciphertext and fails the authentication check).`,
	Example: `  # Fetch, decrypt, and prove the latest push is recoverable
  gf verify ghostfork-io/myproject

  # Show that decrypting an already-decrypted file fails authentication
  gf verify --input ./decrypted.pack ghostfork-io/myproject`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyInput, "input", "",
		"decrypt a local file instead of fetching the latest packfile from the server")
}

func runVerify(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	sess, err := loadSession()
	if err != nil {
		return err
	}
	owner, repo, err := parseRepoArg(args[0], sess.cfg.Username)
	if err != nil {
		return err
	}

	// Temp files are removed on the way out regardless of how we exit (real
	// error, silent demo failure, or success).
	var temps []string
	defer func() {
		for _, p := range temps {
			_ = os.Remove(p)
		}
	}()

	fmt.Fprintln(out)

	// ── Step 1: obtain the ciphertext ───────────────────────────────────────
	// Either a local --input file (fetch skipped) or the latest packfile
	// downloaded from the server, whose SHA-256 we confirm against the server.
	var cipherPath string
	if verifyInput != "" {
		vline(out, "fetching packfile...", "(skipped — using local input)", "")
		cipherPath = verifyInput
	} else {
		seqs, err := sess.client.ListPackfiles(owner, repo, 0)
		if err != nil {
			return fmt.Errorf("listing packfiles for %s/%s: %w", owner, repo, err)
		}
		if len(seqs) == 0 {
			return fmt.Errorf("vault %s/%s has no packfiles to verify — push something first", owner, repo)
		}
		latest := seqs[len(seqs)-1]

		clientHash, path, err := downloadCipher(sess, owner, repo, latest)
		if err != nil {
			return err
		}
		temps = append(temps, path)
		cipherPath = path
		vline(out, "fetching packfile...", "✓", "")

		serverHash, _, err := sess.client.PackfileSHA256(owner, repo, latest)
		if err != nil {
			return fmt.Errorf("fetching server hash: %w", err)
		}
		if clientHash != serverHash {
			vline(out, "ciphertext SHA256: "+shortHash(clientHash), "✗", "does NOT match server")
			return fmt.Errorf("ciphertext SHA256 mismatch: downloaded %s, server recorded %s", clientHash, serverHash)
		}
		vline(out, "ciphertext SHA256: "+shortHash(clientHash), "✓", "matches server")
	}

	// ── Step 2: unwrap the repo key and decrypt ─────────────────────────────
	repoKey, err := unwrapRepoKey(sess, owner, repo)
	if err != nil {
		return err
	}

	cipherFile, err := os.Open(cipherPath)
	if err != nil {
		return fmt.Errorf("opening ciphertext: %w", err)
	}
	defer cipherFile.Close() //nolint:errcheck

	plainTmp, err := os.CreateTemp("", "gf-verify-plain-*.pack")
	if err != nil {
		return err
	}
	plainPath := plainTmp.Name()
	temps = append(temps, plainPath)

	decErr := crypto.DecryptPackfile(plainTmp, cipherFile, repoKey)
	_ = plainTmp.Close()
	if decErr != nil {
		// Any decrypt failure here means the input is not authentic ciphertext
		// for this key — a tampered blob, the wrong key, or (the demo case)
		// plaintext fed back in. The AEAD's Poly1305 tag is what rejects it.
		vline(out, "decrypting  [XChaCha20-Poly1305]", "✗", "authentication tag mismatch")
		vsub(out, "decryption aborted")
		slog.Debug("verify: decryption failed", slog.Any("err", decErr))
		return ErrSilent
	}
	vline(out, "decrypting  [XChaCha20-Poly1305]", "✓", "authentication tag verified")

	// ── Step 3: let git itself validate the recovered objects ───────────────
	names, err := unpackAndList(plainPath)
	if err != nil {
		vline(out, "piping to git unpack-objects...", "✗", "git rejected the objects")
		slog.Debug("verify: git unpack-objects failed", slog.Any("err", err))
		return ErrSilent
	}
	vline(out, "piping to git unpack-objects...", "✓", "git accepted the objects")
	for _, n := range names {
		vsub(out, n)
	}

	// ── Step 4: write the recovered packfile to disk ────────────────────────
	if err := copyFile(plainPath, decryptedPackName); err != nil {
		return fmt.Errorf("writing %s: %w", decryptedPackName, err)
	}
	fmt.Fprintf(out, "  decrypted pack saved to ./%s\n", decryptedPackName)
	return nil
}

// downloadCipher streams the encrypted packfile to a temp file while hashing it,
// returning the hex SHA-256 of what was received and the temp file path.
func downloadCipher(sess *session, owner, repo string, seq int64) (sha256hex, path string, err error) {
	rc, err := sess.client.DownloadPackfile(owner, repo, seq)
	if err != nil {
		return "", "", fmt.Errorf("downloading packfile: %w", err)
	}
	defer rc.Close() //nolint:errcheck

	tmp, err := os.CreateTemp("", "gf-verify-cipher-*.bin")
	if err != nil {
		return "", "", err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(tmp, hasher), rc)
	closeErr := tmp.Close()
	if copyErr != nil {
		_ = os.Remove(tmp.Name())
		return "", "", fmt.Errorf("reading packfile: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp.Name())
		return "", "", closeErr
	}
	return hex.EncodeToString(hasher.Sum(nil)), tmp.Name(), nil
}

// unwrapRepoKey fetches the caller's encrypted repo key from the server and
// decrypts it with the local Ed25519 identity. The plaintext key never leaves
// this process.
func unwrapRepoKey(sess *session, owner, repo string) ([]byte, error) {
	encKey, err := sess.client.GetKey(owner, repo, sess.cfg.Username)
	if err != nil {
		return nil, fmt.Errorf("fetching your repo key for %s/%s: %w", owner, repo, err)
	}
	if len(encKey) == 0 {
		return nil, fmt.Errorf("you have no key for %s/%s — ask the owner to grant access", owner, repo)
	}
	repoKey, err := crypto.DecryptRepoKey(encKey, sess.identity)
	if err != nil {
		return nil, fmt.Errorf("unwrapping repo key (is this your vault?): %w", err)
	}
	return repoKey, nil
}

// unpackAndList feeds a decrypted packfile to `git unpack-objects` inside a
// throwaway bare repo, then returns the sorted file names contained in the
// pack's tip commit(s). A nil error means git accepted every object.
func unpackAndList(packPath string) ([]string, error) {
	gitDir, err := os.MkdirTemp("", "gf-verify-git-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(gitDir) //nolint:errcheck

	if _, err := runGit(gitDir, nil, "init", "--bare", "--quiet"); err != nil {
		return nil, fmt.Errorf("git init: %w", err)
	}

	pack, err := os.Open(packPath)
	if err != nil {
		return nil, err
	}
	defer pack.Close() //nolint:errcheck
	if _, err := runGit(gitDir, pack, "unpack-objects", "-q"); err != nil {
		return nil, err
	}

	return listPackFileNames(gitDir)
}

// listPackFileNames returns the file paths in the tip commit(s) of whatever was
// just unpacked into gitDir. "Tip" = a commit that is not the parent of any
// other unpacked commit, so we show the latest tree rather than every revision.
func listPackFileNames(gitDir string) ([]string, error) {
	check, err := runGit(gitDir, nil, "cat-file", "--batch-all-objects", "--batch-check=%(objecttype) %(objectname)")
	if err != nil {
		return nil, err
	}
	var commits []string
	for _, line := range strings.Split(strings.TrimSpace(check), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "commit" {
			commits = append(commits, f[1])
		}
	}
	if len(commits) == 0 {
		return nil, nil
	}

	isParent := map[string]bool{}
	for _, c := range commits {
		body, err := runGit(gitDir, nil, "cat-file", "commit", c)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(body, "\n") {
			if line == "" {
				break // commit header ends at the first blank line
			}
			if p, ok := strings.CutPrefix(line, "parent "); ok {
				isParent[strings.TrimSpace(p)] = true
			}
		}
	}

	tips := commits[:0:0]
	for _, c := range commits {
		if !isParent[c] {
			tips = append(tips, c)
		}
	}
	if len(tips) == 0 {
		tips = commits
	}

	seen := map[string]bool{}
	for _, t := range tips {
		out, err := runGit(gitDir, nil, "ls-tree", "-r", "--name-only", t)
		if err != nil {
			return nil, err
		}
		for _, n := range strings.Split(strings.TrimSpace(out), "\n") {
			if n != "" {
				seen[n] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// runGit runs a git command against gitDir, optionally feeding stdin, and
// returns stdout. On failure the error carries git's stderr.
func runGit(gitDir string, stdin io.Reader, args ...string) (string, error) {
	c := exec.Command("git", append([]string{"--git-dir=" + gitDir}, args...)...)
	c.Stdin = stdin
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return stdout.String(), nil
}

// copyFile copies src to dst (0644), truncating dst if it exists.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// shortHash abbreviates a hex digest for on-screen display, e.g.
// "9f4a2c...e7b1". Full hashes still go to the log file.
func shortHash(h string) string {
	if len(h) <= 13 {
		return h
	}
	return h[:6] + "..." + h[len(h)-4:]
}

// vLabelWidth is the column the status marks (✓/✗) align to, so every step
// reads as a tidy table on camera.
const vLabelWidth = 40

// vline prints one verification step: a left-aligned label, a status mark, and
// an optional trailing note. When note is empty, mark is printed alone (used
// for the "(skipped …)" line, where mark carries the whole message).
func vline(w io.Writer, label, mark, note string) {
	if note == "" {
		fmt.Fprintf(w, "  %-*s%s\n", vLabelWidth, label, mark)
		return
	}
	fmt.Fprintf(w, "  %-*s%s  %s\n", vLabelWidth, label, mark, note)
}

// vsub prints a continuation line indented under a step's note column (e.g. a
// recovered file name, or "decryption aborted").
func vsub(w io.Writer, text string) {
	fmt.Fprintf(w, "  %*s%s\n", vLabelWidth+3, "", text)
}
