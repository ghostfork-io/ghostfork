package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/logging"
	"github.com/ghostfork/gf/protocol/auth"
)

// rotatePreviewLimit is how many ciphertext bytes of the re-encrypted packfile
// are previewed (base64) under -v, mirroring the push demo logging.
const rotatePreviewLimit = 10 * 1024

var rotateKeyCmd = &cobra.Command{
	Use:   "rotate-key <vault>",
	Short: "Rotate a vault's encryption key and re-encrypt its history",
	Long: `Generate a fresh vault key, re-encrypt the vault's entire history under it,
and re-wrap the new key for every current member.

This closes the gap left by remove-user: a removed user who recorded the
old vault key can still decrypt blobs encrypted with it. After rotation the
server stores only ciphertext under the new key, so the old key is useless.

To actually revoke someone, remove them first, then rotate:

    gf remove-user my-vault bob     # drops bob's access
    gf rotate-key my-vault          # re-keys so bob's old key opens nothing

What happens locally (the server never sees a plaintext key):
  1. Your client clones the vault (decrypting it with the current key).
  2. A new vault key is generated and all objects are repacked and encrypted
     with it into one consolidated packfile.
  3. The new packfile is uploaded and the new key is wrapped for each
     remaining member; the server swaps everything over atomically.

Existing clones pick up the re-encrypted history on their next pull
automatically.

<repo> can be 'repo-name' (your own) or 'owner/repo-name'.`,
	Example: `  gf rotate-key my-project
  gf rotate-key alice/my-project`,
	Args: cobra.ExactArgs(1),
	RunE: runRotateKey,
}

func runRotateKey(cmd *cobra.Command, args []string) error {
	sess, err := loadSession()
	if err != nil {
		return err
	}
	owner, repo, err := parseRepoArg(args[0], sess.cfg.Username)
	if err != nil {
		return err
	}
	slog.Debug("rotate-key start", slog.String("owner", owner), slog.String("repo", repo))

	// Current generation — also confirms we have access (403 otherwise). The
	// commit must present this so a concurrent rotation is detected.
	_, generation, err := sess.client.ListPackfiles(owner, repo, 0)
	if err != nil {
		return fmt.Errorf("reading repo state (are you a member of %s/%s?): %w", owner, repo, err)
	}

	// Whom to re-wrap the new key for: every current key holder. (Drop a user
	// with remove-user *before* rotating; they won't appear here.)
	members, err := sess.client.ListKeyHolders(owner, repo)
	if err != nil {
		return fmt.Errorf("listing repo members: %w", err)
	}
	if len(members) == 0 {
		return fmt.Errorf("repo %s/%s has no members to re-key", owner, repo)
	}
	pubs := make(map[string]ed25519.PublicKey, len(members))
	for _, u := range members {
		ur, err := sess.client.GetUser(u)
		if err != nil {
			return fmt.Errorf("fetching public key for %q: %w", u, err)
		}
		pub, err := auth.DecodePublicKey(ur.PublicKey)
		if err != nil {
			return fmt.Errorf("decoding public key for %q: %w", u, err)
		}
		pubs[u] = pub
	}
	slog.Debug("rotate-key re-keying members",
		slog.Int("count", len(pubs)),
		slog.String("members", strings.Join(members, ", ")),
		slog.Int("current_generation", generation),
	)

	// Obtain the full object set by cloning (the helper decrypts with the
	// current key). A bare clone gives us every object and ref with no checkout.
	tmpDir, err := os.MkdirTemp("", "gf-rotate-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	cloneDir := filepath.Join(tmpDir, "repo.git")

	fmt.Fprintf(cmd.OutOrStdout(), "Cloning %s/%s to re-encrypt…\n", owner, repo)
	clone := exec.Command("git", "clone", "--bare", "--quiet", "gf://"+owner+"/"+repo, cloneDir)
	clone.Env = os.Environ()
	clone.Stderr = cmd.ErrOrStderr()
	if err := clone.Run(); err != nil {
		return fmt.Errorf("cloning repo for rotation: %w", err)
	}

	// Generate the new key and repack everything under it.
	newKey, err := crypto.GenerateRepoKey()
	if err != nil {
		return fmt.Errorf("generating new repo key: %w", err)
	}
	// The plaintext key is logged only under explicit debug (-v /
	// GHOSTFORK_LOG_LEVEL=debug), never by default — mirroring init-repo. It lets
	// a demo show the new key being born locally; it leaves the machine only
	// wrapped per member below.
	slog.Debug("generated new repo sym key (client-side)")
	if logging.DebugRequested(verbose) {
		slog.Debug("new repo sym key (plaintext, hex): " + hex.EncodeToString(newKey))
	}

	encPath, size, bodyHash, err := buildConsolidatedPack(cloneDir, newKey)
	if err != nil {
		return err
	}
	defer os.Remove(encPath)
	slog.Debug("re-encrypted full history into one packfile", slog.Int64("encrypted_bytes", size))
	// SHA-256 of the ciphertext, logged before upload so it can be matched
	// against the server's stored blob (admin Inspect view / sha256sum).
	slog.Debug("re-encrypted packfile SHA-256: " + bodyHash)

	// Stage the new packfile, then commit the atomic swap with the new wrapped
	// keys for every member.
	f, err := os.Open(encPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if logging.DebugRequested(verbose) {
		preview := make([]byte, rotatePreviewLimit)
		n, _ := io.ReadFull(f, preview)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		slog.Debug("re-encrypted packfile preview (first 10 KB, base64): " +
			base64.StdEncoding.EncodeToString(preview[:n]))
	}

	slog.Debug("uploading re-encrypted packfile to server (staging)", slog.Int64("bytes", size))
	if err := sess.client.StageRotationPackfile(owner, repo, generation, f, size, bodyHash); err != nil {
		return fmt.Errorf("staging re-encrypted packfile: %w", err)
	}

	// Re-wrap the new key for each remaining member: encrypt it to their public
	// key, client-side. The base64 blobs are ciphertext (safe to log); the
	// server only ever receives these wrapped copies, never the plaintext key.
	wrapped := make(map[string][]byte, len(pubs))
	for u, pub := range pubs {
		slog.Debug(fmt.Sprintf("encrypting new repo sym key with %s's public key (client-side operation)", u))
		ek, err := crypto.EncryptRepoKey(newKey, pub)
		if err != nil {
			return fmt.Errorf("wrapping new key for %q: %w", u, err)
		}
		slog.Debug(fmt.Sprintf("encrypted new repo sym key for %s (base64): %s",
			u, base64.StdEncoding.EncodeToString(ek)))
		wrapped[u] = ek
	}

	slog.Debug("committing rotation on server (atomic swap: packfiles + wrapped keys + generation)",
		slog.Int("members", len(wrapped)))
	resp, err := sess.client.CommitRotation(owner, repo, generation, wrapped)
	if err != nil {
		return fmt.Errorf("committing rotation: %w", err)
	}
	slog.Debug("rotation committed on server",
		slog.Int("generation", resp.Generation), slog.Int64("seq", resp.Seq))

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "\nRotated %s/%s to key generation %d.\n", owner, repo, resp.Generation)
	fmt.Fprintf(out, "History re-encrypted under a new key and re-wrapped for %d member(s): %s.\n",
		len(wrapped), strings.Join(members, ", "))
	fmt.Fprintf(out, "Anyone removed before this rotation can no longer decrypt the vault.\n\n")
	return nil
}

// buildConsolidatedPack packs every object in the bare repo at gitDir into a
// single packfile, encrypts it with repoKey, and writes the ciphertext to a
// temp file. It returns the temp file path, its byte size, and the lowercase
// hex SHA-256 of the ciphertext (which the server verifies against the signed
// upload). The caller must remove the temp file.
func buildConsolidatedPack(gitDir string, repoKey []byte) (encPath string, size int64, bodyHashHex string, err error) {
	env := append(os.Environ(), "GIT_DIR="+gitDir)

	// rev-list --objects --all | pack-objects --stdout : enumerate every object
	// reachable from any ref and pack them into one stream.
	revList := exec.Command("git", "rev-list", "--objects", "--all")
	revList.Env = env
	revList.Stderr = os.Stderr
	revOut, err := revList.StdoutPipe()
	if err != nil {
		return "", 0, "", fmt.Errorf("rev-list stdout: %w", err)
	}

	pack := exec.Command("git", "pack-objects", "--stdout", "--delta-base-offset")
	pack.Env = env
	pack.Stdin = revOut
	pack.Stderr = os.Stderr
	packOut, err := pack.StdoutPipe()
	if err != nil {
		return "", 0, "", fmt.Errorf("pack-objects stdout: %w", err)
	}

	if err := revList.Start(); err != nil {
		return "", 0, "", fmt.Errorf("starting rev-list: %w", err)
	}
	if err := pack.Start(); err != nil {
		_ = revList.Wait()
		return "", 0, "", fmt.Errorf("starting pack-objects: %w", err)
	}

	tmp, err := os.CreateTemp("", "gf-rotate-*.pack.enc")
	if err != nil {
		return "", 0, "", fmt.Errorf("creating temp file: %w", err)
	}
	hasher := sha256.New()
	if encErr := crypto.EncryptPackfile(io.MultiWriter(tmp, hasher), packOut, repoKey); encErr != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		_ = pack.Wait()
		_ = revList.Wait()
		return "", 0, "", fmt.Errorf("encrypting consolidated packfile: %w", encErr)
	}
	if waitErr := pack.Wait(); waitErr != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		_ = revList.Wait()
		return "", 0, "", fmt.Errorf("pack-objects: %w", waitErr)
	}
	if waitErr := revList.Wait(); waitErr != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("rev-list: %w", waitErr)
	}

	size, err = tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", 0, "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", 0, "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", 0, "", err
	}
	return tmp.Name(), size, hex.EncodeToString(hasher.Sum(nil)), nil
}
