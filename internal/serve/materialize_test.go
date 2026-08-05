package serve

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghostfork/gf/crypto"
)

// fakeMatUpstream serves one encrypted packfile per seq and counts downloads.
type fakeMatUpstream struct {
	encKey     []byte           // repo key wrapped for the test identity
	packs      map[int64][]byte // seq → encrypted packfile bytes
	seqs       []int64
	generation int // reported key generation (0 → treated as 1)
	downloads  int
}

func (f *fakeMatUpstream) GetKey(owner, repo, username string) ([]byte, error) {
	return f.encKey, nil
}

func (f *fakeMatUpstream) ListPackfiles(owner, repo string, afterSeq int64) ([]int64, int, error) {
	var out []int64
	for _, s := range f.seqs {
		if s > afterSeq {
			out = append(out, s)
		}
	}
	gen := f.generation
	if gen == 0 {
		gen = 1
	}
	return out, gen, nil
}

func (f *fakeMatUpstream) DownloadPackfile(owner, repo string, seq int64) (io.ReadCloser, error) {
	f.downloads++
	p, ok := f.packs[seq]
	if !ok {
		return nil, fmt.Errorf("no pack for seq %d", seq)
	}
	return io.NopCloser(bytes.NewReader(p)), nil
}

// gitOut runs git and returns trimmed stdout, failing the test on error.
func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// buildEncryptedPack creates a commit in work adding files, packs every object
// reachable from HEAD, and returns the pack encrypted with repoKey plus the
// commit SHA. Each call packs the full history — fine for tests.
func buildEncryptedPack(t *testing.T, work string, repoKey []byte, files map[string]string) (encrypted []byte, headSHA string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	gitOut(t, work, "add", "-A")
	gitOut(t, work, "commit", "-q", "-m", "test commit")
	head := gitOut(t, work, "rev-parse", "HEAD")

	objects := gitOut(t, work, "rev-list", "--objects", "HEAD")
	pack := exec.Command("git", "pack-objects", "--stdout", "-q")
	pack.Dir = work
	pack.Stdin = strings.NewReader(objects + "\n")
	var packBuf bytes.Buffer
	pack.Stdout = &packBuf
	pack.Stderr = os.Stderr
	if err := pack.Run(); err != nil {
		t.Fatalf("pack-objects: %v", err)
	}

	var enc bytes.Buffer
	if err := crypto.EncryptPackfile(&enc, &packBuf, repoKey); err != nil {
		t.Fatalf("encrypting pack: %v", err)
	}
	return enc.Bytes(), head
}

func TestMaterializerSyncAndIncremental(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	repoKey, err := crypto.GenerateRepoKey()
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := crypto.EncryptRepoKey(repoKey, identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	gitOut(t, work, "init", "-q", "-b", "main")
	pack1, head1 := buildEncryptedPack(t, work, repoKey, map[string]string{"a.txt": "alpha"})

	up := &fakeMatUpstream{
		encKey: encKey,
		packs:  map[int64][]byte{1: pack1},
		seqs:   []int64{1},
	}
	m := NewMaterializer(up, identity, "alice", t.TempDir())

	gitDir, err := m.Sync("alice", "app")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// The commit and the file contents are recoverable from the bare repo.
	if typ := gitOut(t, gitDir, "--git-dir", gitDir, "cat-file", "-t", head1); typ != "commit" {
		t.Errorf("cat-file -t %s = %q, want commit", head1, typ)
	}
	if got := gitOut(t, gitDir, "--git-dir", gitDir, "show", head1+":a.txt"); got != "alpha" {
		t.Errorf("a.txt content = %q, want alpha", got)
	}

	// Second sync with nothing new: no downloads.
	up.downloads = 0
	if _, err := m.Sync("alice", "app"); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if up.downloads != 0 {
		t.Errorf("second sync downloaded %d packfiles, want 0 (incremental via last_seq)", up.downloads)
	}

	// A new push appears as seq 2; only that one is fetched.
	pack2, head2 := buildEncryptedPack(t, work, repoKey, map[string]string{"b.txt": "beta"})
	up.packs[2] = pack2
	up.seqs = []int64{1, 2}

	if _, err := m.Sync("alice", "app"); err != nil {
		t.Fatalf("third Sync: %v", err)
	}
	if up.downloads != 1 {
		t.Errorf("third sync downloaded %d packfiles, want 1", up.downloads)
	}
	if got := gitOut(t, gitDir, "--git-dir", gitDir, "show", head2+":b.txt"); got != "beta" {
		t.Errorf("b.txt content = %q, want beta", got)
	}
}

// TestMaterializerRebuildsOnKeyRotation proves the cache is invalidated when
// the server's key generation changes: after a rotation (new key, new history
// at a higher generation), Sync wipes the stale mirror and re-materializes
// under the new key — the old objects are gone, not left dangling under the
// retired key.
func TestMaterializerRebuildsOnKeyRotation(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key1, _ := crypto.GenerateRepoKey()
	encKey1, err := crypto.EncryptRepoKey(key1, identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	work1 := t.TempDir()
	gitOut(t, work1, "init", "-q", "-b", "main")
	pack1, head1 := buildEncryptedPack(t, work1, key1, map[string]string{"old.txt": "before rotation"})

	up := &fakeMatUpstream{
		encKey:     encKey1,
		packs:      map[int64][]byte{1: pack1},
		seqs:       []int64{1},
		generation: 1,
	}
	m := NewMaterializer(up, identity, "alice", t.TempDir())

	gitDir, err := m.Sync("alice", "app")
	if err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	if got := gitOut(t, gitDir, "--git-dir", gitDir, "show", head1+":old.txt"); got != "before rotation" {
		t.Fatalf("pre-rotation content = %q, want 'before rotation'", got)
	}

	// Rotation: a fresh key re-encrypts a new consolidated history at a higher
	// seq and generation. The upstream now hands out the new wrapped key.
	key2, _ := crypto.GenerateRepoKey()
	encKey2, err := crypto.EncryptRepoKey(key2, identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	work2 := t.TempDir()
	gitOut(t, work2, "init", "-q", "-b", "main")
	pack2, head2 := buildEncryptedPack(t, work2, key2, map[string]string{"new.txt": "after rotation"})
	up.encKey = encKey2
	up.packs = map[int64][]byte{2: pack2}
	up.seqs = []int64{2}
	up.generation = 2

	if _, err := m.Sync("alice", "app"); err != nil {
		t.Fatalf("post-rotation Sync: %v", err)
	}

	// The new history is present, decrypted under the new key…
	if got := gitOut(t, gitDir, "--git-dir", gitDir, "show", head2+":new.txt"); got != "after rotation" {
		t.Errorf("post-rotation content = %q, want 'after rotation'", got)
	}
	// …and the pre-rotation commit was wiped, not merely left unreferenced.
	chk := exec.Command("git", "--git-dir", gitDir, "cat-file", "-t", head1)
	chk.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+gitDir)
	if err := chk.Run(); err == nil {
		t.Errorf("pre-rotation commit %s still present after rotation — cache not invalidated", head1)
	}
}

// TestMaterializerRebuildAfterVaultReset covers the case the generation check
// cannot see: a vault wiped and re-created keeps generation == 1 but restarts
// its packfile sequence, so after an incremental Sync the cache is pinned to
// history the server no longer has. ListPackfiles(afterSeq=last_seq) reports
// nothing new, so a plain Sync leaves the stale commit in place and the new one
// absent — exactly what made `gf serve` answer "doesn't exist on this branch"
// for freshly re-pushed data. Rebuild must re-materialize from seq 0.
func TestMaterializerRebuildAfterVaultReset(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Original vault: key1, history reaching seq 2.
	key1, _ := crypto.GenerateRepoKey()
	encKey1, err := crypto.EncryptRepoKey(key1, identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	work1 := t.TempDir()
	gitOut(t, work1, "init", "-q", "-b", "main")
	pack1a, _ := buildEncryptedPack(t, work1, key1, map[string]string{"a.txt": "one"})
	pack1b, headOld := buildEncryptedPack(t, work1, key1, map[string]string{"b.txt": "two"})

	up := &fakeMatUpstream{
		encKey:     encKey1,
		packs:      map[int64][]byte{1: pack1a, 2: pack1b},
		seqs:       []int64{1, 2},
		generation: 1,
	}
	m := NewMaterializer(up, identity, "alice", t.TempDir())

	gitDir, err := m.Sync("alice", "app")
	if err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	if !commitPresent(gitDir, headOld) {
		t.Fatalf("original commit %s not materialized", headOld)
	}

	// Vault reset: deleted and re-created, so a brand-new key, a brand-new
	// history, and the sequence restarts at 1 — while generation stays 1.
	key2, _ := crypto.GenerateRepoKey()
	encKey2, err := crypto.EncryptRepoKey(key2, identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	work2 := t.TempDir()
	gitOut(t, work2, "init", "-q", "-b", "main")
	pack2, headNew := buildEncryptedPack(t, work2, key2, map[string]string{"c.txt": "fresh"})
	up.encKey = encKey2
	up.packs = map[int64][]byte{1: pack2}
	up.seqs = []int64{1}
	up.generation = 1

	// A plain incremental Sync is blind to the reset: seq 1 <= cached last_seq 2,
	// so nothing is fetched and the new commit stays absent. This is the bug.
	if _, err := m.Sync("alice", "app"); err != nil {
		t.Fatalf("post-reset Sync: %v", err)
	}
	if commitPresent(gitDir, headNew) {
		t.Fatalf("incremental Sync unexpectedly fetched the reset history; the test no longer models the bug")
	}

	// Rebuild re-materializes from seq 0 under the new key: the new commit
	// appears and the stale one is gone.
	if _, err := m.Rebuild("alice", "app"); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if !commitPresent(gitDir, headNew) {
		t.Errorf("commit %s missing after Rebuild — reset history not re-fetched", headNew)
	}
	if commitPresent(gitDir, headOld) {
		t.Errorf("stale commit %s still present after Rebuild — cache not wiped", headOld)
	}
}

func TestMaterializerRejectsBadNames(t *testing.T) {
	m := NewMaterializer(&fakeMatUpstream{}, nil, "alice", t.TempDir())
	for _, bad := range []string{"..", "a/b", ".hidden", "", "a b", strings.Repeat("x", 65)} {
		if _, err := m.Sync(bad, "repo"); err == nil {
			t.Errorf("Sync(%q, repo) accepted an invalid owner", bad)
		}
		if _, err := m.Sync("owner", bad); err == nil {
			t.Errorf("Sync(owner, %q) accepted an invalid repo", bad)
		}
	}
}

func TestMaterializerWrongKeyFailsAuthentication(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rightKey, _ := crypto.GenerateRepoKey()
	wrongKey, _ := crypto.GenerateRepoKey()
	// The upstream wraps the WRONG key for us: decryption must fail the
	// Poly1305 check, and nothing may be indexed.
	encWrong, err := crypto.EncryptRepoKey(wrongKey, identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	gitOut(t, work, "init", "-q", "-b", "main")
	pack, _ := buildEncryptedPack(t, work, rightKey, map[string]string{"a.txt": "alpha"})

	up := &fakeMatUpstream{encKey: encWrong, packs: map[int64][]byte{1: pack}, seqs: []int64{1}}
	m := NewMaterializer(up, identity, "alice", t.TempDir())

	if _, err := m.Sync("alice", "app"); err == nil {
		t.Fatal("Sync succeeded with the wrong repo key, want authentication failure")
	}
}
