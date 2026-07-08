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
	encKey    []byte           // repo key wrapped for the test identity
	packs     map[int64][]byte // seq → encrypted packfile bytes
	seqs      []int64
	downloads int
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
	return out, 1, nil
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
