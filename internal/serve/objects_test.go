package serve

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/protocol/types"
)

// browseFixture is a running gf serve wired to one real, encrypted,
// materializable repo ("alice/app") with three commits on main:
//
//	c1: a.txt, sub/nested.txt
//	c2: b.bin (binary)
//	c3: a.txt modified
type browseFixture struct {
	base  string
	heads []string // c1, c2, c3
}

func newBrowseFixture(t *testing.T) *browseFixture {
	t.Helper()
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
	if err := os.MkdirAll(filepath.Join(work, "sub"), 0755); err != nil {
		t.Fatal(err)
	}

	var heads []string
	_, h1 := buildEncryptedPack(t, work, repoKey, map[string]string{
		"a.txt":          "alpha\n",
		"sub/nested.txt": "nested\n",
	})
	heads = append(heads, h1)
	_, h2 := buildEncryptedPack(t, work, repoKey, map[string]string{
		"b.bin": "\x00\x01\x02\x03binary",
	})
	heads = append(heads, h2)
	// One pack with the whole history keeps the fixture simple.
	pack, h3 := buildEncryptedPack(t, work, repoKey, map[string]string{
		"a.txt": "alpha v2\n",
	})
	heads = append(heads, h3)

	mat := NewMaterializer(&fakeMatUpstream{
		encKey: encKey,
		packs:  map[int64][]byte{1: pack},
		seqs:   []int64{1},
	}, identity, "alice", t.TempDir())

	base := startTestServer(t, func(o *Options) {
		o.Upstream = &fakeUpstream{refs: []types.Ref{{Branch: "refs/heads/main", CommitSHA: h3}}}
		o.Materializer = mat
	})
	return &browseFixture{base: base, heads: heads}
}

func decodeInto(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decoding: %v", err)
	}
}

func TestTreeEndpoint(t *testing.T) {
	fx := newBrowseFixture(t)

	resp := get(t, fx.base+"/v1/repos/alice/app/tree?ref=main", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var tree treeResponse
	decodeInto(t, resp, &tree)

	if len(tree.Entries) != 3 {
		t.Fatalf("root entries = %+v, want [sub, a.txt, b.bin]", tree.Entries)
	}
	if tree.Entries[0].Name != "sub" || tree.Entries[0].Type != "dir" {
		t.Errorf("entries[0] = %+v, want dir sub first", tree.Entries[0])
	}
	if tree.Entries[1].Name != "a.txt" || tree.Entries[1].Type != "file" ||
		tree.Entries[1].Size == nil || *tree.Entries[1].Size != int64(len("alpha v2\n")) {
		t.Errorf("entries[1] = %+v, want a.txt file with size", tree.Entries[1])
	}

	// Subdirectory listing carries full paths.
	resp = get(t, fx.base+"/v1/repos/alice/app/tree?ref=main&path=sub", testToken)
	var sub treeResponse
	decodeInto(t, resp, &sub)
	if len(sub.Entries) != 1 || sub.Entries[0].Path != "sub/nested.txt" {
		t.Errorf("sub entries = %+v, want [sub/nested.txt]", sub.Entries)
	}

	// Historical ref by SHA: a.txt at c1 has the old size.
	resp = get(t, fx.base+"/v1/repos/alice/app/tree?ref="+fx.heads[0], testToken)
	var old treeResponse
	decodeInto(t, resp, &old)
	for _, e := range old.Entries {
		if e.Name == "a.txt" && (e.Size == nil || *e.Size != int64(len("alpha\n"))) {
			t.Errorf("a.txt at c1 = %+v, want original size", e)
		}
	}

	// Missing directory.
	resp = get(t, fx.base+"/v1/repos/alice/app/tree?ref=main&path=nope", testToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing dir status = %d, want 404", resp.StatusCode)
	}
	if body := decodeError(t, resp); body.Error != "path_not_found" {
		t.Errorf("error = %q, want path_not_found", body.Error)
	}

	// Unknown ref.
	resp = get(t, fx.base+"/v1/repos/alice/app/tree?ref=gone", testToken)
	if body := decodeError(t, resp); resp.StatusCode != http.StatusNotFound || body.Error != "ref_not_found" {
		t.Errorf("unknown ref = %d/%q, want 404/ref_not_found", resp.StatusCode, body.Error)
	}
}

func TestBlobEndpoint(t *testing.T) {
	fx := newBrowseFixture(t)

	resp := get(t, fx.base+"/v1/repos/alice/app/blob?ref=main&path=a.txt", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "alpha v2\n" {
		t.Errorf("content = %q, want alpha v2", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "9" {
		t.Errorf("Content-Length = %q, want 9", cl)
	}

	// Binary passthrough: bytes verbatim, non-text content type.
	resp = get(t, fx.base+"/v1/repos/alice/app/blob?ref=main&path=b.bin", testToken)
	raw, _ := io.ReadAll(resp.Body)
	if string(raw) != "\x00\x01\x02\x03binary" {
		t.Errorf("binary content = %q, want verbatim bytes", raw)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("binary Content-Type = %q, want application/octet-stream", ct)
	}

	// Old version by SHA.
	resp = get(t, fx.base+"/v1/repos/alice/app/blob?ref="+fx.heads[0]+"&path=a.txt", testToken)
	old, _ := io.ReadAll(resp.Body)
	if string(old) != "alpha\n" {
		t.Errorf("historical content = %q, want alpha", old)
	}

	// A directory is not a blob.
	resp = get(t, fx.base+"/v1/repos/alice/app/blob?ref=main&path=sub", testToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("blob of a dir = %d, want 404", resp.StatusCode)
	}
}

func TestCommitsEndpoint(t *testing.T) {
	fx := newBrowseFixture(t)

	// Page 1: two of three commits, newest first, with a cursor.
	resp := get(t, fx.base+"/v1/repos/alice/app/commits?ref=main&limit=2", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var page1 commitsResponse
	decodeInto(t, resp, &page1)
	if len(page1.Commits) != 2 ||
		page1.Commits[0].SHA != fx.heads[2] || page1.Commits[1].SHA != fx.heads[1] {
		t.Fatalf("page1 = %+v, want [c3, c2]", page1.Commits)
	}
	if page1.NextBefore != fx.heads[1] {
		t.Errorf("next_before = %q, want %q", page1.NextBefore, fx.heads[1])
	}
	if page1.Commits[0].Message != "test commit" || page1.Commits[0].Author.Name != "t" {
		t.Errorf("commit fields = %+v", page1.Commits[0])
	}
	if len(page1.Commits[0].Parents) != 1 || page1.Commits[0].Parents[0] != fx.heads[1] {
		t.Errorf("c3 parents = %v, want [c2]", page1.Commits[0].Parents)
	}

	// Page 2: the remaining root commit, no cursor.
	resp = get(t, fx.base+"/v1/repos/alice/app/commits?ref=main&limit=2&before="+page1.NextBefore, testToken)
	var page2 commitsResponse
	decodeInto(t, resp, &page2)
	if len(page2.Commits) != 1 || page2.Commits[0].SHA != fx.heads[0] {
		t.Fatalf("page2 = %+v, want [c1]", page2.Commits)
	}
	if len(page2.Commits[0].Parents) != 0 {
		t.Errorf("root commit parents = %v, want none", page2.Commits[0].Parents)
	}
	if page2.NextBefore != "" {
		t.Errorf("page2 next_before = %q, want empty (history exhausted)", page2.NextBefore)
	}
}
