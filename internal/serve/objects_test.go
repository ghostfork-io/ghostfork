package serve

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func TestCommitDetailEndpoint(t *testing.T) {
	fx := newBrowseFixture(t)

	// c3 modified a.txt in place: one line out, one line in, diffed against c2.
	resp := get(t, fx.base+"/v1/repos/alice/app/commit?ref=main", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var c3 commitDetailResponse
	decodeInto(t, resp, &c3)

	if c3.SHA != fx.heads[2] || c3.DiffAgainst != fx.heads[1] {
		t.Errorf("sha/diff_against = %s/%s, want %s/%s",
			c3.SHA, c3.DiffAgainst, fx.heads[2], fx.heads[1])
	}
	if c3.Message != "test commit" || c3.Author.Name != "t" {
		t.Errorf("commit metadata = %+v", c3.commitEntry)
	}
	if len(c3.Files) != 1 {
		t.Fatalf("files = %+v, want just a.txt", c3.Files)
	}
	f := c3.Files[0]
	if f.Path != "a.txt" || f.Status != "modified" || f.Binary {
		t.Errorf("file = %+v, want modified text a.txt", f)
	}
	if f.Additions != 1 || f.Deletions != 1 {
		t.Errorf("a.txt stats = +%d/-%d, want +1/-1", f.Additions, f.Deletions)
	}
	if c3.Additions != 1 || c3.Deletions != 1 {
		t.Errorf("commit totals = +%d/-%d, want +1/-1", c3.Additions, c3.Deletions)
	}
	if !strings.Contains(f.Patch, "-alpha") || !strings.Contains(f.Patch, "+alpha v2") {
		t.Errorf("patch does not show the line swap:\n%s", f.Patch)
	}
	if f.OldPath != "" || f.PatchOmitted {
		t.Errorf("unexpected rename/omission on a plain edit: %+v", f)
	}

	// c2 added a binary file: flagged, no line counts, no patch.
	resp = get(t, fx.base+"/v1/repos/alice/app/commit?ref="+fx.heads[1], testToken)
	var c2 commitDetailResponse
	decodeInto(t, resp, &c2)
	if len(c2.Files) != 1 || c2.Files[0].Path != "b.bin" {
		t.Fatalf("c2 files = %+v, want just b.bin", c2.Files)
	}
	if b := c2.Files[0]; !b.Binary || b.Status != "added" || b.Patch != "" ||
		b.Additions != 0 || b.Deletions != 0 {
		t.Errorf("b.bin = %+v, want added binary with no counts or patch", b)
	}

	// c1 is the root commit: everything added, nothing to diff against.
	resp = get(t, fx.base+"/v1/repos/alice/app/commit?ref="+fx.heads[0], testToken)
	var c1 commitDetailResponse
	decodeInto(t, resp, &c1)
	if c1.DiffAgainst != "" {
		t.Errorf("root commit diff_against = %q, want empty", c1.DiffAgainst)
	}
	if len(c1.Parents) != 0 {
		t.Errorf("root commit parents = %v, want none", c1.Parents)
	}
	paths := map[string]diffFile{}
	for _, f := range c1.Files {
		paths[f.Path] = f
	}
	if len(paths) != 2 || paths["a.txt"].Status != "added" || paths["sub/nested.txt"].Status != "added" {
		t.Fatalf("root commit files = %+v, want a.txt and sub/nested.txt added", c1.Files)
	}
	if p := paths["sub/nested.txt"]; !strings.Contains(p.Patch, "+nested") {
		t.Errorf("nested.txt patch = %q, want the added line", p.Patch)
	}
	// Both files are one line each, so the totals must add up.
	if c1.Additions != 2 || c1.Deletions != 0 {
		t.Errorf("root commit totals = +%d/-%d, want +2/-0", c1.Additions, c1.Deletions)
	}

	// Unknown ref.
	resp = get(t, fx.base+"/v1/repos/alice/app/commit?ref=gone", testToken)
	if body := decodeError(t, resp); resp.StatusCode != http.StatusNotFound || body.Error != "ref_not_found" {
		t.Errorf("unknown ref = %d/%q, want 404/ref_not_found", resp.StatusCode, body.Error)
	}

	// No ref at all.
	resp = get(t, fx.base+"/v1/repos/alice/app/commit", testToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing ref = %d, want 400", resp.StatusCode)
	}
}

// TestParseDiffFiles covers the git renderings the browse fixture can't
// produce — renames, copies, deletions and typechanges — straight from the
// plumbing output shapes documented in git-diff-tree(1).
func TestParseDiffFiles(t *testing.T) {
	z := func(records ...string) string {
		out := ""
		for _, r := range records {
			out += r + "\x00"
		}
		return out
	}
	numstat := z(
		"3\t1\tsrc/keep.go",
		"-\t-\tassets/logo.png",
		"0\t0\t", "old/name.txt", "new/name.txt", // rename: counts, then both paths
		"0\t12\tgone.txt",
		"1\t2\tlink",
		"5\t0\tcopy.txt",
	)
	nameStatus := z(
		"M", "src/keep.go",
		"M", "assets/logo.png",
		"R100", "old/name.txt", "new/name.txt",
		"D", "gone.txt",
		"T", "link",
		"C75", "orig.txt", "copy.txt",
	)

	files := parseDiffFiles(numstat, nameStatus)
	want := []diffFile{
		{Path: "src/keep.go", Status: "modified", Additions: 3, Deletions: 1},
		{Path: "assets/logo.png", Status: "modified", Binary: true},
		{Path: "new/name.txt", OldPath: "old/name.txt", Status: "renamed"},
		{Path: "gone.txt", Status: "deleted", Deletions: 12},
		{Path: "link", Status: "typechanged", Additions: 1, Deletions: 2},
		{Path: "copy.txt", Status: "copied", Additions: 5},
	}
	if len(files) != len(want) {
		t.Fatalf("parsed %d files, want %d: %+v", len(files), len(want), files)
	}
	for i, w := range want {
		if files[i] != w {
			t.Errorf("files[%d] = %+v, want %+v", i, files[i], w)
		}
	}
}

// A rename's numstat record names both paths, so the copy's old path is only
// known from --name-status. parseDiffFiles keys status off the new path; a
// numstat record with no matching status entry must still parse.
func TestParseDiffFilesToleratesMismatch(t *testing.T) {
	files := parseDiffFiles("4\t0\tonly-in-numstat.txt\x00", "")
	if len(files) != 1 {
		t.Fatalf("parsed %+v, want one file", files)
	}
	if files[0].Status != "modified" || files[0].Additions != 4 {
		t.Errorf("file = %+v, want modified with +4", files[0])
	}
	if got := parseDiffFiles("", "M\x00a.txt\x00"); len(got) != 0 {
		t.Errorf("status without numstat = %+v, want no files", got)
	}
	// Truncated records must not panic or invent paths.
	if got := parseDiffFiles("0\t0\t\x00only-old-path\x00", "R100\x00old\x00"); len(got) != 0 {
		t.Errorf("truncated rename = %+v, want no files", got)
	}
}

func TestTreeCommitsEndpoint(t *testing.T) {
	fx := newBrowseFixture(t)

	// At main: a.txt was last touched by c3, b.bin by c2, and sub/ (via
	// sub/nested.txt) only ever by the root commit c1.
	resp := get(t, fx.base+"/v1/repos/alice/app/tree-commits?ref=main", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got treeCommitsResponse
	decodeInto(t, resp, &got)

	byPath := map[string]treeCommitEntry{}
	for _, e := range got.Entries {
		byPath[e.Path] = e
	}
	if len(byPath) != 3 {
		t.Fatalf("entries = %+v, want a.txt, b.bin and sub", got.Entries)
	}
	for path, want := range map[string]string{
		"a.txt": fx.heads[2],
		"b.bin": fx.heads[1],
		"sub":   fx.heads[0], // a directory answers with the newest commit inside it
	} {
		if e, ok := byPath[path]; !ok || e.SHA != want {
			t.Errorf("%s last commit = %q, want %q", path, e.SHA, want)
		}
	}
	if e := byPath["a.txt"]; e.Message != "test commit" || e.Author.Name != "t" || e.Date == "" {
		t.Errorf("a.txt entry = %+v, want the commit's metadata filled in", e)
	}

	// The header row: the newest commit touching the whole directory. At the
	// root of this fixture that is the tip, c3.
	if got.Latest == nil || got.Latest.SHA != fx.heads[2] {
		t.Errorf("latest = %+v, want c3 %q", got.Latest, fx.heads[2])
	}

	// Inside a subdirectory, paths stay repo-rooted.
	resp = get(t, fx.base+"/v1/repos/alice/app/tree-commits?ref=main&path=sub", testToken)
	var sub treeCommitsResponse
	decodeInto(t, resp, &sub)
	if len(sub.Entries) != 1 || sub.Entries[0].Path != "sub/nested.txt" ||
		sub.Entries[0].SHA != fx.heads[0] {
		t.Fatalf("sub entries = %+v, want sub/nested.txt at c1", sub.Entries)
	}
	// sub/ has only ever been touched by c1, so its header row says so rather
	// than repeating the ref tip.
	if sub.Latest == nil || sub.Latest.SHA != fx.heads[0] {
		t.Errorf("sub latest = %+v, want c1 %q", sub.Latest, fx.heads[0])
	}

	// At c1, a.txt had not yet been modified, so it answers with c1 itself and
	// b.bin isn't in the tree at all.
	resp = get(t, fx.base+"/v1/repos/alice/app/tree-commits?ref="+fx.heads[0], testToken)
	var old treeCommitsResponse
	decodeInto(t, resp, &old)
	for _, e := range old.Entries {
		if e.Path == "b.bin" {
			t.Errorf("b.bin listed at c1, but it was added by c2")
		}
		if e.Path == "a.txt" && e.SHA != fx.heads[0] {
			t.Errorf("a.txt at c1 = %q, want c1 %q", e.SHA, fx.heads[0])
		}
	}

	// A path that isn't a directory.
	resp = get(t, fx.base+"/v1/repos/alice/app/tree-commits?ref=main&path=nope", testToken)
	if body := decodeError(t, resp); resp.StatusCode != http.StatusNotFound || body.Error != "path_not_found" {
		t.Errorf("missing dir = %d/%q, want 404/path_not_found", resp.StatusCode, body.Error)
	}
}
