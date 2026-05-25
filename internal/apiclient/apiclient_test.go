package apiclient_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/server/testserver"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// newIdentity returns a fresh Ed25519 keypair for test use.
func newIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return pub, priv
}

// registered registers a user against ts and returns an authenticated client.
func registered(t *testing.T, ts *testserver.TestServer, username string) *apiclient.Client {
	t.Helper()
	pub, priv := newIdentity(t)
	anon := apiclient.New(ts.URL)
	if err := anon.Register(username, base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatalf("register %s: %v", username, err)
	}
	return apiclient.NewAuthenticated(ts.URL, username, priv)
}

// withRepo registers a user, creates a repo, and returns the client. The repo
// is always owned by the registered user; URL-level owner is the username.
func withRepo(t *testing.T, ts *testserver.TestServer, username, name string) *apiclient.Client {
	t.Helper()
	c := registered(t, ts, username)
	if err := c.CreateRepo(name, []byte("fake-enc-key")); err != nil {
		t.Fatalf("create repo: %v", err)
	}
	return c
}

// ── Register ──────────────────────────────────────────────────────────────────

func TestRegisterSucceeds(t *testing.T) {
	ts := testserver.Start(t)
	anon := apiclient.New(ts.URL)
	pub, _ := newIdentity(t)

	if err := anon.Register("alice", base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterDuplicateReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	anon := apiclient.New(ts.URL)
	pub, _ := newIdentity(t)
	encoded := base64.StdEncoding.EncodeToString(pub)

	if err := anon.Register("alice", encoded); err != nil {
		t.Fatal(err)
	}
	err := anon.Register("alice", encoded)
	if err == nil {
		t.Fatal("expected error registering duplicate username, got nil")
	}
}

// ── GetUser ───────────────────────────────────────────────────────────────────

func TestGetUser(t *testing.T) {
	ts := testserver.Start(t)
	c := registered(t, ts, "alice")

	u, err := c.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" {
		t.Fatalf("expected username alice, got %q", u.Username)
	}
	if u.PublicKey == "" {
		t.Fatal("expected non-empty public key")
	}
}

func TestGetUserNotFoundReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	c := registered(t, ts, "alice")

	_, err := c.GetUser("nobody")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

// ── CreateRepo ────────────────────────────────────────────────────────────────

func TestCreateRepo(t *testing.T) {
	ts := testserver.Start(t)
	c := registered(t, ts, "alice")

	if err := c.CreateRepo("myrepo", []byte("enc-key")); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRepoDuplicateReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	c := registered(t, ts, "alice")

	if err := c.CreateRepo("myrepo", []byte("enc-key")); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateRepo("myrepo", []byte("enc-key")); err == nil {
		t.Fatal("expected error for duplicate repo, got nil")
	}
}

// ── Refs ──────────────────────────────────────────────────────────────────────

func TestGetRefsEmptyOnNewRepo(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	refs, err := c.GetRefs("alice", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected empty refs, got %v", refs)
	}
}

func TestUpdateAndGetRefs(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	if err := c.UpdateRef("alice", "repo", "main", "abc123"); err != nil {
		t.Fatal(err)
	}

	refs, err := c.GetRefs("alice", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Branch != "main" || refs[0].CommitSHA != "abc123" {
		t.Fatalf("unexpected ref: %+v", refs[0])
	}
}

func TestUpdateRefReplacesPreviousValue(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	c.UpdateRef("alice", "repo", "main", "aaa") //nolint:errcheck
	c.UpdateRef("alice", "repo", "main", "bbb") //nolint:errcheck

	refs, _ := c.GetRefs("alice", "repo")
	if len(refs) != 1 || refs[0].CommitSHA != "bbb" {
		t.Fatalf("expected SHA bbb, got %v", refs)
	}
}

// ── Packfiles ─────────────────────────────────────────────────────────────────

func TestUploadPackfileReturnsSeq1(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	seq, err := c.UploadPackfile("alice", "repo", []byte("packdata"))
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("expected seq=1, got %d", seq)
	}
}

func TestUploadPackfileSequentialSeqs(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	for i := int64(1); i <= 3; i++ {
		seq, err := c.UploadPackfile("alice", "repo", []byte("pack"))
		if err != nil {
			t.Fatal(err)
		}
		if seq != i {
			t.Fatalf("push %d: expected seq=%d, got %d", i, i, seq)
		}
	}
}

func TestListPackfilesReturnsAllSeqs(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	for range 3 {
		c.UploadPackfile("alice", "repo", []byte("pack")) //nolint:errcheck
	}

	seqs, err := c.ListPackfiles("alice", "repo", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 3 {
		t.Fatalf("expected 3 seqs, got %v", seqs)
	}
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("seqs[%d] = %d, want %d", i, s, i+1)
		}
	}
}

func TestListPackfilesAfterN(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	for range 3 {
		c.UploadPackfile("alice", "repo", []byte("pack")) //nolint:errcheck
	}

	seqs, err := c.ListPackfiles("alice", "repo", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 1 || seqs[0] != 3 {
		t.Fatalf("expected [3], got %v", seqs)
	}
}

func TestDownloadPackfileMatchesUpload(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	payload := []byte("encrypted-packfile-contents")
	seq, _ := c.UploadPackfile("alice", "repo", payload)

	got, err := c.DownloadPackfile("alice", "repo", seq)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded bytes differ from uploaded bytes")
	}
}

func TestDownloadNonexistentPackfileReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	_, err := c.DownloadPackfile("alice", "repo", 99)
	if err == nil {
		t.Fatal("expected error for missing packfile, got nil")
	}
}

// ── Keys ──────────────────────────────────────────────────────────────────────

func TestPutAndGetKey(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	encKey := []byte("encrypted-repo-key-bytes")
	if err := c.PutKey("alice", "repo", "alice", encKey); err != nil {
		t.Fatal(err)
	}

	got, err := c.GetKey("alice", "repo", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, encKey) {
		t.Fatalf("key mismatch: got %v, want %v", got, encKey)
	}
}

func TestGetKeyNotFoundReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	c := withRepo(t, ts, "alice", "repo")

	_, err := c.GetKey("alice", "repo", "nobody")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestDeleteKey(t *testing.T) {
	ts := testserver.Start(t)
	alice := withRepo(t, ts, "alice", "repo")
	// Register bob and grant him access so alice can then revoke it.
	registered(t, ts, "bob")
	alice.PutKey("alice", "repo", "bob", []byte("bob-key")) //nolint:errcheck

	if err := alice.DeleteKey("alice", "repo", "bob"); err != nil {
		t.Fatal(err)
	}

	_, err := alice.GetKey("alice", "repo", "bob")
	if err == nil {
		t.Fatal("expected error after deletion, got nil")
	}
}

// ── Auth / authz errors ───────────────────────────────────────────────────────

func TestWrongSignerReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	registered(t, ts, "alice") // alice exists, but we'll try a bogus key

	_, bogusPriv := newIdentity(t)
	bad := apiclient.NewAuthenticated(ts.URL, "alice", bogusPriv)
	_, err := bad.GetUser("alice")
	if err == nil {
		t.Fatal("expected error when signing with a key that doesn't match alice's stored pubkey")
	}
}

func TestUnauthenticatedReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	registered(t, ts, "alice")

	anon := apiclient.New(ts.URL)
	_, err := anon.GetUser("alice")
	if err == nil {
		t.Fatal("expected error for unauthenticated GetUser, got nil")
	}
}

func TestForbiddenRepoReturnsError(t *testing.T) {
	ts := testserver.Start(t)
	withRepo(t, ts, "alice", "secret")
	bob := registered(t, ts, "bob")

	_, err := bob.GetRefs("alice", "secret")
	if err == nil {
		t.Fatal("expected error for unauthorized repo access, got nil")
	}
}
