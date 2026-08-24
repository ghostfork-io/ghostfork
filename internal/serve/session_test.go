package serve

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/ghostfork/gf/crypto"
)

// TestServeUpstreamIsReadOnly is what makes the session endpoint's
// "plaintext bytes sent to server: 0" a structural fact rather than a hopeful
// constant. This package reaches the gf server only through two narrow
// interfaces; if neither can write, no code path here can upload anything,
// plaintext or otherwise. Adding a write method to either — however
// innocuous-looking — breaks that guarantee and fails this test.
func TestServeUpstreamIsReadOnly(t *testing.T) {
	// Verbs that would mean the helper can push data upstream. Matched as
	// prefixes so e.g. UploadPackfile or SetRefs is caught.
	writeVerbs := []string{
		"Upload", "Put", "Post", "Set", "Create", "Delete", "Update",
		"Write", "Commit", "Stage", "Push", "Rotate", "Add", "Remove",
	}

	for _, iface := range []reflect.Type{
		reflect.TypeOf((*Upstream)(nil)).Elem(),
		reflect.TypeOf((*MaterializeUpstream)(nil)).Elem(),
	} {
		if iface.NumMethod() == 0 {
			t.Errorf("%s has no methods — did the interface move?", iface.Name())
		}
		for i := range iface.NumMethod() {
			name := iface.Method(i).Name
			for _, verb := range writeVerbs {
				if strings.HasPrefix(name, verb) {
					t.Errorf("%s.%s looks like a write: the serve helper must stay "+
						"read-only, because the session dialog tells users no data can "+
						"be uploaded from here. If this method really is a read, rename "+
						"it; if it is a write, it does not belong in this interface.",
						iface.Name(), name)
				}
			}
		}
	}
}

func TestSessionEndpoint(t *testing.T) {
	fx := newBrowseFixture(t)

	// Fetch a page first, so the transfer counters have something real in them.
	if resp := get(t, fx.base+"/v1/repos/alice/app/tree?ref=main", testToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("priming fetch: status %d", resp.StatusCode)
	}

	resp := get(t, fx.base+"/v1/repos/alice/app/session", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var s sessionResponse
	decodeInto(t, resp, &s)

	// Identity of the running process: these must be live, not zero values.
	if s.Version == "" {
		t.Error("version is empty")
	}
	if s.PID <= 0 {
		t.Errorf("pid = %d, want this process's real pid", s.PID)
	}
	if !strings.HasPrefix(s.Address, "127.0.0.1:") {
		t.Errorf("address = %q, want a loopback address", s.Address)
	}
	if s.Port <= 0 {
		t.Errorf("port = %d, want the bound port", s.Port)
	}
	if s.Username != "alice" {
		t.Errorf("username = %q, want alice", s.Username)
	}
	if s.StartedAt == "" || s.UptimeSeconds < 0 {
		t.Errorf("started_at = %q, uptime = %d", s.StartedAt, s.UptimeSeconds)
	}

	// Vault-specific: fingerprint present and shaped, counters actually counted.
	if !strings.HasPrefix(s.Vault.KeyFingerprint, "SHA256:") || len(s.Vault.KeyFingerprint) != 7+16 {
		t.Errorf("key_fingerprint = %q, want SHA256: + 16 hex chars", s.Vault.KeyFingerprint)
	}
	if s.Vault.Owner != "alice" || s.Vault.Name != "app" {
		t.Errorf("vault = %+v, want alice/app", s.Vault)
	}
	if s.Vault.PackfilesFetched < 1 {
		t.Errorf("packfiles_fetched = %d, want at least the one this vault has",
			s.Vault.PackfilesFetched)
	}
	if s.Vault.CiphertextBytesFetched < 1 || s.Vault.PlaintextBytesDecrypted < 1 {
		t.Errorf("byte counters = %d ciphertext / %d plaintext, want both measured",
			s.Vault.CiphertextBytesFetched, s.Vault.PlaintextBytesDecrypted)
	}

	// The headline claim.
	if s.PlaintextBytesSentToServer != 0 {
		t.Errorf("plaintext_bytes_sent_to_server = %d, MUST be 0",
			s.PlaintextBytesSentToServer)
	}
}

// TestKeyFingerprintIsStableAndNotTheKey checks the fingerprint identifies the
// vault key without being derived in a way that could expose it: same key →
// same fingerprint, and the output is a short hash, never key bytes.
func TestKeyFingerprintIsStableAndNotTheKey(t *testing.T) {
	fx := newBrowseFixture(t)

	first := get(t, fx.base+"/v1/repos/alice/app/session", testToken)
	var a sessionResponse
	decodeInto(t, first, &a)

	second := get(t, fx.base+"/v1/repos/alice/app/session", testToken)
	var b sessionResponse
	decodeInto(t, second, &b)

	if a.Vault.KeyFingerprint != b.Vault.KeyFingerprint {
		t.Errorf("fingerprint changed between calls: %q → %q",
			a.Vault.KeyFingerprint, b.Vault.KeyFingerprint)
	}
	// 8 bytes of hash is plenty to identify a key and far too little to be one.
	if hexPart := strings.TrimPrefix(a.Vault.KeyFingerprint, "SHA256:"); len(hexPart) != 16 {
		t.Errorf("fingerprint hex = %q (%d chars), want 16", hexPart, len(hexPart))
	}
}

// TestKeyFingerprintMatchesCryptoHelper is the test that keeps the dialog's
// "compare this against `gf key-fingerprint`" instruction honest. Both sides
// must derive the fingerprint from crypto.RepoKeyFingerprint; if the helper
// ever computes it another way, the two values diverge and the instruction
// becomes actively misleading — telling a user to verify, then showing them a
// mismatch on a perfectly healthy vault.
func TestKeyFingerprintMatchesCryptoHelper(t *testing.T) {
	repoKey, err := crypto.GenerateRepoKey()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := crypto.EncryptRepoKey(repoKey, identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	// A materializer whose upstream serves exactly this wrapped key.
	mat := NewMaterializer(&fakeMatUpstream{encKey: encKey}, identity, "alice", t.TempDir())

	got, err := mat.KeyFingerprint("alice", "app")
	if err != nil {
		t.Fatalf("KeyFingerprint: %v", err)
	}
	// What `gf key-fingerprint` prints for the same key.
	want := crypto.RepoKeyFingerprint(repoKey)
	if got != want {
		t.Errorf("helper reports %q but the CLI would print %q — the dialog tells "+
			"users to compare these, so they must be derived identically", got, want)
	}
}
