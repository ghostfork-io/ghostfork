package crypto_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghostfork/gf/crypto"
)

// ── Identity ────────────────────────────────────────────────────────────────

func TestGenerateIdentityIsValid(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		t.Fatal("identity is nil")
	}
	if len(id.PublicKey()) == 0 {
		t.Fatal("public key is empty")
	}
	if len(id.Signer()) == 0 {
		t.Fatal("signer is empty")
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "identity.ed25519")
	if err := crypto.SaveIdentity(path, id); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected permissions 0600, got %o", info.Mode().Perm())
	}

	loaded, err := crypto.LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.PublicKey(), id.PublicKey()) {
		t.Fatal("public key mismatch after round trip")
	}
	if !bytes.Equal(loaded.Signer(), id.Signer()) {
		t.Fatal("private key mismatch after round trip")
	}
}

func TestTwoIdentitiesAreDistinct(t *testing.T) {
	a, _ := crypto.GenerateIdentity()
	b, _ := crypto.GenerateIdentity()
	if bytes.Equal(a.Signer(), b.Signer()) {
		t.Fatal("two generated identities are identical")
	}
}

// ── Repo key ─────────────────────────────────────────────────────────────────

func TestGenerateRepoKeyIs32Bytes(t *testing.T) {
	key, err := crypto.GenerateRepoKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key))
	}
}

func TestTwoRepoKeysAreDistinct(t *testing.T) {
	a, _ := crypto.GenerateRepoKey()
	b, _ := crypto.GenerateRepoKey()
	if bytes.Equal(a, b) {
		t.Fatal("two generated repo keys are identical")
	}
}

func TestRepoKeyEncryptDecryptRoundTrip(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	repoKey, _ := crypto.GenerateRepoKey()

	ct, err := crypto.EncryptRepoKey(repoKey, id.PublicKey())
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	got, err := crypto.DecryptRepoKey(ct, id)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	if !bytes.Equal(got, repoKey) {
		t.Fatal("decrypted repo key does not match original")
	}
}

func TestRepoKeyWrongIdentityFails(t *testing.T) {
	idA, _ := crypto.GenerateIdentity()
	idB, _ := crypto.GenerateIdentity()
	repoKey, _ := crypto.GenerateRepoKey()

	ct, _ := crypto.EncryptRepoKey(repoKey, idA.PublicKey())
	_, err := crypto.DecryptRepoKey(ct, idB)
	if err == nil {
		t.Fatal("expected error decrypting with wrong identity, got nil")
	}
}

// ── Packfile ─────────────────────────────────────────────────────────────────

func mustEncrypt(t *testing.T, plain, key []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := crypto.EncryptPackfile(&buf, bytes.NewReader(plain), key); err != nil {
		t.Fatalf("EncryptPackfile: %v", err)
	}
	return buf.Bytes()
}

func TestPackfileRoundTrip(t *testing.T) {
	plain := []byte("package main\n\nfunc main() {}\n")
	key, _ := crypto.GenerateRepoKey()

	ct := mustEncrypt(t, plain, key)

	var got bytes.Buffer
	if err := crypto.DecryptPackfile(&got, bytes.NewReader(ct), key); err != nil {
		t.Fatal("DecryptPackfile:", err)
	}
	if !bytes.Equal(got.Bytes(), plain) {
		t.Fatalf("round trip mismatch:\n got  %q\n want %q", got.Bytes(), plain)
	}
}

func TestPackfileCiphertextNotSubstringOfPlaintext(t *testing.T) {
	plain := []byte(`package main

import "fmt"

func main() {
	secret := "my_api_key=abc123"
	fmt.Println(secret)
}
`)
	key, _ := crypto.GenerateRepoKey()
	ct := mustEncrypt(t, plain, key)

	if bytes.Contains(ct, []byte("my_api_key")) {
		t.Fatal("plaintext fragment found in ciphertext")
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("full plaintext found in ciphertext")
	}
}

func TestPackfileSamePlaintextDifferentCiphertext(t *testing.T) {
	plain := []byte("package main\n")
	key, _ := crypto.GenerateRepoKey()

	ct1 := mustEncrypt(t, plain, key)
	ct2 := mustEncrypt(t, plain, key)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("same plaintext produced identical ciphertexts (nonce reuse)")
	}
}

func TestPackfileWrongKeyFails(t *testing.T) {
	plain := []byte("secret data")
	keyA, _ := crypto.GenerateRepoKey()
	keyB, _ := crypto.GenerateRepoKey()

	ct := mustEncrypt(t, plain, keyA)
	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(ct), keyB)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestPackfileTruncatedFails(t *testing.T) {
	plain := []byte("secret data that is long enough to test truncation")
	key, _ := crypto.GenerateRepoKey()

	ct := mustEncrypt(t, plain, key)
	half := ct[:len(ct)/2]

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(half), key)
	if err == nil {
		t.Fatal("expected error on truncated ciphertext, got nil")
	}
}

func TestPackfileFlippedByteFails(t *testing.T) {
	plain := []byte("secret data for bit-flip test — long enough to cover all positions")
	key, _ := crypto.GenerateRepoKey()
	ct := mustEncrypt(t, plain, key)

	positions := []struct {
		name string
		idx  int
	}{
		{"start", 0},
		{"middle", len(ct) / 2},
		{"end", len(ct) - 1},
	}

	for _, p := range positions {
		flipped := make([]byte, len(ct))
		copy(flipped, ct)
		flipped[p.idx] ^= 0xFF

		err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(flipped), key)
		if err == nil {
			t.Errorf("position %s (byte %d): expected error, got nil", p.name, p.idx)
		}
	}
}

func TestPackfileAppendedByteFails(t *testing.T) {
	plain := []byte("secret data")
	key, _ := crypto.GenerateRepoKey()

	ct := mustEncrypt(t, plain, key)
	appended := append(ct, 0xFF)

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(appended), key)
	if err == nil {
		t.Fatal("expected error with appended byte, got nil")
	}
}

func TestPackfileLarge100MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large file test in short mode")
	}

	const size = 100 * 1024 * 1024
	plain := make([]byte, size)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	key, _ := crypto.GenerateRepoKey()

	var ct bytes.Buffer
	ct.Grow(size + 4*1024)
	if err := crypto.EncryptPackfile(&ct, bytes.NewReader(plain), key); err != nil {
		t.Fatal("encrypt:", err)
	}

	var got bytes.Buffer
	got.Grow(size)
	if err := crypto.DecryptPackfile(&got, bytes.NewReader(ct.Bytes()), key); err != nil {
		t.Fatal("decrypt:", err)
	}

	if !bytes.Equal(got.Bytes(), plain) {
		t.Fatal("100 MB round trip: bytes do not match")
	}
}
