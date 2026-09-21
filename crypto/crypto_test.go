package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// ── Packfile: multi-chunk framing ────────────────────────────────────────────
//
// Every tamper test above runs on a payload that fits in a single 64 KiB
// chunk, so they only ever exercise the AEAD tag. The wire format's other
// promise — that the per-chunk nonce derivation and the index AAD make
// reordering, dropping and duplicating chunks detectable — needs a plaintext
// spanning several chunks to test at all.

const (
	nonceLen = 24 // chacha20poly1305.NonceSizeX
	tagLen   = 16 // Poly1305 tag
)

// multiChunkPlaintext returns n chunks' worth of random bytes, plus a short
// tail so the final chunk is partial (the common real-world shape).
func multiChunkPlaintext(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n*crypto.ChunkSize+7)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// splitChunks decomposes a packfile ciphertext into its wire pieces: the
// 24-byte base nonce, each framed chunk ([4-byte LE plaintext size][ct+tag]),
// and the 4-byte zero sentinel. Tests rebuild a stream from these pieces to
// simulate a malicious server reordering or removing chunks.
func splitChunks(t *testing.T, ct []byte) (nonce []byte, chunks [][]byte, sentinel []byte) {
	t.Helper()
	if len(ct) < nonceLen+4 {
		t.Fatalf("ciphertext too short to be a packfile: %d bytes", len(ct))
	}
	nonce = ct[:nonceLen]
	for off := nonceLen; ; {
		if off+4 > len(ct) {
			t.Fatal("ran past the end of the ciphertext without finding the sentinel")
		}
		size := binary.LittleEndian.Uint32(ct[off:])
		if size == 0 {
			// Trailer is the 4-byte sentinel plus the 16-byte terminator seal.
			// It must be carried along, not dropped: a rebuilt stream that ends
			// at the bare sentinel is the pre-terminator format, and would be
			// rejected as legacy rather than for the reason under test.
			if off+4+tagLen != len(ct) {
				t.Fatalf("expected the sentinel to be followed by a %d-byte terminator and nothing else; "+
					"%d bytes remain after offset %d", tagLen, len(ct)-off-4, off)
			}
			return nonce, chunks, ct[off:]
		}
		end := off + 4 + int(size) + tagLen
		if end > len(ct) {
			t.Fatalf("chunk at offset %d claims %d plaintext bytes, which runs past the end", off, size)
		}
		chunks = append(chunks, ct[off:end])
		off = end
	}
}

// joinChunks reassembles what splitChunks took apart, trailer included.
func joinChunks(nonce []byte, chunks [][]byte, trailer []byte) []byte {
	out := append([]byte(nil), nonce...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return append(out, trailer...)
}

// assertNotLegacy guards every manipulation test below against passing for the
// wrong reason. Each one rebuilds a stream and expects a specific rejection; if
// the rebuild accidentally dropped the terminator the decryptor would refuse it
// as legacy instead, and the test would still "pass" while proving nothing.
func assertNotLegacy(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, crypto.ErrLegacyPackfile) {
		t.Fatalf("stream was rejected as legacy format, not for the reason under test: %v", err)
	}
}

func TestPackfileMultiChunkRoundTrip(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()

	// Sizes chosen around the chunk boundary, where off-by-one framing bugs live.
	sizes := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"one byte", 1},
		{"exactly one chunk", crypto.ChunkSize},
		{"one chunk plus a byte", crypto.ChunkSize + 1},
		{"exactly two chunks", 2 * crypto.ChunkSize},
		{"three chunks and a tail", 3*crypto.ChunkSize + 7},
	}

	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			plain := make([]byte, s.n)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}

			var got bytes.Buffer
			if err := crypto.DecryptPackfile(&got, bytes.NewReader(mustEncrypt(t, plain, key)), key); err != nil {
				t.Fatalf("DecryptPackfile: %v", err)
			}
			if !bytes.Equal(got.Bytes(), plain) {
				t.Fatalf("round trip mismatch at %d bytes: got %d bytes back", s.n, got.Len())
			}
		})
	}
}

// TestPackfileSwappedChunksFail is the test the index-AAD exists for: a server
// that hands back the same chunks in a different order must not produce
// plaintext. Without the per-chunk index bound into the nonce and the AAD,
// every chunk would decrypt fine and git would receive a scrambled packfile.
func TestPackfileSwappedChunksFail(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()
	plain := multiChunkPlaintext(t, 3)

	nonce, chunks, trailer := splitChunks(t, mustEncrypt(t, plain, key))
	if len(chunks) < 3 {
		t.Fatalf("expected at least 3 chunks, got %d", len(chunks))
	}
	chunks[0], chunks[1] = chunks[1], chunks[0]

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(joinChunks(nonce, chunks, trailer)), key)
	if err == nil {
		t.Fatal("expected an error decrypting reordered chunks, got nil")
	}
	assertNotLegacy(t, err)
}

// TestPackfileDroppedChunkFails covers a server silently deleting a chunk from
// the middle of the stream. Every surviving chunk is authentic, so only the
// index binding can catch it.
func TestPackfileDroppedChunkFails(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()
	plain := multiChunkPlaintext(t, 3)

	nonce, chunks, trailer := splitChunks(t, mustEncrypt(t, plain, key))
	if len(chunks) < 3 {
		t.Fatalf("expected at least 3 chunks, got %d", len(chunks))
	}
	without := append(append([][]byte{}, chunks[0]), chunks[2:]...)

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(joinChunks(nonce, without, trailer)), key)
	if err == nil {
		t.Fatal("expected an error after a chunk was dropped, got nil")
	}
	assertNotLegacy(t, err)
}

// TestPackfileDuplicatedChunkFails covers a replayed chunk — authentic bytes
// presented twice, which would corrupt the packfile if accepted.
func TestPackfileDuplicatedChunkFails(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()
	plain := multiChunkPlaintext(t, 2)

	nonce, chunks, trailer := splitChunks(t, mustEncrypt(t, plain, key))
	if len(chunks) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(chunks))
	}
	dup := append([][]byte{chunks[0], chunks[0]}, chunks[1:]...)

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(joinChunks(nonce, dup, trailer)), key)
	if err == nil {
		t.Fatal("expected an error on a duplicated chunk, got nil")
	}
	assertNotLegacy(t, err)
}

// TestPackfileTruncatedAtChunkBoundaryFails is the dangerous form of
// truncation: the attacker cuts whole chunks off the end, keeping the real
// trailer, so the stream is structurally perfect and every remaining chunk
// still sits at its original index — every derived nonce and every index AAD
// still matches, and every chunk tag verifies. The byte-halving truncation test
// above cannot catch this, because chopping mid-tag fails for a much weaker
// reason.
//
// The index AAD alone does not stop this, which is why the terminator exists:
// it is sealed at the index one past the final data chunk, so the chunk count
// is authenticated. The trailer kept here is bound to the original length and
// cannot authenticate at the shortened one.
//
// Note this is a layer of defence, not the only one — UnpackEncrypted pipes
// plaintext into `git index-pack --stdin`, which verifies the pack's own
// trailing SHA-1. But git's check is not what the threat model rests on, so the
// crypto layer has to stand on its own.
func TestPackfileTruncatedAtChunkBoundaryFails(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()
	plain := multiChunkPlaintext(t, 3)

	nonce, chunks, trailer := splitChunks(t, mustEncrypt(t, plain, key))
	if len(chunks) < 3 {
		t.Fatalf("expected at least 3 chunks, got %d", len(chunks))
	}

	// Cut one chunk, then two — a single surviving chunk must be no more
	// acceptable than a nearly-complete stream.
	for _, keep := range []int{len(chunks) - 1, 1} {
		short := joinChunks(nonce, chunks[:keep], trailer)

		var got bytes.Buffer
		err := crypto.DecryptPackfile(&got, bytes.NewReader(short), key)
		if err == nil {
			t.Fatalf("truncating the stream to %d of %d chunks decrypted cleanly to %d bytes — "+
				"a malicious server can silently drop the tail of a push",
				keep, len(chunks), got.Len())
		}
		assertNotLegacy(t, err)
	}
}

// TestPackfileTerminatorFromAnotherStreamRejected closes the obvious dodge once
// the chunk count is authenticated: splice in a terminator that *is* sealed at
// the shortened length, taken from a genuine shorter packfile. It only
// authenticates under its own base nonce, so it cannot be transplanted.
func TestPackfileTerminatorFromAnotherStreamRejected(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()

	long := multiChunkPlaintext(t, 3)
	nonce, chunks, _ := splitChunks(t, mustEncrypt(t, long, key))

	// A genuine 2-chunk stream under the same key: its trailer is sealed at
	// exactly the index the truncated stream would need.
	short := multiChunkPlaintext(t, 2)
	_, shortChunks, shortTrailer := splitChunks(t, mustEncrypt(t, short, key))
	if len(chunks) < 3 || len(shortChunks) < 2 {
		t.Fatalf("expected 3 and 2 chunks, got %d and %d", len(chunks), len(shortChunks))
	}

	forged := joinChunks(nonce, chunks[:len(shortChunks)], shortTrailer)

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(forged), key)
	if err == nil {
		t.Fatal("a terminator lifted from a different stream was accepted")
	}
	assertNotLegacy(t, err)
}

// TestPackfileTamperedTerminatorRejected: flipping any byte of the terminator
// must break it, the same as flipping a byte of a chunk.
func TestPackfileTamperedTerminatorRejected(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()

	nonce, chunks, trailer := splitChunks(t, mustEncrypt(t, multiChunkPlaintext(t, 2), key))

	for i := 4; i < len(trailer); i++ { // skip the 4-byte sentinel, hit the seal
		bad := append([]byte(nil), trailer...)
		bad[i] ^= 0xFF

		err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(joinChunks(nonce, chunks, bad)), key)
		if err == nil {
			t.Fatalf("flipping terminator byte %d still decrypted cleanly", i)
		}
		assertNotLegacy(t, err)
	}
}

// TestPackfileLegacyStreamRefused covers the migration edge. A stream in the
// pre-terminator format ends at the bare sentinel — indistinguishable from one
// a server truncated and stripped. Accepting it would be a downgrade that
// reopens the hole, so it must be refused, with an error a user can act on.
func TestPackfileLegacyStreamRefused(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()

	nonce, chunks, trailer := splitChunks(t, mustEncrypt(t, multiChunkPlaintext(t, 2), key))
	legacy := joinChunks(nonce, chunks, trailer[:4]) // sentinel only, no terminator

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(legacy), key)
	if !errors.Is(err, crypto.ErrLegacyPackfile) {
		t.Fatalf("expected ErrLegacyPackfile for a terminator-less stream, got %v", err)
	}
}

// TestPackfileOversizedChunkHeaderRejected forges a chunk header claiming more
// plaintext than a chunk can hold. The guard exists so a hostile header cannot
// drive a huge allocation before any authentication happens.
func TestPackfileOversizedChunkHeaderRejected(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()

	nonce, chunks, trailer := splitChunks(t, mustEncrypt(t, []byte("small"), key))
	forged := append([]byte(nil), chunks[0]...)
	binary.LittleEndian.PutUint32(forged, uint32(crypto.ChunkSize)+1)

	err := crypto.DecryptPackfile(io.Discard, bytes.NewReader(joinChunks(nonce, [][]byte{forged}, trailer)), key)
	if err == nil {
		t.Fatal("expected an error for a chunk header exceeding the maximum chunk size, got nil")
	}
	if !strings.Contains(err.Error(), "exceeding maximum") {
		t.Fatalf("expected the oversize guard to reject this before reading, got: %v", err)
	}
}

// TestPackfileIdenticalChunksGetDistinctCiphertext guards the per-chunk nonce
// derivation. Identical plaintext chunks under one key must still encrypt to
// different bytes; if they did not, the base nonce would be reused across
// chunks and the server could spot repeated content inside a single packfile.
func TestPackfileIdenticalChunksGetDistinctCiphertext(t *testing.T) {
	key, _ := crypto.GenerateRepoKey()

	// Three chunks of the same repeated byte — identical plaintext throughout.
	plain := bytes.Repeat([]byte{0xAB}, 3*crypto.ChunkSize)

	_, chunks, _ := splitChunks(t, mustEncrypt(t, plain, key))
	if len(chunks) < 3 {
		t.Fatalf("expected at least 3 chunks, got %d", len(chunks))
	}
	for i := range chunks {
		for j := i + 1; j < len(chunks); j++ {
			if bytes.Equal(chunks[i], chunks[j]) {
				t.Fatalf("chunks %d and %d are byte-identical — the per-chunk nonce is not varying", i, j)
			}
		}
	}
}
