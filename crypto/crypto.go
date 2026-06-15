package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
)

// chunkSize is the plaintext size of each encrypted chunk in a packfile.
const chunkSize = 64 * 1024 // 64 KiB

// Identity is a user's Ed25519 keypair. The same key is used both for
// signing API requests (see shared/auth) and for wrapping per-repo
// encryption keys via age's SSH-key compatibility (see docs/crypto.md).
type Identity struct {
	priv ed25519.PrivateKey
}

// GenerateIdentity creates a new Ed25519 keypair.
func GenerateIdentity() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return &Identity{priv: priv}, nil
}

// PublicKey returns the raw Ed25519 public key. Suitable for ed25519.Verify
// and for passing to EncryptRepoKey.
func (id *Identity) PublicKey() ed25519.PublicKey {
	return id.priv.Public().(ed25519.PublicKey)
}

// Signer returns the underlying private key for use with ed25519.Sign and
// shared/auth.SignRequest. The caller must not modify the returned slice.
func (id *Identity) Signer() ed25519.PrivateKey {
	return id.priv
}

// PublicKeyString returns the wire/storage encoding of the public key
// (base64-std of the 32 raw bytes).
func (id *Identity) PublicKeyString() string {
	return base64.StdEncoding.EncodeToString(id.PublicKey())
}

// PublicKeyFingerprint returns the SHA-256 of the raw Ed25519 public key as
// lowercase hex. Safe to log — the public key is not secret — and handy for a
// short, human-comparable identifier of which key is in play.
func (id *Identity) PublicKeyFingerprint() string {
	sum := sha256.Sum256(id.PublicKey())
	return hex.EncodeToString(sum[:])
}

// SaveIdentity writes id to path with permissions 0600. The on-disk format
// is the base64-std encoding of the 32-byte Ed25519 seed plus a trailing
// newline — a single short line, mirroring the old age identity file.
func SaveIdentity(path string, id *Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(id.priv.Seed())
	return os.WriteFile(path, []byte(encoded+"\n"), 0600)
}

// LoadIdentity reads an Ed25519 identity from path.
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseIdentity(string(data))
}

// ParseIdentity decodes an Ed25519 identity from its base64-std string form
// (the same format SaveIdentity writes). Whitespace around the value is
// trimmed so input pasted from a terminal works without sanitization.
//
// Used by 'gf login --recover' to accept a key from terminal input or stdin
// instead of from a file on disk.
func ParseIdentity(s string) (*Identity, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decoding identity: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity has %d-byte seed, want %d", len(seed), ed25519.SeedSize)
	}
	return &Identity{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// GenerateRepoKey returns 32 cryptographically random bytes for use as a repo encryption key.
func GenerateRepoKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// EncryptRepoKey encrypts the 32-byte repoKey to recipient using age via the
// agessh adapter. The result is safe to store on the server.
func EncryptRepoKey(repoKey []byte, recipient ed25519.PublicKey) ([]byte, error) {
	r, err := ageRecipient(recipient)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(repoKey); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptRepoKey decrypts an encrypted repo key using id's Ed25519 key.
func DecryptRepoKey(ciphertext []byte, id *Identity) ([]byte, error) {
	identity, err := agessh.NewEd25519Identity(id.priv)
	if err != nil {
		return nil, fmt.Errorf("agessh identity: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// ageRecipient wraps an Ed25519 public key as an age recipient via SSH-style
// conversion. agessh's recipient constructor requires an ssh.PublicKey, so
// we first marshal the raw Ed25519 key through golang.org/x/crypto/ssh.
func ageRecipient(pub ed25519.PublicKey) (age.Recipient, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh.NewPublicKey: %w", err)
	}
	r, err := agessh.NewEd25519Recipient(sshPub)
	if err != nil {
		return nil, fmt.Errorf("agessh recipient: %w", err)
	}
	return r, nil
}

// EncryptPackfile encrypts src to dst using XChaCha20-Poly1305 with repoKey.
//
// Wire format:
//
//	[24-byte random nonce]
//	[repeating: 4-byte LE plaintext chunk size | ciphertext+tag]
//	[4-byte LE sentinel: 0]
//
// Each chunk's nonce is derived by XOR-ing the last 8 bytes of the base nonce
// with the little-endian chunk index. The chunk index is also included as AAD
// so that reordering or truncation is detected.
func EncryptPackfile(dst io.Writer, src io.Reader, repoKey []byte) error {
	aead, err := chacha20poly1305.NewX(repoKey)
	if err != nil {
		return err
	}

	baseNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(baseNonce); err != nil {
		return err
	}
	if _, err := dst.Write(baseNonce); err != nil {
		return err
	}

	plain := make([]byte, chunkSize)
	var idx uint64

	for {
		n, readErr := io.ReadFull(src, plain)
		if n > 0 {
			nonce := chunkNonce(baseNonce, idx)
			ct := aead.Seal(nil, nonce, plain[:n], indexAAD(idx))
			if err := binary.Write(dst, binary.LittleEndian, uint32(n)); err != nil {
				return err
			}
			if _, err := dst.Write(ct); err != nil {
				return err
			}
			idx++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	return binary.Write(dst, binary.LittleEndian, uint32(0))
}

// DecryptPackfile decrypts src to dst using repoKey.
// Returns an error if the ciphertext is tampered, truncated, or has trailing bytes.
func DecryptPackfile(dst io.Writer, src io.Reader, repoKey []byte) error {
	aead, err := chacha20poly1305.NewX(repoKey)
	if err != nil {
		return err
	}

	baseNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(src, baseNonce); err != nil {
		return fmt.Errorf("reading nonce: %w", err)
	}

	var idx uint64
	for {
		var plainSize uint32
		if err := binary.Read(src, binary.LittleEndian, &plainSize); err != nil {
			return fmt.Errorf("reading chunk size: %w", err)
		}
		if plainSize == 0 {
			// Sentinel reached — verify no trailing bytes follow.
			var extra [1]byte
			if n, _ := src.Read(extra[:]); n > 0 {
				return fmt.Errorf("unexpected trailing data after stream sentinel")
			}
			return nil
		}
		if plainSize > chunkSize {
			return fmt.Errorf("chunk %d claims plaintext size %d exceeding maximum %d", idx, plainSize, chunkSize)
		}

		ct := make([]byte, int(plainSize)+aead.Overhead())
		if _, err := io.ReadFull(src, ct); err != nil {
			return fmt.Errorf("reading chunk %d: %w", idx, err)
		}

		plain, err := aead.Open(nil, chunkNonce(baseNonce, idx), ct, indexAAD(idx))
		if err != nil {
			return fmt.Errorf("decrypting chunk %d: %w", idx, err)
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
		idx++
	}
}

// chunkNonce derives a per-chunk nonce by XOR-ing the last 8 bytes of base with idx.
func chunkNonce(base []byte, idx uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(nonce, base)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], idx)
	for i := 0; i < 8; i++ {
		nonce[16+i] ^= b[i]
	}
	return nonce
}

// indexAAD encodes idx as 8-byte little-endian additional authenticated data.
func indexAAD(idx uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, idx)
	return b
}
