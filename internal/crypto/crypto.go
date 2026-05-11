package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

// chunkSize is the plaintext size of each encrypted chunk in a packfile.
const chunkSize = 64 * 1024 // 64 KiB

// GenerateIdentity creates a new age X25519 keypair.
func GenerateIdentity() (*age.X25519Identity, error) {
	return age.GenerateX25519Identity()
}

// SaveIdentity writes id to path with permissions 0600.
// The parent directory is created if it does not exist.
func SaveIdentity(path string, id *age.X25519Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(id.String()+"\n"), 0600)
}

// LoadIdentity reads an age X25519 identity from path.
func LoadIdentity(path string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.TrimSpace(string(data)))
}

// GenerateRepoKey returns 32 cryptographically random bytes for use as a repo encryption key.
func GenerateRepoKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// EncryptRepoKey encrypts the 32-byte repoKey for recipient using age X25519.
// The result is safe to store on the server.
func EncryptRepoKey(repoKey []byte, recipient *age.X25519Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
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

// DecryptRepoKey decrypts an encrypted repo key using the given age identity.
func DecryptRepoKey(ciphertext []byte, id *age.X25519Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
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
