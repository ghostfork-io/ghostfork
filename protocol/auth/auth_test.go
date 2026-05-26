package auth_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ghostfork/gf/shared/auth"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newSignedRequest(t *testing.T, method, urlStr string, body []byte, user string, priv ed25519.PrivateKey) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		t.Fatal(err)
	}
	auth.SignRequest(req, body, user, priv)
	return req
}

// ── Encoding ─────────────────────────────────────────────────────────────────

func TestPublicKeyRoundTrip(t *testing.T) {
	pub, _ := newKey(t)
	encoded := auth.EncodePublicKey(pub)
	decoded, err := auth.DecodePublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, pub) {
		t.Fatal("decoded public key does not match original")
	}
}

func TestDecodeRejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	if _, err := auth.DecodePublicKey(short); err == nil {
		t.Fatal("expected error for short key, got nil")
	}
}

func TestDecodeRejectsNonBase64(t *testing.T) {
	if _, err := auth.DecodePublicKey("not!!!base64"); err == nil {
		t.Fatal("expected error for non-base64, got nil")
	}
}

// ── Sign / Verify happy path ─────────────────────────────────────────────────

func TestSignAndVerifyEmptyBody(t *testing.T) {
	pub, priv := newKey(t)
	req := newSignedRequest(t, http.MethodGet, "http://example/api/v1/users/alice", nil, "alice", priv)

	got, err := auth.VerifyRequest(req, nil, pub)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if got.Username != "alice" {
		t.Fatalf("username: got %q, want alice", got.Username)
	}
	if got.Nonce == "" {
		t.Fatal("expected nonce to be populated")
	}
}

func TestSignAndVerifyWithBody(t *testing.T) {
	pub, priv := newKey(t)
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, http.MethodPost, "http://example/api/v1/things", body, "alice", priv)

	if _, err := auth.VerifyRequest(req, body, pub); err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
}

// ── Prehashed signing / envelope verification ────────────────────────────────

func TestSignPrehashedRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	body := []byte("a streamed body the signer never holds in full")

	req, err := http.NewRequest(http.MethodPost, "http://example/api/v1/repos/alice/r/packfiles", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	auth.SignRequestPrehashed(req, auth.HashBody(body), "alice", priv)

	// VerifyEnvelope returns the claimed hash without ever seeing the body.
	env, err := auth.VerifyEnvelope(req, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if env.Username != "alice" {
		t.Fatalf("username: got %q, want alice", env.Username)
	}
	if env.ClaimedBodyHash != auth.HashBody(body) {
		t.Fatalf("claimed hash mismatch:\n got  %s\n want %s", env.ClaimedBodyHash, auth.HashBody(body))
	}

	// The full VerifyRequest still accepts the matching body.
	if _, err := auth.VerifyRequest(req, body, pub); err != nil {
		t.Fatalf("VerifyRequest with matching body: %v", err)
	}
}

// TestVerifyEnvelopeIgnoresBody documents the streaming contract: the envelope
// check is body-agnostic, so a caller MUST compare the actual bytes against
// ClaimedBodyHash itself before trusting the request.
func TestVerifyEnvelopeIgnoresBody(t *testing.T) {
	pub, priv := newKey(t)
	signed := []byte("the bytes the client promised to send")

	req, err := http.NewRequest(http.MethodPost, "http://example/x", bytes.NewReader([]byte("totally different bytes")))
	if err != nil {
		t.Fatal(err)
	}
	auth.SignRequestPrehashed(req, auth.HashBody(signed), "alice", priv)

	// Envelope verifies fine — it only commits to the header values.
	env, err := auth.VerifyEnvelope(req, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelope should ignore body: %v", err)
	}
	// But the full body check catches the mismatch.
	if _, err := auth.VerifyRequest(req, []byte("totally different bytes"), pub); !errors.Is(err, auth.ErrBadBodyHash) {
		t.Fatalf("expected ErrBadBodyHash for mismatched body, got %v", err)
	}
	_ = env
}

func TestVerifyEnvelopeTamperedSignatureFails(t *testing.T) {
	pub, priv := newKey(t)
	req, err := http.NewRequest(http.MethodGet, "http://example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.SignRequestPrehashed(req, auth.HashBody(nil), "alice", priv)

	req.Method = http.MethodDelete // mutate after signing
	if _, err := auth.VerifyEnvelope(req, pub); !errors.Is(err, auth.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// ── Tamper detection ─────────────────────────────────────────────────────────

func TestTamperedBodyFails(t *testing.T) {
	pub, priv := newKey(t)
	body := []byte(`{"original":"value"}`)
	req := newSignedRequest(t, http.MethodPost, "http://example/x", body, "alice", priv)

	tampered := []byte(`{"tampered":"value"}`)
	_, err := auth.VerifyRequest(req, tampered, pub)
	if !errors.Is(err, auth.ErrBadBodyHash) {
		t.Fatalf("expected ErrBadBodyHash, got %v", err)
	}
}

func TestTamperedMethodFails(t *testing.T) {
	pub, priv := newKey(t)
	req := newSignedRequest(t, http.MethodGet, "http://example/x", nil, "alice", priv)

	// Mutate after signing so the signature still references the old method.
	req.Method = http.MethodDelete
	_, err := auth.VerifyRequest(req, nil, pub)
	if !errors.Is(err, auth.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestWrongPublicKeyFails(t *testing.T) {
	_, priv := newKey(t)
	req := newSignedRequest(t, http.MethodGet, "http://example/x", nil, "alice", priv)

	otherPub, _ := newKey(t)
	_, err := auth.VerifyRequest(req, nil, otherPub)
	if !errors.Is(err, auth.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// ── Replay window ────────────────────────────────────────────────────────────

func TestStaleTimestampFails(t *testing.T) {
	pub, priv := newKey(t)
	req := newSignedRequest(t, http.MethodGet, "http://example/x", nil, "alice", priv)
	// Force the timestamp 10 minutes into the past and resign so the
	// signature commits to the old timestamp.
	old := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	nonce := req.Header.Get(auth.HeaderNonce)
	bodyHash := req.Header.Get(auth.HeaderBodyHash)
	msg := auth.Canonical(req.Method, req.URL.RequestURI(), old, nonce, bodyHash)
	sig := ed25519.Sign(priv, msg)
	req.Header.Set(auth.HeaderTimestamp, old)
	req.Header.Set(auth.HeaderSignature, base64.StdEncoding.EncodeToString(sig))

	_, err := auth.VerifyRequest(req, nil, pub)
	if !errors.Is(err, auth.ErrStaleTimestamp) {
		t.Fatalf("expected ErrStaleTimestamp, got %v", err)
	}
}

// ── Missing headers ──────────────────────────────────────────────────────────

func TestMissingSignatureHeaderFails(t *testing.T) {
	pub, priv := newKey(t)
	req := newSignedRequest(t, http.MethodGet, "http://example/x", nil, "alice", priv)
	req.Header.Del(auth.HeaderSignature)

	_, err := auth.VerifyRequest(req, nil, pub)
	if !errors.Is(err, auth.ErrMissingHeader) {
		t.Fatalf("expected ErrMissingHeader, got %v", err)
	}
}
