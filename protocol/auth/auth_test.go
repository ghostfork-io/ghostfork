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
