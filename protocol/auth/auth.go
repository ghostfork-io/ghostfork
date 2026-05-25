// Package auth defines the request-signing protocol used by the Ghostfork
// client and server. Both sides build the same canonical byte string from
// the request and verify an Ed25519 signature over it.
//
// See docs/auth.md for the full specification.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// HTTP header names carrying the signed-request envelope.
const (
	HeaderUser      = "X-Gf-User"
	HeaderTimestamp = "X-Gf-Timestamp"
	HeaderNonce     = "X-Gf-Nonce"
	HeaderBodyHash  = "X-Gf-Body-SHA256"
	HeaderSignature = "X-Gf-Signature"
)

// MaxClockSkew is the symmetric window around server time during which a
// timestamp is accepted. Generous enough to absorb laptop NTP drift; tight
// enough to bound any replay attempt to a known short interval.
const MaxClockSkew = 5 * time.Minute

// NonceSize is the number of random bytes in a per-request nonce.
const NonceSize = 16

// Errors returned by Verify. The server collapses all of these into a
// generic 401 so an attacker cannot probe which check failed.
var (
	ErrMissingHeader  = errors.New("auth: missing required header")
	ErrBadTimestamp   = errors.New("auth: malformed timestamp")
	ErrStaleTimestamp = errors.New("auth: timestamp outside skew window")
	ErrBadNonce       = errors.New("auth: malformed nonce")
	ErrBadBodyHash    = errors.New("auth: malformed or mismatched body hash")
	ErrBadSignature   = errors.New("auth: invalid signature")
)

// Canonical builds the byte string that the client signs and the server
// verifies. Both sides must produce identical bytes for the signature to
// validate, so the format is fully deterministic.
//
//	METHOD \n
//	PATH-WITH-QUERY \n
//	TIMESTAMP \n
//	NONCE \n
//	BODY-SHA256-HEX
func Canonical(method, pathWithQuery, timestamp, nonce, bodyHashHex string) []byte {
	return []byte(method + "\n" + pathWithQuery + "\n" + timestamp + "\n" + nonce + "\n" + bodyHashHex)
}

// HashBody returns the lowercase hex SHA-256 of body. Empty body produces
// the hash of the empty string (e3b0c442…) — never an empty placeholder.
func HashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// EncodePublicKey returns the wire/storage encoding of an Ed25519 public key.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePublicKey parses an Ed25519 public key from its wire encoding.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// SignRequest sets the five envelope headers on req. body is the exact bytes
// that will be sent as the request body (nil for empty body). The caller is
// responsible for sending those same bytes.
func SignRequest(req *http.Request, body []byte, username string, signer ed25519.PrivateKey) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonceBytes := make([]byte, NonceSize)
	if _, err := rand.Read(nonceBytes); err != nil {
		// rand.Read on Linux only fails if the kernel CSPRNG is broken —
		// in which case nothing else this process does is trustworthy.
		panic(fmt.Sprintf("auth: crypto/rand failure: %v", err))
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	bodyHash := HashBody(body)
	msg := Canonical(req.Method, req.URL.RequestURI(), ts, nonce, bodyHash)
	sig := ed25519.Sign(signer, msg)

	req.Header.Set(HeaderUser, username)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodyHash, bodyHash)
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
}

// VerifiedRequest carries the fields the caller needs after a successful
// Verify: the claimed user (already cryptographically bound to the request)
// and the timestamp/nonce pair the caller must run through its replay cache.
type VerifiedRequest struct {
	Username  string
	Timestamp time.Time
	Nonce     string
}

// VerifyRequest checks the headers on req against body and pub. Returns the
// verified envelope on success. Caller is responsible for:
//  1. Resolving Username → public key before calling (passed in as pub).
//  2. Running (Username, Nonce) through a replay cache after a successful
//     return. VerifyRequest itself is stateless.
//
// All failures collapse to one of the package's sentinel errors; the server
// should not distinguish them in its response to the client.
func VerifyRequest(req *http.Request, body []byte, pub ed25519.PublicKey) (*VerifiedRequest, error) {
	user := req.Header.Get(HeaderUser)
	tsStr := req.Header.Get(HeaderTimestamp)
	nonce := req.Header.Get(HeaderNonce)
	bodyHashHdr := req.Header.Get(HeaderBodyHash)
	sigB64 := req.Header.Get(HeaderSignature)
	if user == "" || tsStr == "" || nonce == "" || bodyHashHdr == "" || sigB64 == "" {
		return nil, ErrMissingHeader
	}

	tsInt, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, ErrBadTimestamp
	}
	ts := time.Unix(tsInt, 0)
	if d := time.Since(ts); d > MaxClockSkew || d < -MaxClockSkew {
		return nil, ErrStaleTimestamp
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil || len(nonceBytes) != NonceSize {
		return nil, ErrBadNonce
	}

	// Verify the body hash matches what was actually received. Without this
	// check, an attacker could swap the body while the signature stays valid
	// because the signature only commits to the header value, not the body.
	if bodyHashHdr != HashBody(body) {
		return nil, ErrBadBodyHash
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}

	msg := Canonical(req.Method, req.URL.RequestURI(), tsStr, nonce, bodyHashHdr)
	if !ed25519.Verify(pub, msg, sig) {
		return nil, ErrBadSignature
	}

	return &VerifiedRequest{Username: user, Timestamp: ts, Nonce: nonce}, nil
}
