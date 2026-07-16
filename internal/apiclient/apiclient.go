package apiclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ghostfork/gf/internal/version"
	"github.com/ghostfork/gf/protocol/auth"
	"github.com/ghostfork/gf/protocol/types"
)

// jsonRequestTimeout caps short, body-buffered API calls (refs, keys, repo
// creation). It is a hard ceiling on the whole request — connect, TLS, send,
// and read — so a server that accepts a connection but never answers can't
// hang the CLI indefinitely; the call fails with a timeout instead. Packfile
// upload and download skip this timeout because they stream multi-GiB bodies —
// there is no sensible single-call ceiling for those.
const jsonRequestTimeout = 60 * time.Second

// UnreachableError reports that the server could not be contacted at all —
// connection refused, DNS failure, no route to host, or a timeout — as opposed
// to the server responding with an HTTP error status (those surface as
// "HTTP <code>: ..." errors). Its message is user-facing: callers can print it
// directly. The originating transport error is preserved via Unwrap for
// --verbose/debug output.
type UnreachableError struct {
	BaseURL string
	Timeout bool
	Err     error
}

func (e *UnreachableError) Error() string {
	if e.Timeout {
		return fmt.Sprintf(
			"could not reach server at %s — connection timed out; check the address and that the server is running, then try again",
			e.BaseURL)
	}
	return fmt.Sprintf(
		"could not reach server at %s — check the address and that the server is running, then try again",
		e.BaseURL)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// ValidateBaseURL checks that raw is a well-formed absolute http(s) URL,
// without making any network call. Commands use it to reject a malformed
// --server value up front with a clear message, rather than emitting a cryptic
// transport error (or, worse, hanging) once a request is actually sent.
func ValidateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid server URL %q: must start with http:// or https:// (e.g. https://api.example.com)", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid server URL %q: missing host (e.g. https://api.example.com)", raw)
	}
	return nil
}

// classifyTransportError converts a low-level failure from http.Client.Do into
// a user-facing UnreachableError. It is only ever called on the error Do
// returns, which for our requests is always a connection-level problem — a
// server that responds with an HTTP error status does NOT surface here (that is
// handled by the status-code checks). The timeout flag distinguishes a stalled
// connection (deadline hit) from an outright refusal/DNS failure.
func classifyTransportError(err error, baseURL string) error {
	var netErr net.Error
	timeout := errors.As(err, &netErr) && netErr.Timeout()
	if !timeout {
		timeout = errors.Is(err, context.DeadlineExceeded)
	}
	return &UnreachableError{BaseURL: baseURL, Timeout: timeout, Err: err}
}

// Client is a typed HTTP client for the gfserver API. An empty username +
// nil signer means an unauthenticated client; only Register may be called.
type Client struct {
	BaseURL  string
	username string
	signer   ed25519.PrivateKey
	// http is used for short JSON calls with a request timeout.
	http *http.Client
	// streamHTTP is used for packfile upload/download. No request timeout —
	// streaming pushes/fetches can legitimately take hours on large repos.
	streamHTTP *http.Client
}

// New creates an unauthenticated client. Only Register may be called.
func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		http:       &http.Client{Timeout: jsonRequestTimeout},
		streamHTTP: &http.Client{},
	}
}

// NewAuthenticated creates a client that signs every request as username.
func NewAuthenticated(baseURL, username string, signer ed25519.PrivateKey) *Client {
	return &Client{
		BaseURL:    baseURL,
		username:   username,
		signer:     signer,
		http:       &http.Client{Timeout: jsonRequestTimeout},
		streamHTTP: &http.Client{},
	}
}

// ── Users ────────────────────────────────────────────────────────────────────

// Register creates a new account. publicKey is the base64-std Ed25519 public
// key string (see shared/auth.EncodePublicKey). On success the server
// returns 201 Created with no body; the client persists nothing.
func (c *Client) Register(username, publicKey string) error {
	return c.doJSON(http.MethodPost, "/api/v1/users", types.RegisterRequest{
		Username:  username,
		PublicKey: publicKey,
	}, nil)
}

// GetUser fetches a user's public profile.
func (c *Client) GetUser(username string) (*types.UserResponse, error) {
	var resp types.UserResponse
	err := c.doJSON(http.MethodGet, "/api/v1/users/"+url.PathEscape(username), nil, &resp)
	return &resp, err
}

// Login authenticates a web-registered account by username + password and
// reports whether it already has a public key on file. Called on an
// unauthenticated client (the account may have no key yet). A 401 surfaces as
// an "HTTP 401: ..." error.
func (c *Client) Login(username, password string) (*types.LoginResponse, error) {
	var resp types.LoginResponse
	err := c.doJSON(http.MethodPost, "/api/v1/users/login",
		types.LoginRequest{Username: username, Password: password}, &resp)
	return &resp, err
}

// UploadPublicKey uploads the public key generated on first login for a
// web-registered account, authenticating with the account password. Called on
// an unauthenticated client. The server rejects a second upload (409), so this
// only succeeds for an account whose key is still unset.
func (c *Client) UploadPublicKey(username, password, publicKey string) error {
	return c.doJSON(http.MethodPut, "/api/v1/users/"+url.PathEscape(username)+"/pubkey",
		types.UploadPubKeyRequest{Password: password, PublicKey: publicKey}, nil)
}

// ── Repos ─────────────────────────────────────────────────────────────────────

// CreateRepo creates a new repo and registers the caller as its first member.
// The repo's owner is always the authenticated caller; the server derives it
// from the request signature. encKey is the repo's symmetric key encrypted
// with the caller's public key.
func (c *Client) CreateRepo(name string, encKey []byte) error {
	return c.doJSON(http.MethodPost, "/api/v1/repos", types.CreateRepoRequest{
		Name:         name,
		EncryptedKey: encKey,
	}, nil)
}

// ── Refs ──────────────────────────────────────────────────────────────────────

// GetRefs returns all branch→SHA refs for a repo, plus the repo's default
// branch (bare name, "" when the server has none recorded — empty repo or one
// predating default-branch support).
func (c *Client) GetRefs(owner, repo string) (refs []types.Ref, defaultBranch string, err error) {
	var resp types.RefsResponse
	err = c.doJSON(http.MethodGet, repoPath(owner, repo)+"/refs", nil, &resp)
	return resp.Refs, resp.DefaultBranch, err
}

// UpdateRef sets the tip SHA for a ref. branch is the full ref name
// (refs/heads/<branch> or refs/tags/<tag>); url.PathEscape keeps its slashes
// within a single path segment so the server receives the whole name.
func (c *Client) UpdateRef(owner, repo, branch, sha string) error {
	return c.doJSON(http.MethodPut, repoPath(owner, repo)+"/refs/"+url.PathEscape(branch),
		types.UpdateRefRequest{CommitSHA: sha}, nil)
}

// SetRefs atomically commits a push — the final phase of an all-or-nothing
// push. In one server transaction it promotes the staged packfiles (seqs) out
// of quarantine and applies every ref, or does neither, so a failed push never
// leaves only some branches set nor committed content with no ref.
func (c *Client) SetRefs(owner, repo string, refs []types.Ref, seqs []int64) error {
	return c.doJSON(http.MethodPost, repoPath(owner, repo)+"/refs",
		types.SetRefsRequest{Refs: refs, PackfileSeqs: seqs}, nil)
}

// ── Packfiles ─────────────────────────────────────────────────────────────────

// DeletePackfile removes a packfile (blob + row) by sequence number. Used to
// roll back the packfiles staged during a push that then aborted, so a failed
// push leaves no orphaned blobs against the owner's quota. Idempotent: an
// already-absent packfile is not an error.
func (c *Client) DeletePackfile(owner, repo string, seq int64) error {
	return c.doJSON(http.MethodDelete,
		repoPath(owner, repo)+"/packfiles/"+strconv.FormatInt(seq, 10), nil, nil)
}

// UploadPackfile streams an encrypted packfile to the server and returns the
// assigned sequence number. body is the encrypted packfile contents, size is
// the exact byte count (so Content-Length can be set), and bodyHashHex is the
// SHA-256 of those bytes (lowercase hex). The caller computes the hash while
// it writes the body — typically by tee-ing the encrypted stream into a temp
// file through a sha256.Hash.
//
// If the bytes sent on the wire do not match bodyHashHex the server rejects
// with 401 (returned here as a generic HTTP error).
//
// branch is the push target (e.g. "main"); it is recorded server-side for
// per-branch packfile counts. Empty means "don't attribute". It travels in the
// query string, so the request signature (which covers path+query) protects it.
func (c *Client) UploadPackfile(owner, repo, branch string, body io.Reader, size int64, bodyHashHex string) (int64, error) {
	path := repoPath(owner, repo) + "/packfiles"
	if branch != "" {
		path += "?branch=" + url.QueryEscape(branch)
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, body)
	if err != nil {
		return 0, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	c.signPrehashed(req, bodyHashHex)

	resp, err := c.doStream(req, http.MethodPost, path)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	var up types.UploadPackfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&up); err != nil {
		return 0, err
	}
	return up.Seq, nil
}

// ListPackfiles returns all sequence numbers with seq > afterSeq.
func (c *Client) ListPackfiles(owner, repo string, afterSeq int64) ([]int64, error) {
	path := repoPath(owner, repo) + "/packfiles?after=" + strconv.FormatInt(afterSeq, 10)
	var resp types.PackfileListResponse
	if err := c.doJSON(http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	seqs := make([]int64, len(resp.Packfiles))
	for i, p := range resp.Packfiles {
		seqs[i] = p.Seq
	}
	return seqs, nil
}

// PackfileSHA256 fetches the server's recorded SHA-256 (and size) of one
// stored encrypted packfile, so the caller (gf verify) can confirm a downloaded
// blob matches the server's bytes before decrypting it.
func (c *Client) PackfileSHA256(owner, repo string, seq int64) (sha256hex string, size int64, err error) {
	path := repoPath(owner, repo) + "/packfiles/" + strconv.FormatInt(seq, 10) + "/sha256"
	var resp types.PackfileHashResponse
	if err := c.doJSON(http.MethodGet, path, nil, &resp); err != nil {
		return "", 0, err
	}
	return resp.SHA256, resp.Size, nil
}

// DownloadPackfile streams one packfile's encrypted bytes. The caller MUST
// Close the returned reader. The caller is responsible for piping the bytes
// through DecryptPackfile and on into git's index-pack.
func (c *Client) DownloadPackfile(owner, repo string, seq int64) (io.ReadCloser, error) {
	path := repoPath(owner, repo) + "/packfiles/" + strconv.FormatInt(seq, 10)
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	c.signPrehashed(req, auth.HashBody(nil))

	resp, err := c.doStream(req, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	return resp.Body, nil
}

// ── Keys ──────────────────────────────────────────────────────────────────────

// GetKey fetches the encrypted repo key for username.
func (c *Client) GetKey(owner, repo, username string) ([]byte, error) {
	var resp types.KeyResponse
	err := c.doJSON(http.MethodGet, repoPath(owner, repo)+"/keys/"+url.PathEscape(username), nil, &resp)
	return resp.EncryptedKey, err
}

// PutKey stores an encrypted repo key for username.
func (c *Client) PutKey(owner, repo, username string, encKey []byte) error {
	return c.doJSON(http.MethodPut, repoPath(owner, repo)+"/keys/"+url.PathEscape(username),
		types.KeyRequest{EncryptedKey: encKey}, nil)
}

// DeleteKey removes the encrypted repo key for username (revokes access).
func (c *Client) DeleteKey(owner, repo, username string) error {
	return c.doJSON(http.MethodDelete, repoPath(owner, repo)+"/keys/"+url.PathEscape(username), nil, nil)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// doJSON performs a JSON request. If body is non-nil it is marshalled as the
// request body. If out is non-nil the response body is unmarshalled into it.
func (c *Client) doJSON(method, path string, body, out any) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyBytes = b
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bytesReader(bodyBytes))
	if err != nil {
		return err
	}
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.sign(req, bodyBytes)

	resp, err := c.do(req, method, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// sign attaches the auth envelope to req when the client has an identity.
// For unauthenticated clients (Register only) it is a no-op.
func (c *Client) sign(req *http.Request, body []byte) {
	if c.username == "" || c.signer == nil {
		return
	}
	if body == nil {
		body = []byte{}
	}
	auth.SignRequest(req, body, c.username, c.signer)
}

// signPrehashed is the streaming counterpart to sign: the caller has already
// computed the SHA-256 of the body bytes it will send. No-op when the client
// has no identity.
func (c *Client) signPrehashed(req *http.Request, bodyHashHex string) {
	if c.username == "" || c.signer == nil {
		return
	}
	auth.SignRequestPrehashed(req, bodyHashHex, c.username, c.signer)
}

// doStream is the no-timeout counterpart to do, used for packfile streams.
// It emits the same debug log line as do.
func (c *Client) doStream(req *http.Request, method, path string) (*http.Response, error) {
	req.Header.Set("User-Agent", version.UserAgent())
	start := time.Now()
	resp, err := c.streamHTTP.Do(req)
	if err != nil {
		slog.Debug("api stream request failed",
			slog.String("method", method),
			slog.String("path", path),
			slog.Any("err", err),
		)
		return nil, classifyTransportError(err, c.BaseURL)
	}
	slog.Debug("api stream request",
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status", resp.StatusCode),
		slog.Duration("latency", time.Since(start)),
		slog.String("request_id", resp.Header.Get("X-Request-ID")),
	)
	return resp, nil
}

// do executes req and emits a debug log line. The body-bytes count is taken
// from the Content-Length header so the function works for both raw and JSON
// paths without needing to thread the body size through.
func (c *Client) do(req *http.Request, method, path string) (*http.Response, error) {
	req.Header.Set("User-Agent", version.UserAgent())
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		slog.Debug("api request failed",
			slog.String("method", method),
			slog.String("path", path),
			slog.Any("err", err),
		)
		return nil, classifyTransportError(err, c.BaseURL)
	}
	slog.Debug("api request",
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status", resp.StatusCode),
		slog.Duration("latency", time.Since(start)),
		slog.String("request_id", resp.Header.Get("X-Request-ID")),
	)
	return resp, nil
}

// bytesReader returns an *bytes.Reader for non-nil data, or nil. Returning
// nil (rather than an empty reader) preserves the request's Content-Length
// behavior for empty-body requests.
func bytesReader(data []byte) io.Reader {
	if data == nil {
		return nil
	}
	return bytes.NewReader(data)
}

func repoPath(owner, repo string) string {
	return "/api/v1/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}
