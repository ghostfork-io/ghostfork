package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ghostfork/gf/shared/types"
)

// maxDownloadSize is the largest packfile blob the client will read (600 MiB,
// slightly above the server's 512 MiB limit to account for encryption overhead).
const maxDownloadSize = 600 << 20

// Client is a typed HTTP client for the gfserver API.
type Client struct {
	BaseURL string
	APIKey  string
	http    *http.Client
}

// New creates a Client. Pass an empty apiKey for unauthenticated calls (Register only).
func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// ── Users ────────────────────────────────────────────────────────────────────

// Register creates a new account and returns the issued API key.
func (c *Client) Register(username, publicKey string) (string, error) {
	var resp types.RegisterResponse
	err := c.doJSON(http.MethodPost, "/api/v1/users", "", types.RegisterRequest{
		Username:  username,
		PublicKey: publicKey,
	}, &resp)
	return resp.APIKey, err
}

// GetUser fetches a user's public profile.
func (c *Client) GetUser(username string) (*types.UserResponse, error) {
	var resp types.UserResponse
	err := c.doJSON(http.MethodGet, "/api/v1/users/"+url.PathEscape(username), c.APIKey, nil, &resp)
	return &resp, err
}

// ── Repos ─────────────────────────────────────────────────────────────────────

// CreateRepo creates a new repo and registers the caller as its first member.
// The repo's owner is always the authenticated caller; the server derives it
// from the API key. encKey is the repo's symmetric key encrypted with the
// caller's public key.
func (c *Client) CreateRepo(name string, encKey []byte) error {
	return c.doJSON(http.MethodPost, "/api/v1/repos", c.APIKey, types.CreateRepoRequest{
		Name:         name,
		EncryptedKey: encKey,
	}, nil)
}

// ── Refs ──────────────────────────────────────────────────────────────────────

// GetRefs returns all branch→SHA refs for a repo.
func (c *Client) GetRefs(owner, repo string) ([]types.Ref, error) {
	var resp types.RefsResponse
	err := c.doJSON(http.MethodGet, repoPath(owner, repo)+"/refs", c.APIKey, nil, &resp)
	return resp.Refs, err
}

// UpdateRef sets the tip SHA for a branch.
func (c *Client) UpdateRef(owner, repo, branch, sha string) error {
	return c.doJSON(http.MethodPut, repoPath(owner, repo)+"/refs/"+url.PathEscape(branch), c.APIKey,
		types.UpdateRefRequest{CommitSHA: sha}, nil)
}

// ── Packfiles ─────────────────────────────────────────────────────────────────

// UploadPackfile stores an encrypted packfile blob and returns its sequence number.
func (c *Client) UploadPackfile(owner, repo string, data []byte) (int64, error) {
	resp, err := c.doRaw(http.MethodPost, repoPath(owner, repo)+"/packfiles", c.APIKey, data)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
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
	if err := c.doJSON(http.MethodGet, path, c.APIKey, nil, &resp); err != nil {
		return nil, err
	}
	seqs := make([]int64, len(resp.Packfiles))
	for i, p := range resp.Packfiles {
		seqs[i] = p.Seq
	}
	return seqs, nil
}

// DownloadPackfile fetches the raw bytes of one packfile by sequence number.
func (c *Client) DownloadPackfile(owner, repo string, seq int64) ([]byte, error) {
	path := repoPath(owner, repo) + "/packfiles/" + strconv.FormatInt(seq, 10)
	resp, err := c.doRaw(http.MethodGet, path, c.APIKey, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, maxDownloadSize))
}

// ── Keys ──────────────────────────────────────────────────────────────────────

// GetKey fetches the encrypted repo key for username.
func (c *Client) GetKey(owner, repo, username string) ([]byte, error) {
	var resp types.KeyResponse
	err := c.doJSON(http.MethodGet, repoPath(owner, repo)+"/keys/"+url.PathEscape(username), c.APIKey, nil, &resp)
	return resp.EncryptedKey, err
}

// PutKey stores an encrypted repo key for username.
func (c *Client) PutKey(owner, repo, username string, encKey []byte) error {
	return c.doJSON(http.MethodPut, repoPath(owner, repo)+"/keys/"+url.PathEscape(username), c.APIKey,
		types.KeyRequest{EncryptedKey: encKey}, nil)
}

// DeleteKey removes the encrypted repo key for username (revokes access).
func (c *Client) DeleteKey(owner, repo, username string) error {
	return c.doJSON(http.MethodDelete, repoPath(owner, repo)+"/keys/"+url.PathEscape(username), c.APIKey, nil, nil)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// doJSON performs a JSON request. If body is non-nil it is marshalled as the
// request body. If out is non-nil the response body is unmarshalled into it.
func (c *Client) doJSON(method, path, apiKey string, body, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := c.http.Do(req)
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

// doRaw performs a request with a raw octet-stream body and returns the response
// for the caller to read. The caller is responsible for closing resp.Body.
// Non-2xx responses are returned as errors.
func (c *Client) doRaw(method, path, apiKey string, data []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if data != nil {
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	return resp, nil
}

func repoPath(owner, repo string) string {
	return "/api/v1/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}
