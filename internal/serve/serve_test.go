package serve

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/protocol/types"
)

// testToken is the pairing token startTestServer runs with. 64 hex chars,
// like a real one.
const testToken = "746573742d746f6b656e2d746573742d746f6b656e2d746573742d746f6b656e"

// testOrigin is the dashboard origin startTestServer admits via CORS.
const testOrigin = "https://gf.example.com"

// fakeRepoLister is a canned RepoLister.
type fakeRepoLister struct {
	repos []types.RepoRef
	err   error
}

func (f *fakeRepoLister) ListMyRepos() ([]types.RepoRef, error) { return f.repos, f.err }

// startTestServer binds an ephemeral loopback port and runs the server until
// the test ends, returning its base URL.
func startTestServer(t *testing.T, opt ...func(*Options)) string {
	t.Helper()
	opts := Options{
		Port:   0,
		Token:  testToken,
		Origin: testOrigin,
		Repos:  &fakeRepoLister{},
	}
	for _, o := range opt {
		o(&opts)
	}
	srv, err := Listen(opts)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned error on shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop after context cancel")
		}
	})
	return "http://" + srv.Addr()
}

// get sends a GET with an optional bearer token and returns the response.
func get(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// decodeError decodes the standard JSON error envelope.
func decodeError(t *testing.T, resp *http.Response) errorBody {
	t.Helper()
	var body errorBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding error envelope: %v", err)
	}
	return body
}

func TestListenBindsLoopbackOnly(t *testing.T) {
	srv, err := Listen(Options{Token: testToken})
	if err != nil {
		t.Fatalf("Listen(0): %v", err)
	}
	defer srv.ln.Close()

	host, _, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", srv.Addr(), err)
	}
	if host != "127.0.0.1" {
		t.Errorf("bound to %q, must be 127.0.0.1", host)
	}
}

func TestListenPortConflict(t *testing.T) {
	first, err := Listen(Options{Token: testToken})
	if err != nil {
		t.Fatalf("Listen(0): %v", err)
	}
	defer first.ln.Close()

	_, portStr, err := net.SplitHostPort(first.Addr())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", first.Addr(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}

	_, err = Listen(Options{Port: port, Token: testToken})
	if err == nil {
		t.Fatal("second Listen on the same port succeeded, want error")
	}
	if !strings.Contains(err.Error(), "--port") {
		t.Errorf("port-conflict error %q should mention --port so the user knows the fix", err)
	}
}

func TestHealthz(t *testing.T) {
	base := startTestServer(t)

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body healthzResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body.Service != "gf-serve" {
		t.Errorf("service = %q, want \"gf-serve\" (the dashboard's detection marker)", body.Service)
	}
	if body.Version == "" {
		t.Error("version is empty")
	}
}

func TestRootExplainsItself(t *testing.T) {
	base := startTestServer(t)

	resp := get(t, base+"/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "dashboard") {
		t.Errorf("root page should point a confused human at the dashboard; got:\n%s", body)
	}
	if strings.Contains(body, testToken) {
		t.Error("root page must never leak the pairing token")
	}
}

func TestUnknownPathIs404(t *testing.T) {
	base := startTestServer(t)

	resp, err := http.Get(base + "/nope")
	if err != nil {
		t.Fatalf("GET /nope: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /nope status = %d, want 404", resp.StatusCode)
	}
}

func TestHealthzRejectsPost(t *testing.T) {
	base := startTestServer(t)

	resp, err := http.Post(base+"/healthz", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz status = %d, want 405 (API is read-only)", resp.StatusCode)
	}
}

func TestV1RequiresToken(t *testing.T) {
	base := startTestServer(t)

	cases := []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"wrong token", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"truncated token", testToken[:32]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := get(t, base+"/v1/repos", tc.token)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if body := decodeError(t, resp); body.Error != "unauthorized" {
				t.Errorf("error code = %q, want \"unauthorized\"", body.Error)
			}
		})
	}
}

func TestV1WithTokenReachesRoutes(t *testing.T) {
	base := startTestServer(t)

	// A correct token must get past auth; an unknown route then yields the
	// enveloped 404, not a 401.
	resp := get(t, base+"/v1/nope", testToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (past auth, unknown route)", resp.StatusCode)
	}
	if body := decodeError(t, resp); body.Error != "not_found" {
		t.Errorf("error code = %q, want \"not_found\"", body.Error)
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	base := startTestServer(t)

	resp := get(t, base+"/healthz", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz without token = %d, want 200 (detection must work before pairing)", resp.StatusCode)
	}
}

func TestReposEndpoint(t *testing.T) {
	repos := []types.RepoRef{{Owner: "alice", Name: "app"}, {Owner: "acme", Name: "lib"}}
	base := startTestServer(t, func(o *Options) { o.Repos = &fakeRepoLister{repos: repos} })

	resp := get(t, base+"/v1/repos", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body types.MyReposResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(body.Repos) != 2 || body.Repos[0] != repos[0] || body.Repos[1] != repos[1] {
		t.Errorf("repos = %v, want %v", body.Repos, repos)
	}
}

func TestReposEndpointEmptyIsArray(t *testing.T) {
	base := startTestServer(t) // default fake returns nil

	resp := get(t, base+"/v1/repos", testToken)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(raw), `"repos":[]`) {
		t.Errorf("body = %s, want a \"repos\":[] array per the contract, not null", raw)
	}
}

func TestReposUpstreamErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"unreachable", &apiclient.UnreachableError{BaseURL: "https://x"}, http.StatusBadGateway, "upstream_unreachable"},
		{"denied 401", &apiclient.StatusError{StatusCode: 401, Body: "bad signature"}, http.StatusBadGateway, "upstream_denied"},
		{"denied 403", &apiclient.StatusError{StatusCode: 403, Body: "no access"}, http.StatusBadGateway, "upstream_denied"},
		{"server 500", &apiclient.StatusError{StatusCode: 500, Body: "boom"}, http.StatusInternalServerError, "internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := startTestServer(t, func(o *Options) { o.Repos = &fakeRepoLister{err: tc.err} })
			resp := get(t, base+"/v1/repos", testToken)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if body := decodeError(t, resp); body.Error != tc.wantCode {
				t.Errorf("error code = %q, want %q", body.Error, tc.wantCode)
			}
		})
	}
}

func TestCORS(t *testing.T) {
	base := startTestServer(t)

	t.Run("dashboard origin admitted", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, base+"/healthz", nil)
		req.Header.Set("Origin", testOrigin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != testOrigin {
			t.Errorf("Allow-Origin = %q, want %q", got, testOrigin)
		}
	})

	t.Run("foreign origin gets no CORS", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, base+"/healthz", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Allow-Origin = %q for a foreign origin, want none", got)
		}
	})

	t.Run("preflight passes without token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodOptions, base+"/v1/repos", nil)
		req.Header.Set("Origin", testOrigin)
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "authorization")
		req.Header.Set("Access-Control-Request-Private-Network", "true")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("preflight status = %d, want 204 (must be answered before token auth)", resp.StatusCode)
		}
		for header, want := range map[string]string{
			"Access-Control-Allow-Origin":          testOrigin,
			"Access-Control-Allow-Methods":         "GET",
			"Access-Control-Allow-Headers":         "Authorization",
			"Access-Control-Allow-Private-Network": "true",
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
	})
}
