// Package serve implements the local read-only HTTP server behind `gf serve`.
// The web dashboard's repo browser talks to it over loopback to display
// decrypted repo data; see docs/gf-serve-api.md for the API contract this
// package implements.
package serve

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/version"
	"github.com/ghostfork/gf/protocol/types"
)

// DefaultPort is the port `gf serve` listens on unless --port overrides it
// (see docs/gf-serve-api.md).
const DefaultPort = 7777

// shutdownTimeout caps how long a graceful shutdown waits for in-flight
// requests before the process exits anyway.
const shutdownTimeout = 5 * time.Second

// Server is a bound-but-not-yet-serving local HTTP server. Listen binds the
// port (so port conflicts surface before any "listening" output), Serve runs
// it until the context is cancelled.
type Server struct {
	ln      net.Listener
	httpSrv *http.Server
}

// RepoLister is the slice of the API client the repos endpoint needs; tests
// substitute a fake.
type RepoLister interface {
	ListMyRepos() ([]types.RepoRef, error)
}

// Options configures the local server.
type Options struct {
	// Port to bind on 127.0.0.1; 0 selects a free ephemeral port (tests).
	Port int
	// Token is the pairing token every /v1 request must present (see
	// LoadOrCreateToken); only /healthz is served without it.
	Token string
	// Origin is the dashboard's web origin (scheme://host[:port] of the
	// configured server), the only origin CORS admits. See Origin().
	Origin string
	// Repos answers the /v1/repos listing.
	Repos RepoLister
}

// Origin derives the dashboard origin CORS must admit from the configured
// server base URL: its scheme://host, dropping any path.
func Origin(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("cannot derive dashboard origin from server URL %q", serverURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// Listen binds 127.0.0.1:opts.Port. The loopback address is a hard security
// requirement, not a default: this server hands out decrypted repo data and
// must never be reachable from the network, so there is deliberately no way
// to bind any other interface. Addr reports the actual address (relevant for
// ephemeral ports).
func Listen(opts Options) (*Server, error) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot listen on %s (is another gf serve or other program using the port? use --port to pick a different one): %w",
			addr, err)
	}
	return &Server{
		ln: ln,
		httpSrv: &http.Server{
			Handler:           newHandler(opts),
			ReadHeaderTimeout: 10 * time.Second,
		},
	}, nil
}

// Addr returns the address the server is bound to, e.g. "127.0.0.1:7777".
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Serve blocks until ctx is cancelled (Ctrl+C in the CLI) or the server fails,
// then shuts down gracefully, letting in-flight requests finish up to
// shutdownTimeout. Returns nil on a clean context-driven stop.
func (s *Server) Serve(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() { errc <- s.httpSrv.Serve(s.ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.httpSrv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("shutting down: %w", err)
		}
		<-errc // http.ErrServerClosed, once Serve has returned
		return nil
	case err := <-errc:
		return err
	}
}

func newHandler(opts Options) http.Handler {
	// Data routes register on v1 and are only reachable with the pairing
	// token; /healthz stays open so the dashboard can detect the helper
	// before pairing. New endpoints must go on v1, never on mux, so they
	// are born behind auth.
	v1 := http.NewServeMux()
	v1.HandleFunc("/", handleV1NotFound)
	v1.HandleFunc("GET /v1/repos", handleRepos(opts.Repos))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleRoot)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("/v1/", requireToken(opts.Token, v1))
	// CORS wraps everything: /healthz needs the headers for pre-pairing
	// detection, and preflights (which carry no Authorization header) must be
	// answered before token auth.
	return logRequests(cors(opts.Origin, mux))
}

// ── Repos ────────────────────────────────────────────────────────────────────

func handleRepos(lister RepoLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if lister == nil {
			writeError(w, http.StatusInternalServerError, "internal", "repo listing is not wired up")
			return
		}
		repos, err := lister.ListMyRepos()
		if err != nil {
			writeUpstreamError(w, "listing repos", err)
			return
		}
		if repos == nil {
			repos = []types.RepoRef{} // contract: "repos" is always an array
		}
		writeJSON(w, http.StatusOK, types.MyReposResponse{Repos: repos})
	}
}

// ── Errors ───────────────────────────────────────────────────────────────────

// errorBody is the JSON error envelope every non-2xx /v1 response carries:
// a stable machine-readable code the dashboard switches on, plus a message
// safe to display verbatim. Codes are listed in docs/gf-serve-api.md.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}

// writeUpstreamError maps a failed call to the gf server onto the contract's
// error codes: could-not-contact → upstream_unreachable, an upstream 401/403
// (the server rejecting the helper's signed request) → upstream_denied,
// anything else → internal. doing names the attempted operation for the
// message ("listing repos", …).
func writeUpstreamError(w http.ResponseWriter, doing string, err error) {
	var unreachable *apiclient.UnreachableError
	if errors.As(err, &unreachable) {
		writeError(w, http.StatusBadGateway, "upstream_unreachable",
			doing+" failed: "+unreachable.Error())
		return
	}
	var status *apiclient.StatusError
	if errors.As(err, &status) &&
		(status.StatusCode == http.StatusUnauthorized || status.StatusCode == http.StatusForbidden) {
		writeError(w, http.StatusBadGateway, "upstream_denied",
			doing+" failed: the server rejected this machine's credentials — try 'gf login' again")
		return
	}
	// Details go to the helper log; the browser gets a generic message.
	slog.Error("serve upstream error", slog.String("doing", doing), slog.Any("err", err))
	writeError(w, http.StatusInternalServerError, "internal", doing+" failed unexpectedly")
}

// ── CORS ─────────────────────────────────────────────────────────────────────

// cors admits exactly one origin — the dashboard's (the gf server's web
// origin) — and answers its preflights. Never a wildcard: the response body
// is decrypted repo data, and the pairing token in the Authorization header
// is what preflights ask permission for. The Private-Network-Access header
// answers Chrome's extra preflight for public-page → loopback requests.
func cors(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		if o := r.Header.Get("Origin"); o != "" && o == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			// Preflights carry no Authorization header, so they must be
			// answered here, before token auth would 401 them.
			w.Header().Set("Access-Control-Allow-Methods", "GET")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
				w.Header().Set("Access-Control-Allow-Private-Network", "true")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleV1NotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not_found",
		fmt.Sprintf("no such API route: %s %s", r.Method, r.URL.Path))
}

// ── Auth ─────────────────────────────────────────────────────────────────────

// requireToken rejects any request that doesn't present the pairing token as
// "Authorization: Bearer <token>". Loopback binding alone is not auth — any
// local process or any web page open in the browser can reach 127.0.0.1 —
// so every data route sits behind this check. Comparison is constant-time.
func requireToken(token string, next http.Handler) http.Handler {
	expected := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), expected) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized",
				"missing or invalid pairing token — paste the token printed by 'gf serve' into the dashboard")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleRoot answers a human opening http://127.0.0.1:<port>/ in a browser.
// It exists purely to explain what this port is — the API itself is JSON
// under /v1 and unusable from an address bar (no way to attach the pairing
// token). It must never include the token or any repo data.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, `gf serve %s

This is the Ghostfork local helper API. It has no pages to browse — the
Ghostfork web dashboard talks to it to display your decrypted repos, and
authenticates with the pairing token printed when 'gf serve' started.

Open the dashboard on your Ghostfork server and it will connect here.
API contract: docs/gf-serve-api.md in the Ghostfork repo.
`, version.String())
}

// healthzResponse is the body of GET /healthz. Service is a fixed marker the
// dashboard checks so an unrelated local server on the same port isn't
// mistaken for the helper.
type healthzResponse struct {
	Service string `json:"service"`
	Version string `json:"version"`
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(healthzResponse{
		Service: "gf-serve",
		Version: version.String(),
	})
}

// logRequests writes one debug line per request to the shared gf log, the
// same audit trail every other gf operation feeds.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Debug("serve request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Duration("latency", time.Since(start)),
		)
	})
}
