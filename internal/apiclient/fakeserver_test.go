package apiclient_test

// fakeServer is an in-memory implementation of the gfserver wire contract,
// just enough for apiclient's tests. The client module must stay free of any
// dependency on the private server module, so these tests exercise the
// client's HTTP wiring (signing, paths, status→error mapping, streaming)
// against this stdlib-only stand-in. The real server's behavior is covered
// end-to-end by the server module's e2e suite.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghostfork/gf/protocol/auth"
	"github.com/ghostfork/gf/protocol/types"
)

type fakeServer struct {
	URL string

	mu    sync.Mutex
	users map[string]string            // username → public key (base64-std)
	repos map[string]bool              // "owner/name"
	keys  map[string][]byte            // "owner/name/username" → encrypted repo key
	refs  map[string]map[string]string // "owner/name" → branch → SHA
	packs map[string][][]byte          // "owner/name" → blobs; seq = index+1
}

// startFake starts a fake gfserver. Automatically shut down via t.Cleanup.
func startFake(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{
		users: map[string]string{},
		repos: map[string]bool{},
		keys:  map[string][]byte{},
		refs:  map[string]map[string]string{},
		packs: map[string][][]byte{},
	}
	srv := httptest.NewServer(http.HandlerFunc(fs.handle))
	t.Cleanup(srv.Close)
	fs.URL = srv.URL
	return fs
}

func (fs *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// The one unauthenticated route.
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/users" {
		fs.register(w, body)
		return
	}

	// Everything else requires a valid signed envelope.
	caller, ok := fs.authenticate(r, body)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/users/"):
		fs.getUser(w, strings.TrimPrefix(r.URL.Path, "/api/v1/users/"))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos":
		fs.createRepo(w, caller, body)
	case strings.HasPrefix(r.URL.Path, "/api/v1/repos/"):
		fs.repoScoped(w, r, caller, body)
	default:
		http.NotFound(w, r)
	}
}

func (fs *fakeServer) register(w http.ResponseWriter, body []byte) {
	var req types.RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Username == "" || req.PublicKey == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, exists := fs.users[req.Username]; exists {
		http.Error(w, "username taken", http.StatusConflict)
		return
	}
	fs.users[req.Username] = req.PublicKey
	w.WriteHeader(http.StatusCreated)
}

// authenticate verifies the signed envelope against the caller's registered
// public key. Mirrors the production middleware's checks (sans replay cache).
func (fs *fakeServer) authenticate(r *http.Request, body []byte) (string, bool) {
	username := r.Header.Get(auth.HeaderUser)
	pubStr, exists := fs.users[username]
	if !exists {
		return "", false
	}
	pub, err := auth.DecodePublicKey(pubStr)
	if err != nil {
		return "", false
	}
	if _, err := auth.VerifyRequest(r, body, pub); err != nil {
		return "", false
	}
	return username, true
}

func (fs *fakeServer) getUser(w http.ResponseWriter, username string) {
	pub, exists := fs.users[username]
	if !exists {
		http.NotFound(w, nil)
		return
	}
	writeJSON(w, types.UserResponse{Username: username, PublicKey: pub})
}

func (fs *fakeServer) createRepo(w http.ResponseWriter, caller string, body []byte) {
	var req types.CreateRepoRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	repo := caller + "/" + req.Name
	if fs.repos[repo] {
		http.Error(w, "repo exists", http.StatusConflict)
		return
	}
	fs.repos[repo] = true
	fs.keys[repo+"/"+caller] = req.EncryptedKey
	w.WriteHeader(http.StatusCreated)
}

// repoScoped routes /api/v1/repos/{owner}/{repo}/... after a membership check.
func (fs *fakeServer) repoScoped(w http.ResponseWriter, r *http.Request, caller string, body []byte) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/repos/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	repo := parts[0] + "/" + parts[1]

	// Membership = a keys row exists for the caller, same as production.
	if _, member := fs.keys[repo+"/"+caller]; !member {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch {
	case parts[2] == "refs" && len(parts) == 3 && r.Method == http.MethodGet:
		resp := types.RefsResponse{Refs: []types.Ref{}}
		for branch, sha := range fs.refs[repo] {
			resp.Refs = append(resp.Refs, types.Ref{Branch: branch, CommitSHA: sha})
		}
		writeJSON(w, resp)

	case parts[2] == "refs" && len(parts) == 4 && r.Method == http.MethodPut:
		var req types.UpdateRefRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if fs.refs[repo] == nil {
			fs.refs[repo] = map[string]string{}
		}
		fs.refs[repo][parts[3]] = req.CommitSHA
		w.WriteHeader(http.StatusNoContent)

	case parts[2] == "packfiles" && len(parts) == 3 && r.Method == http.MethodPost:
		fs.packs[repo] = append(fs.packs[repo], body)
		writeJSON(w, types.UploadPackfileResponse{Seq: int64(len(fs.packs[repo]))})

	case parts[2] == "packfiles" && len(parts) == 3 && r.Method == http.MethodGet:
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		resp := types.PackfileListResponse{Packfiles: []types.PackfileEntry{}}
		for i := range fs.packs[repo] {
			if seq := int64(i + 1); seq > after {
				resp.Packfiles = append(resp.Packfiles, types.PackfileEntry{Seq: seq})
			}
		}
		writeJSON(w, resp)

	case parts[2] == "packfiles" && len(parts) == 4 && r.Method == http.MethodGet:
		seq, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil || seq < 1 || seq > int64(len(fs.packs[repo])) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(fs.packs[repo][seq-1]) //nolint:errcheck

	case parts[2] == "keys" && len(parts) == 4:
		fs.handleKey(w, r, repo, parts[3], body)

	default:
		http.NotFound(w, r)
	}
}

func (fs *fakeServer) handleKey(w http.ResponseWriter, r *http.Request, repo, username string, body []byte) {
	id := repo + "/" + username
	switch r.Method {
	case http.MethodGet:
		key, exists := fs.keys[id]
		if !exists {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, types.KeyResponse{EncryptedKey: key})
	case http.MethodPut:
		var req types.KeyRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fs.keys[id] = req.EncryptedKey
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if _, exists := fs.keys[id]; !exists {
			http.NotFound(w, r)
			return
		}
		delete(fs.keys, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(fmt.Sprintf("fakeserver: encoding response: %v", err))
	}
}
