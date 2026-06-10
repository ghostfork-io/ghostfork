package apiclient_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/version"
)

// Every request must carry the versioned User-Agent so server logs can
// correlate behaviour to a specific client build. We assert it on both
// request paths: short JSON calls (do) and packfile streams (doStream).

func TestJSONRequestsCarryVersionedUserAgent(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	if err := apiclient.New(ts.URL).Register("alice", "pub"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got != version.UserAgent() {
		t.Errorf("User-Agent = %q, want %q", got, version.UserAgent())
	}
	if !strings.HasPrefix(got, "gf/") {
		t.Errorf("User-Agent %q should start with %q", got, "gf/")
	}
}

func TestStreamingRequestsCarryVersionedUserAgent(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("encrypted-packfile-bytes"))
	}))
	defer ts.Close()

	rc, err := apiclient.New(ts.URL).DownloadPackfile("alice", "repo", 1)
	if err != nil {
		t.Fatalf("DownloadPackfile: %v", err)
	}
	rc.Close()

	if got != version.UserAgent() {
		t.Errorf("User-Agent = %q, want %q", got, version.UserAgent())
	}
}
