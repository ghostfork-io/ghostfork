package apiclient_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghostfork/gf/internal/apiclient"
)

// ── ValidateBaseURL ─────────────────────────────────────────────────────────

func TestValidateBaseURLAcceptsWellFormed(t *testing.T) {
	for _, raw := range []string{
		"http://localhost:8080",
		"https://api.example.com",
		"http://127.0.0.1:1",
		"https://api.example.com/sub/path",
	} {
		if err := apiclient.ValidateBaseURL(raw); err != nil {
			t.Errorf("ValidateBaseURL(%q) = %v, want nil", raw, err)
		}
	}
}

func TestValidateBaseURLRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"",                  // empty
		"not-a-url",         // no scheme/host
		"example.com",       // missing scheme
		"ftp://example.com", // wrong scheme
		"http://",           // missing host
		"://missing-scheme", // unparseable scheme
		"http://exa mple",   // illegal space in host
	} {
		err := apiclient.ValidateBaseURL(raw)
		if err == nil {
			t.Errorf("ValidateBaseURL(%q) = nil, want error", raw)
			continue
		}
		// Message must name the offending value so the user can fix it.
		if !strings.Contains(err.Error(), "server URL") {
			t.Errorf("ValidateBaseURL(%q) error %q does not mention %q", raw, err.Error(), "server URL")
		}
	}
}

// ── Unreachable server ──────────────────────────────────────────────────────

// A request to a port with nothing listening must fail fast with a friendly,
// classified error — never a cryptic transport string and never a hang.
func TestUnreachableServerReturnsFriendlyError(t *testing.T) {
	// 127.0.0.1:1 is effectively always closed → connection refused, instantly.
	c := apiclient.New("http://127.0.0.1:1")

	err := c.Register("alice", "irrelevant-pubkey")
	if err == nil {
		t.Fatal("expected error registering against an unreachable server, got nil")
	}

	var unreachable *apiclient.UnreachableError
	if !errors.As(err, &unreachable) {
		t.Fatalf("expected *UnreachableError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "could not reach server at http://127.0.0.1:1") {
		t.Errorf("error %q does not contain the friendly unreachable message", err.Error())
	}
}
