package apiclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// timeoutErr is a synthetic net.Error that reports Timeout() == true, so we can
// exercise the timeout branch of classifyTransportError without waiting on a
// real network timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestClassifyTransportErrorRefused(t *testing.T) {
	// A typical connection-refused error is NOT a timeout.
	raw := &url.Error{Op: "Post", URL: "http://127.0.0.1:1", Err: errors.New("connect: connection refused")}

	got := classifyTransportError(raw, "http://127.0.0.1:1")

	var ue *UnreachableError
	if !errors.As(got, &ue) {
		t.Fatalf("expected *UnreachableError, got %T", got)
	}
	if ue.Timeout {
		t.Error("connection refused must not be classified as a timeout")
	}
	if !strings.Contains(got.Error(), "could not reach server at http://127.0.0.1:1") {
		t.Errorf("unexpected message: %q", got.Error())
	}
	// The original cause must remain retrievable for --verbose/debug.
	if !errors.Is(got, raw) {
		t.Error("classified error must Unwrap to the original transport error")
	}
}

func TestClassifyTransportErrorTimeout(t *testing.T) {
	// net.Error with Timeout()==true (e.g. dial/TLS deadline) → timeout branch.
	raw := &url.Error{Op: "Get", URL: "http://10.255.255.1", Err: timeoutErr{}}
	var _ net.Error = timeoutErr{} // compile-time: timeoutErr satisfies net.Error

	got := classifyTransportError(raw, "http://10.255.255.1")

	var ue *UnreachableError
	if !errors.As(got, &ue) {
		t.Fatalf("expected *UnreachableError, got %T", got)
	}
	if !ue.Timeout {
		t.Error("a net.Error reporting Timeout() must be classified as a timeout")
	}
	if !strings.Contains(strings.ToLower(got.Error()), "timed out") {
		t.Errorf("timeout message should mention a timeout, got %q", got.Error())
	}
}

func TestClassifyTransportErrorContextDeadline(t *testing.T) {
	// http.Client.Timeout surfaces as a context deadline wrapped in *url.Error.
	raw := fmt.Errorf("Get %q: %w", "http://example.com", context.DeadlineExceeded)

	got := classifyTransportError(raw, "http://example.com")

	var ue *UnreachableError
	if !errors.As(got, &ue) || !ue.Timeout {
		t.Fatalf("context.DeadlineExceeded must classify as a timeout UnreachableError, got %v (%T)", got, got)
	}
}

// Guard the contract that http.Client.Timeout caps a JSON call, so a dead but
// silent server can't hang the CLI forever.
func TestJSONRequestTimeoutIsBounded(t *testing.T) {
	if jsonRequestTimeout <= 0 || jsonRequestTimeout > 2*time.Minute {
		t.Fatalf("jsonRequestTimeout = %v, want a small positive bound", jsonRequestTimeout)
	}
}
