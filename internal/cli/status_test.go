package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/config"
)

func TestStatusLoggedIn(t *testing.T) {
	setupGFDir(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveIdentity(config.DefaultIdentityPath(), id); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(config.DefaultPath(), &config.Config{
		Username: "alice", ServerURL: "http://localhost:4640",
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	if err := runStatus(cmd, nil); err != nil {
		t.Fatalf("status: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Logged in as alice",
		"http://localhost:4640",
		"key fingerprint",
		id.PublicKeyFingerprint(),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got: %q", want, out)
		}
	}
}

func TestStatusNotLoggedIn(t *testing.T) {
	setupGFDir(t) // fresh temp gf dir, no config/identity written

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	err := runStatus(cmd, nil)
	if !errors.Is(err, ErrSilent) {
		t.Errorf("want ErrSilent when not logged in, got %v", err)
	}
	if !strings.Contains(buf.String(), "Not logged in") {
		t.Errorf("want a 'Not logged in' message; got: %q", buf.String())
	}
}
