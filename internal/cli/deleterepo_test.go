package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestConfirmDeleteRepo covers the type-the-name guard that protects the
// irreversible delete: only an exact match of the bare repo name (whitespace
// trimmed) confirms; anything else — including a wrong name, the owner/repo
// form, or empty input — cancels.
func TestConfirmDeleteRepo(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"exact match", "my-project\n", true},
		{"trailing spaces trimmed", "  my-project  \n", true},
		{"wrong name", "other\n", false},
		{"owner/repo form is not the bare name", "alice/my-project\n", false},
		{"empty line", "\n", false},
		{"eof no input", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetIn(strings.NewReader(tc.input))
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})

			got, err := confirmDeleteVault(cmd, "alice", "my-project")
			if err != nil {
				t.Fatalf("confirmDeleteVault: %v", err)
			}
			if got != tc.want {
				t.Fatalf("confirmDeleteVault(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
