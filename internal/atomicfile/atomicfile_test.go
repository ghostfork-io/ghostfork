package atomicfile_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghostfork/gf/internal/atomicfile"
)

func writeString(s string) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := io.WriteString(w, s)
		return err
	}
}

func TestWriteCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")

	if err := atomicfile.Write(path, 0600, writeString("hello")); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestWriteCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "out")

	if err := atomicfile.Write(path, 0600, writeString("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestWriteAppliesMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")

	if err := atomicfile.Write(path, 0600, writeString("x")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestWriteOverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")

	if err := atomicfile.Write(path, 0600, writeString("first")); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(path, 0600, writeString("second")); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("got %q, want %q", got, "second")
	}
}

func TestWriteLeavesNoTempFileOnSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")

	if err := atomicfile.Write(path, 0600, writeString("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file not removed after successful write")
	}
}

func TestWriteEncodeErrorLeavesExistingFileIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")

	if err := atomicfile.Write(path, 0600, writeString("original")); err != nil {
		t.Fatal(err)
	}

	encErr := errors.New("encode boom")
	err := atomicfile.Write(path, 0600, func(w io.Writer) error { return encErr })
	if !errors.Is(err, encErr) {
		t.Fatalf("want encode error %v, got %v", encErr, err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "original" {
		t.Fatalf("existing file was modified: got %q", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file not removed after encode error")
	}
}
