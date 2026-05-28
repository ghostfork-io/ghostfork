package logging_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghostfork/gf/internal/logging"
)

// NewServer with a log file path writes log lines into that file.
func TestNewServerWritesToFile(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "server.log")

	lg, closer, err := logging.NewServer(logFile)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer closer.Close() //nolint:errcheck

	lg.Info("hello", slog.String("k", "v"))

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Fatalf("log file missing message; got: %q", data)
	}
}

// Once total bytes written exceeds GHOSTFORK_LOG_MAX_SIZE_MB, at least one
// rotated backup file appears alongside the active log.
func TestNewServerRotatesAtMaxSize(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "server.log")

	t.Setenv("GHOSTFORK_LOG_MAX_SIZE_MB", "1")
	t.Setenv("GHOSTFORK_LOG_MAX_BACKUPS", "2")

	lg, closer, err := logging.NewServer(logFile)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// ~3 MB of payload — crosses the 1 MB rotation boundary at least twice.
	payload := strings.Repeat("x", 1000)
	for range 3000 {
		lg.Info("filler", slog.String("data", payload))
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var rotated []string
	for _, e := range entries {
		name := e.Name()
		// lumberjack names backups like server-2026-...-utc.log
		if strings.HasPrefix(name, "server-") && strings.HasSuffix(name, ".log") {
			rotated = append(rotated, name)
		}
	}
	if len(rotated) == 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected at least one rotated backup; got files: %v", names)
	}
}
