package logging_test

import (
	"io"
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

// The CLI log file is a complete audit trail: DEBUG records land in it even
// when verbose is off (stderr stays quiet at WARN — that part is covered by
// the spec suite, which runs the real binary).
func TestNewCLIFileCapturesDebugWithoutVerbose(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "sub", "gf.log")
	t.Setenv("GHOSTFORK_LOG_FILE", "")  // isolate from the developer's shell
	t.Setenv("GHOSTFORK_LOG_LEVEL", "") // file is DEBUG regardless of level env

	lg := logging.NewCLI(false, logFile)
	lg.Debug("dbg-marker")
	lg.Error("err-marker")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	for _, want := range []string{"dbg-marker", "err-marker"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("log file missing %q; got: %q", want, data)
		}
	}

	// The log can hold sensitive detail under -v, so the file must be 0600
	// and a freshly created parent directory 0700 (mirrors the config dir).
	fi, err := os.Stat(logFile)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("log file perm = %o, want 0600", perm)
	}
	di, err := os.Stat(filepath.Dir(logFile))
	if err != nil {
		t.Fatalf("stat log dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("log dir perm = %o, want 0700", perm)
	}
}

// Records marked FileOnly reach the log file but are dropped by the stderr
// handler — used for failures that main.go already reports in friendly form.
func TestFileOnlySkipsStderrButReachesFile(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "gf.log")
	t.Setenv("GHOSTFORK_LOG_FILE", "")
	t.Setenv("GHOSTFORK_LOG_LEVEL", "")

	// NewCLI snapshots os.Stderr at build time, so swap in a pipe around it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	lg := logging.NewCLI(false, logFile)
	lg.Error("hidden-marker", logging.FileOnly())
	lg.Error("visible-marker")
	os.Stderr = oldStderr
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}

	if strings.Contains(string(captured), "hidden-marker") {
		t.Errorf("FileOnly record leaked to stderr: %q", captured)
	}
	if !strings.Contains(string(captured), "visible-marker") {
		t.Errorf("regular ERROR record missing from stderr: %q", captured)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	for _, want := range []string{"hidden-marker", "visible-marker"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("log file missing %q; got: %q", want, data)
		}
	}
}

// GHOSTFORK_LOG_FILE redirects the CLI log file away from the default path.
func TestNewCLIEnvFileOverridesPath(t *testing.T) {
	dir := t.TempDir()
	defaultPath := filepath.Join(dir, "default.log")
	envPath := filepath.Join(dir, "override.log")
	t.Setenv("GHOSTFORK_LOG_FILE", envPath)

	lg := logging.NewCLI(false, defaultPath)
	lg.Warn("override-marker")

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env log: %v", err)
	}
	if !strings.Contains(string(data), "override-marker") {
		t.Fatalf("env log missing message; got: %q", data)
	}
	if _, err := os.Stat(defaultPath); !os.IsNotExist(err) {
		t.Fatalf("default path should be untouched when env var is set; stat err: %v", err)
	}
}

// NewCLI with an empty log file path degrades to stderr-only and must not panic.
func TestNewCLINoFile(t *testing.T) {
	lg := logging.NewCLI(true, "")
	lg.Debug("no-file-marker") // must not panic or create files
}

// DebugRequested is the gate for logging sensitive values (e.g. the plaintext
// repo key): true only when the user explicitly opted in via -v or
// GHOSTFORK_LOG_LEVEL=debug. The env var overrides the flag, matching NewCLI.
func TestDebugRequested(t *testing.T) {
	cases := []struct {
		verbose bool
		env     string
		want    bool
	}{
		{false, "", false},
		{true, "", true},
		{false, "debug", true},
		{false, "info", false},
		{true, "warn", false},
	}
	for _, c := range cases {
		t.Setenv("GHOSTFORK_LOG_LEVEL", c.env)
		if got := logging.DebugRequested(c.verbose); got != c.want {
			t.Errorf("DebugRequested(verbose=%v, env=%q) = %v, want %v", c.verbose, c.env, got, c.want)
		}
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
