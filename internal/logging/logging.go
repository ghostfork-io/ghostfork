// Package logging centralises slog setup for both gfserver and the gf CLI.
//
// The server reads format/level from env vars so deployment can switch the
// handler without recompiling. The CLI uses a verbose flag to decide between
// quiet (WARN) and verbose (DEBUG) output to stderr, and additionally keeps
// a complete DEBUG-level audit trail in a log file (see NewCLI).
package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

// envFormat selects "text" (default) or "json" via GHOSTFORK_LOG_FORMAT.
const envFormat = "GHOSTFORK_LOG_FORMAT"

// envLevel sets the minimum level (debug|info|warn|error) via GHOSTFORK_LOG_LEVEL.
const envLevel = "GHOSTFORK_LOG_LEVEL"

// envFile names a file to append logs to in addition to stderr.
const envFile = "GHOSTFORK_LOG_FILE"

// envMaxSizeMB caps the active log file before it rotates. Default 50 MB.
const envMaxSizeMB = "GHOSTFORK_LOG_MAX_SIZE_MB"

// envMaxBackups limits how many rotated files lumberjack keeps. Default 5.
const envMaxBackups = "GHOSTFORK_LOG_MAX_BACKUPS"

const defaultMaxSizeMB = 50
const defaultMaxBackups = 5
const defaultMaxAgeDays = 30

// NewServer builds the logger for gfserver. Format and level are taken from
// env vars: GHOSTFORK_LOG_FORMAT (text|json, default text) and
// GHOSTFORK_LOG_LEVEL (debug|info|warn|error, default info).
//
// If logFile is non-empty (or GHOSTFORK_LOG_FILE is set), logs are written to
// both stderr and that file. The flag value wins over the env var. Rotation
// is built in via lumberjack — the file is capped at GHOSTFORK_LOG_MAX_SIZE_MB
// (default 50) and at most GHOSTFORK_LOG_MAX_BACKUPS rotated files
// (default 5) are kept, so disk usage has a hard ceiling. No external
// logrotate config is needed.
func NewServer(logFile string) (*slog.Logger, io.Closer, error) {
	if logFile == "" {
		logFile = os.Getenv(envFile)
	}

	var w io.Writer = os.Stderr
	var closer io.Closer
	if logFile != "" {
		rot := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    envIntOr(envMaxSizeMB, defaultMaxSizeMB),
			MaxBackups: envIntOr(envMaxBackups, defaultMaxBackups),
			MaxAge:     defaultMaxAgeDays,
			Compress:   false,
		}
		// Tee to stderr so interactive runs and systemd/Docker still see logs;
		// the file is a durable copy independent of the orchestrator.
		w = io.MultiWriter(os.Stderr, rot)
		closer = rot
	}

	logger := newLogger(w, envOr(envFormat, "text"), parseLevel(os.Getenv(envLevel), slog.LevelInfo))
	return logger, closer, nil
}

// NewCLI builds the logger for the gf CLI and the git remote helper.
//
// stderr: WARN when quiet, DEBUG when verbose, so user-facing stdout output
// stays clean. GHOSTFORK_LOG_LEVEL overrides the verbose flag when set, so
// `GHOSTFORK_LOG_LEVEL=debug git push` works without -v (useful when git
// invokes the helper directly and there's no flag plumbed through).
//
// logFile: every record is ALSO written to logFile at DEBUG level regardless
// of verbosity, so the file is a complete audit trail — command received,
// inputs, intermediate steps, encryption steps, outputs, and errors all land
// there even when stderr stays quiet. Pass "" to disable; GHOSTFORK_LOG_FILE
// overrides the path when set. Rotation is the same lumberjack setup as the
// server, so disk usage has a hard ceiling. The file is created 0600 (and a
// fresh parent directory 0700) because debug runs can carry sensitive detail.
//
// Because the file always records DEBUG, sensitive values (e.g. the plaintext
// repo key during init-repo) must NOT rely on the logger's level as a gate —
// callers must check DebugRequested before emitting them at all.
//
// The CLI is short-lived and slog writes synchronously, so no Closer is
// returned; the file handle is released at process exit.
func NewCLI(verbose bool, logFile string) *slog.Logger {
	defaultLevel := slog.LevelWarn
	if verbose {
		defaultLevel = slog.LevelDebug
	}
	stderrLevel := parseLevel(os.Getenv(envLevel), defaultLevel)
	format := envOr(envFormat, "text")
	stderrH := newHandler(os.Stderr, format, stderrLevel)

	if v := os.Getenv(envFile); v != "" {
		logFile = v
	}
	if logFile == "" {
		return slog.New(stderrH)
	}

	// Create the parent dir 0700 before lumberjack's own MkdirAll (which
	// would use 0755) — the log lives next to the config and can hold
	// sensitive detail, so it gets the same tight permissions. Failure is
	// deliberately ignored: a broken log path must never take the CLI down,
	// and lumberjack degrades to write errors that slog discards.
	_ = os.MkdirAll(filepath.Dir(logFile), 0700)
	rot := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    envIntOr(envMaxSizeMB, defaultMaxSizeMB),
		MaxBackups: envIntOr(envMaxBackups, defaultMaxBackups),
		MaxAge:     defaultMaxAgeDays,
		Compress:   false,
	}
	fileH := newHandler(rot, format, slog.LevelDebug)
	return slog.New(multiHandler{skipFileOnly{stderrH}, fileH})
}

// fileOnlyKey marks a record as destined for the log file only — see FileOnly.
const fileOnlyKey = "file_only"

// FileOnly marks a record so the CLI's stderr handler drops it while the log
// file still records it. Use for lines that would duplicate output the user
// already sees in friendly form — e.g. the final "command failed" line, whose
// error main.go prints as "Error: …":
//
//	slog.Error("command failed", logging.FileOnly(), slog.Any("err", err))
//
// The marker must be passed at the call site; attrs baked in via Logger.With
// are not inspected.
func FileOnly() slog.Attr { return slog.Bool(fileOnlyKey, true) }

// skipFileOnly wraps the stderr handler and drops records carrying the
// FileOnly marker.
type skipFileOnly struct{ slog.Handler }

func (s skipFileOnly) Handle(ctx context.Context, r slog.Record) error {
	fileOnly := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == fileOnlyKey && a.Value.Kind() == slog.KindBool && a.Value.Bool() {
			fileOnly = true
			return false
		}
		return true
	})
	if fileOnly {
		return nil
	}
	return s.Handler.Handle(ctx, r)
}

func (s skipFileOnly) WithAttrs(attrs []slog.Attr) slog.Handler {
	return skipFileOnly{s.Handler.WithAttrs(attrs)}
}

func (s skipFileOnly) WithGroup(name string) slog.Handler {
	return skipFileOnly{s.Handler.WithGroup(name)}
}

// DebugRequested reports whether the user explicitly opted into debug-level
// output — via the -v flag or GHOSTFORK_LOG_LEVEL=debug (the env var
// overrides the flag, matching NewCLI). Sensitive values such as the
// plaintext repo key may only be logged when this returns true; checking the
// logger's level is not enough because the CLI log file records DEBUG
// unconditionally.
func DebugRequested(verbose bool) bool {
	defaultLevel := slog.LevelWarn
	if verbose {
		defaultLevel = slog.LevelDebug
	}
	return parseLevel(os.Getenv(envLevel), defaultLevel) <= slog.LevelDebug
}

// SetDefault installs l as slog.Default so packages that use the package-level
// slog functions (apiclient, helper, api handlers) pick it up.
func SetDefault(l *slog.Logger) {
	slog.SetDefault(l)
}

func newLogger(w io.Writer, format string, level slog.Level) *slog.Logger {
	return slog.New(newHandler(w, format, level))
}

func newHandler(w io.Writer, format string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(format, "json") {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// multiHandler fans each record out to several handlers, each with its own
// level. The CLI uses it so stderr can stay quiet (WARN) while the log file
// captures everything (DEBUG).
type multiHandler []slog.Handler

func (m multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(name)
	}
	return out
}

func parseLevel(s string, def slog.Level) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return def
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
