// Package logging centralises slog setup for both gfserver and the gf CLI.
//
// The server reads format/level from env vars so deployment can switch the
// handler without recompiling. The CLI uses a verbose flag to decide between
// quiet (WARN) and verbose (DEBUG) output to stderr.
package logging

import (
	"io"
	"log/slog"
	"os"
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

// NewCLI builds the logger for the gf CLI. When verbose is true the level is
// DEBUG; otherwise WARN. The CLI writes to stderr so user-facing stdout output
// stays clean. GHOSTFORK_LOG_LEVEL overrides the verbose flag when set, so
// `GHOSTFORK_LOG_LEVEL=debug gf push` works without -v (useful when git
// invokes the helper directly and there's no flag plumbed through).
func NewCLI(verbose bool) *slog.Logger {
	defaultLevel := slog.LevelWarn
	if verbose {
		defaultLevel = slog.LevelDebug
	}
	level := parseLevel(os.Getenv(envLevel), defaultLevel)
	return newLogger(os.Stderr, envOr(envFormat, "text"), level)
}

// SetDefault installs l as slog.Default so packages that use the package-level
// slog functions (apiclient, helper, api handlers) pick it up.
func SetDefault(l *slog.Logger) {
	slog.SetDefault(l)
}

func newLogger(w io.Writer, format string, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
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
