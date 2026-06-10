# Build identity injected into the binary. The semver version is a constant
# baked into the source (internal/version); only the commit is injected here.
# COMMIT is the short SHA, falling back to "unknown" outside a git repo. DIRTY
# appends "-dirty" when the tracked working tree has uncommitted changes — and
# is empty (never "-dirty") when we're not in a repo at all.
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIRTY  := $(shell git rev-parse --git-dir >/dev/null 2>&1 && { git diff-index --quiet HEAD -- 2>/dev/null || echo -dirty; })
LDFLAGS  = -ldflags "-X github.com/ghostfork/gf/internal/version.Commit=$(COMMIT)$(DIRTY) -s -w"
BINDIR   = $(CURDIR)/bin

# Standalone Makefile for the gf client module (github.com/ghostfork/gf).
# This module is self-contained — everything here works from inside client/
# with no reference to the rest of the repo, and keeps working unchanged if
# this directory is ever published as its own repository.

.PHONY: all build build-all test test-short clean install uninstall

all: build

# ── Local build (current platform) ──────────────────────────────────────────

build:
	@mkdir -p $(BINDIR)
	go build $(LDFLAGS) -o $(BINDIR)/gf ./cmd/gf

# ── Cross-platform builds ────────────────────────────────────────────────────

build-all: build-darwin-arm64 build-darwin-amd64 build-linux-amd64 build-windows-amd64

build-darwin-arm64:
	@mkdir -p $(BINDIR)
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(BINDIR)/gf-darwin-arm64 ./cmd/gf

build-darwin-amd64:
	@mkdir -p $(BINDIR)
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(BINDIR)/gf-darwin-amd64 ./cmd/gf

build-linux-amd64:
	@mkdir -p $(BINDIR)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(BINDIR)/gf-linux-amd64 ./cmd/gf

build-windows-amd64:
	@mkdir -p $(BINDIR)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINDIR)/gf-windows-amd64.exe ./cmd/gf

# ── Tests ────────────────────────────────────────────────────────────────────
# No external services needed — client tests run against in-memory fakes.

test:
	go test -v ./...

test-short:
	go test -short -v ./...

# ── Install (Unix only) ──────────────────────────────────────────────────────
# Installs to $(PREFIX)/bin. Defaults to ~/.local/bin so `make install` works
# without sudo and respects XDG conventions. Override for a system-wide
# install:  sudo make install PREFIX=/usr/local

PREFIX ?= $(HOME)/.local

install: build
	@mkdir -p $(PREFIX)/bin
	install -m 0755 $(BINDIR)/gf $(PREFIX)/bin/gf
	ln -sf $(PREFIX)/bin/gf $(PREFIX)/bin/git-remote-gf
	@echo "installed gf to $(PREFIX)/bin"
	@case ":$$PATH:" in \
	  *":$(PREFIX)/bin:"*) ;; \
	  *) echo "warning: $(PREFIX)/bin is not in \$$PATH. Add to your shell rc:"; \
	     echo "  export PATH=\"$(PREFIX)/bin:\$$PATH\"";; \
	esac

# Fully undoes `make install`: removes the gf binary and the git-remote-gf
# symlink from $(PREFIX)/bin and reports each path removed. Use the same
# PREFIX you installed with (e.g. sudo make uninstall PREFIX=/usr/local).
# User config (~/.config/gf) is intentionally left alone — it is created by
# `gf login`, not by install, and holds your irreplaceable identity key.
uninstall:
	@removed=0; \
	for f in $(PREFIX)/bin/gf $(PREFIX)/bin/git-remote-gf; do \
	  if [ -e "$$f" ] || [ -L "$$f" ]; then \
	    rm -f "$$f" && echo "removed $$f"; \
	    removed=1; \
	  fi; \
	done; \
	if [ "$$removed" = "0" ]; then \
	  echo "nothing to uninstall — no gf files found in $(PREFIX)/bin"; \
	else \
	  echo "gf uninstalled from $(PREFIX)/bin"; \
	fi

# ── Clean ────────────────────────────────────────────────────────────────────

# Removes build output (client/bin). Source code and configs are never touched.
clean:
	@if [ -e bin ]; then rm -rf bin && echo "removed bin"; else echo "already clean"; fi
