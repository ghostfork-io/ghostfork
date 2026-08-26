#!/bin/sh
# Ghostfork gf installer for macOS and Linux.
#
#   curl -sSL https://ghostfork.io/install.sh | sh
#
# Downloads the prebuilt gf binary for this machine from GitHub Releases,
# verifies it against the release's SHA256SUMS, installs it alongside the
# git-remote-gf helper Git needs for gf:// remotes, and puts the install
# directory on PATH.
#
# Re-running upgrades in place — that is the supported upgrade path, since
# there is no `gf upgrade` command.
#
# Environment overrides:
#   GF_VERSION       release tag to install (default: the latest release)
#   GF_INSTALL_DIR   where to put the binaries (default: ~/.local/bin)
#   GF_BASE_URL      base URL to fetch assets from (default: GitHub Releases;
#                    used by the test suite to run offline)
#   NO_MODIFY_PATH   set to anything to leave shell rc files alone
#
# POSIX sh on purpose: this runs under whatever /bin/sh is (dash on Debian and
# Ubuntu), so nothing here may assume bash. Everything lives inside main() and
# is invoked on the last line, so a download truncated mid-transfer can never
# execute a partial script.

set -eu

REPO="ghostfork-io/ghostfork"
# Written verbatim into the user's shell rc, and matched by `make uninstall`.
# Keep it byte-identical to the marker in the Makefile's install target.
PATH_MARKER="# added by ghostfork gf installer"

say() { printf '%s\n' "$*"; }
err() {
	printf 'gf install: %s\n' "$*" >&2
	exit 1
}

# have reports whether a command exists.
have() { command -v "$1" >/dev/null 2>&1; }

# fetch downloads $1 to $2 using whichever downloader is present. Failure to
# fetch is fatal — a partial or missing file must never reach the install step.
fetch() {
	url=$1
	dest=$2
	if have curl; then
		curl -fsSL -o "$dest" "$url" || err "could not download $url"
	elif have wget; then
		wget -qO "$dest" "$url" || err "could not download $url"
	else
		err "need curl or wget to download gf, found neither"
	fi
}

# sha256_of prints the SHA-256 of $1 as bare lowercase hex. Linux ships
# sha256sum; macOS ships shasum. Both print "<hash>  <file>".
sha256_of() {
	if have sha256sum; then
		sha256sum "$1" | cut -d' ' -f1
	elif have shasum; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		err "need sha256sum or shasum to verify the download, found neither"
	fi
}

# detect_target echoes the release asset name for this machine, or exits with a
# message naming what IS available. Deliberately explicit rather than falling
# back to another architecture: an amd64 binary does not run on arm64 Linux,
# and silently installing one would fail later and more confusingly.
detect_target() {
	os=$(uname -s)
	arch=$(uname -m)

	case "$os" in
	Darwin) os_part=darwin ;;
	Linux) os_part=linux ;;
	*) err "unsupported operating system: $os (gf ships for macOS and Linux; Windows uses install.ps1)" ;;
	esac

	case "$arch" in
	x86_64 | amd64) arch_part=amd64 ;;
	arm64 | aarch64) arch_part=arm64 ;;
	*) err "unsupported architecture: $arch (gf ships for x86_64 and arm64)" ;;
	esac

	printf 'gf-%s-%s\n' "$os_part" "$arch_part"
}

# installed_version prints the version of an existing gf at $1, or nothing.
# Any failure is ignored: a corrupt or foreign-arch binary must not stop an
# upgrade that is about to replace it anyway.
installed_version() {
	[ -x "$1" ] || return 0
	"$1" --version 2>/dev/null | head -n1 || true
}

# add_to_path appends the install dir to the user's shell rc, matching the
# Makefile's install target exactly: same marker, same rc selection, same
# idempotence. The written block is the marker followed by EXACTLY one line,
# which is the shape `make uninstall` knows how to remove.
add_to_path() {
	bindir=$1

	case ":$PATH:" in
	*":$bindir:"*)
		say "$bindir is already on \$PATH — ready to use"
		return 0
		;;
	esac

	line="export PATH=\"$bindir:\$PATH\""

	if [ -n "${NO_MODIFY_PATH:-}" ]; then
		say ""
		say "warning: $bindir is not on \$PATH. Add to your shell rc:"
		say "  $line"
		return 0
	fi

	case "$(basename "${SHELL:-/bin/sh}")" in
	zsh) rcs="$HOME/.zshrc" ;;
	bash)
		if [ "$(uname)" = Darwin ]; then
			rcs="$HOME/.bash_profile $HOME/.bashrc"
		else
			rcs="$HOME/.bashrc"
		fi
		;;
	*) rcs="$HOME/.profile" ;;
	esac

	added=0
	for rc in $rcs; do
		if [ -f "$rc" ] && grep -qF "$PATH_MARKER" "$rc"; then
			added=1
			continue
		fi
		if printf '\n%s\n%s\n' "$PATH_MARKER" "$line" >>"$rc" 2>/dev/null; then
			say "added $bindir to \$PATH in $rc"
			added=1
		fi
	done

	if [ "$added" = 1 ]; then
		say "open a new terminal, or run now:  $line"
	else
		say "warning: could not update a shell rc; add manually:"
		say "  $line"
	fi
}

main() {
	asset=$(detect_target)
	version=${GF_VERSION:-}
	bindir=${GF_INSTALL_DIR:-$HOME/.local/bin}

	if [ -n "${GF_BASE_URL:-}" ]; then
		base=$GF_BASE_URL
	elif [ -n "$version" ]; then
		base="https://github.com/$REPO/releases/download/$version"
	else
		# GitHub's own "latest" redirect. Using it instead of the API keeps the
		# installer off the 60-requests-per-hour unauthenticated API limit,
		# which a whole office behind one NAT would otherwise share.
		base="https://github.com/$REPO/releases/latest/download"
	fi

	say "Ghostfork gf installer"
	say "  platform:  $(uname -s) $(uname -m) → $asset"
	say "  release:   ${version:-latest}"
	say "  target:    $bindir"
	say ""

	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t gf-install)
	# staged sits NEXT TO the final binary so the last step is a same-directory
	# rename; see the install step below. Cleared by the same trap as $tmp.
	staged="$bindir/.gf.install.$$"
	# Cleanup on every exit path, including the error paths above.
	trap 'rm -rf "$tmp"; rm -f "$staged"' EXIT INT TERM

	say "downloading $asset…"
	fetch "$base/$asset" "$tmp/gf"
	fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"

	# Verify before anything is written outside the temp dir. SHA256SUMS covers
	# every asset in the release; we check only the one we fetched.
	expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1 || true)
	[ -n "$expected" ] || err "$asset is not listed in SHA256SUMS for this release"
	actual=$(sha256_of "$tmp/gf")
	if [ "$expected" != "$actual" ]; then
		err "checksum mismatch for $asset
  expected $expected
  actual   $actual
Nothing was installed. Retry, and if it persists please report it."
	fi
	say "checksum verified (sha256 ${actual%"${actual#????????}"}…)"

	previous=$(installed_version "$bindir/gf")

	mkdir -p "$bindir" || err "could not create $bindir"

	# Land the binary in two steps: copy into the target DIRECTORY under a
	# temp name, then rename. $tmp is usually on another filesystem, so moving
	# straight to $bindir/gf would be a copy-then-unlink — and an install
	# interrupted partway through that copy leaves a truncated gf on the user's
	# PATH. A same-directory rename is atomic, so gf is either the old build or
	# the new one, never half of one. A running gf keeps its open inode either
	# way.
	cp "$tmp/gf" "$staged" || err "could not write to $bindir"
	chmod +x "$staged"
	mv -f "$staged" "$bindir/gf" || err "could not write $bindir/gf"

	# Git runs `git-remote-gf` for gf:// URLs; the binary detects the name it
	# was invoked as and switches into remote-helper mode.
	ln -sf "$bindir/gf" "$bindir/git-remote-gf" || err "could not link $bindir/git-remote-gf"

	current=$(installed_version "$bindir/gf")
	say ""
	if [ -n "$previous" ] && [ "$previous" != "$current" ]; then
		say "upgraded:  $previous"
		say "       →   $current"
	else
		say "installed: ${current:-gf}"
	fi
	say "           $bindir/gf"
	say "           $bindir/git-remote-gf"
	say ""

	add_to_path "$bindir"

	say ""
	say "Next:  gf login --server <url> --username <name>"
	say "Docs:  https://github.com/$REPO#readme"
}

main "$@"
