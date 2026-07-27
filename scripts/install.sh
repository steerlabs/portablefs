#!/bin/sh
# PortableFS CLI installer.
#
#   curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh
#
# Downloads the portablefs release archive for this OS/architecture, verifies
# its sha256 against the release checksums.txt (mandatory — the install aborts
# on any mismatch), extracts the `portablefs` CLI and its `portablefsd` mount
# daemon, and installs both to /usr/local/bin when writable, otherwise
# ~/.local/bin. `portablefs mount` discovers portablefsd next to itself, so
# the two MUST land in the same directory. Nothing is written to the
# destination until every binary is fully downloaded and verified.
#
# Environment:
#   PORTABLEFS_VERSION       pin a release, e.g. v0.3.0 or 0.3.0 (default: latest)
#   PORTABLEFS_GITHUB_REPO   owner/repo to install from (default: steerlabs/portablefs)
#   PORTABLEFS_INSTALL_DIR   force the install directory
set -eu

REPO="${PORTABLEFS_GITHUB_REPO:-steerlabs/portablefs}"
BINARY=portablefs
# portablefs mount spawns/adopts this daemon and finds it as a sibling of the
# CLI, so it installs alongside portablefs into the same directory.
DAEMON=portablefsd

log() { printf '%s\n' "portablefs install: $*" >&2; }
die() { log "error: $*"; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

# --- platform -----------------------------------------------------------------
os_raw=$(uname -s)
case "$os_raw" in
  Linux) goos=linux ;;
  Darwin) goos=darwin ;;
  *) die "unsupported operating system: $os_raw (releases cover Linux and macOS)" ;;
esac

arch_raw=$(uname -m)
case "$arch_raw" in
  x86_64 | amd64) goarch=amd64 ;;
  arm64 | aarch64) goarch=arm64 ;;
  *) die "unsupported architecture: $arch_raw (releases cover amd64 and arm64)" ;;
esac

# --- version ------------------------------------------------------------------
if [ -n "${PORTABLEFS_VERSION:-}" ]; then
  tag="$PORTABLEFS_VERSION"
  case "$tag" in
    v*) ;;
    *) tag="v$tag" ;;
  esac
else
  log "resolving the latest release of $REPO"
  api_url="https://api.github.com/repos/$REPO/releases/latest"
  api_response=$(curl -fsSL --retry 3 "$api_url") ||
    die "could not query $api_url (offline, or GitHub API rate limit?); pin PORTABLEFS_VERSION=vX.Y.Z to skip the lookup"
  # Extract "tag_name": "vX.Y.Z" without jq. grep -o emits every match in
  # document order and tag_name precedes the free-form body field, so the
  # first match is the release tag even if the notes mention "tag_name".
  tag=$(printf '%s' "$api_response" | tr -d '\r' |
    grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 |
    sed 's/.*"\([^"]*\)"$/\1/')
  [ -n "$tag" ] || die "could not parse tag_name from $api_url; pin PORTABLEFS_VERSION=vX.Y.Z"
fi
version=${tag#v}

# Matches the goreleaser archives name_template:
#   {{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}
archive="${BINARY}_${version}_${goos}_${goarch}.tar.gz"
base_url="https://github.com/$REPO/releases/download/$tag"

# --- download + verify ----------------------------------------------------------
tmp=$(mktemp -d "${TMPDIR:-/tmp}/portablefs-install.XXXXXX") || die "mktemp failed"
staged=""
cleanup() {
  rm -rf "$tmp"
  if [ -n "$staged" ]; then
    rm -f "$staged"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log "downloading $archive ($tag)"
curl -fsSL --retry 3 -o "$tmp/$archive" "$base_url/$archive" ||
  die "download failed: $base_url/$archive
does release $tag publish ${goos}/${goarch} archives?"
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base_url/checksums.txt" ||
  die "download failed: $base_url/checksums.txt (refusing to install without checksum verification)"

expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
[ -n "$expected" ] || die "checksums.txt in release $tag has no entry for $archive; refusing to install"

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')
else
  die "sha256sum or shasum is required to verify the download"
fi

if [ "$actual" != "$expected" ]; then
  die "sha256 mismatch for $archive
  expected: $expected
  actual:   $actual
the download is corrupt or has been tampered with; nothing was installed"
fi
log "sha256 verified"

# The release archive bundles several binaries; extract the CLI and its mount
# daemon (the CLI resolves portablefsd as a sibling on the mount path).
tar -xzf "$tmp/$archive" -C "$tmp" "$BINARY" "$DAEMON" 2>/dev/null ||
  die "could not extract $BINARY and $DAEMON from $archive"
[ -f "$tmp/$BINARY" ] || die "$archive does not contain a $BINARY binary"
[ -f "$tmp/$DAEMON" ] || die "$archive does not contain a $DAEMON binary"
chmod 0755 "$tmp/$BINARY" "$tmp/$DAEMON"

# --- install --------------------------------------------------------------------
if [ -n "${PORTABLEFS_INSTALL_DIR:-}" ]; then
  dest="$PORTABLEFS_INSTALL_DIR"
  mkdir -p "$dest" || die "cannot create $dest"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  dest=/usr/local/bin
else
  dest="$HOME/.local/bin"
  mkdir -p "$dest" || die "cannot create $dest"
fi
[ -w "$dest" ] || die "$dest is not writable; set PORTABLEFS_INSTALL_DIR to a writable directory"

# Stage each binary inside the destination directory so its final rename is
# atomic: an interrupted install never leaves a partial binary at $dest.
install_binary() {
  _name=$1
  _staged="$dest/.$_name.tmp.$$"
  staged="$_staged"
  cp "$tmp/$_name" "$_staged" || die "copy $_name into $dest failed"
  mv -f "$_staged" "$dest/$_name" || die "install $_name into $dest failed"
  staged=""
}
install_binary "$BINARY"
install_binary "$DAEMON"

# --- smoke test + next steps -----------------------------------------------------
"$dest/$BINARY" version >/dev/null 2>&1 ||
  die "$dest/$BINARY was installed but failed its smoke test (\`$BINARY version\`)"

printf '%s\n' ""
printf '%s installed to %s\n' "$("$dest/$BINARY" version)" "$dest/$BINARY"
printf 'mount daemon installed to %s\n' "$dest/$DAEMON"

case ":$PATH:" in
  *":$dest:"*) ;;
  *)
    printf '%s\n' "" \
      "note: $dest is not in your PATH. Add it to your shell profile (~/.zshrc or ~/.bashrc):" \
      "  export PATH=\"$dest:\$PATH\""
    ;;
esac

printf '%s\n' "" "Next steps:" \
  "  portablefs login    # portablefs.com; self-hosted: portablefs login <url>" \
  "  portablefs adopt ~/code/myproject" \
  "  portablefs mount myproject ~/work"
