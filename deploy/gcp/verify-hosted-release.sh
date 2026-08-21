#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 && $1 == /* && -d $1 ]] || {
  echo "usage: $0 /absolute/hosted-release-directory" >&2
  exit 64
}
stage=$1

expected=(
  architecture
  bin/portablefs
  bin/portablefs-archiver
  bin/portablefs-authority
  bin/portablefs-cell-agent
  bin/portablefs-hydrator
  bin/portablefs-manager
  libexec/portablefs-authority-launcher
  libexec/portablefs-cell-helper
  release-id
  source-commit
  systemd/portablefs-authority@.service
  systemd/portablefs-authority@.socket
  systemd/portablefs-archiver@.service
  systemd/portablefs-cell-agent@.service
  systemd/portablefs-cell-helper@.service
  systemd/portablefs-hydrator@.service
  systemd/portablefs-manager.service
)
mapfile -t expected_sorted < <(printf '%s\n' "${expected[@]}" | LC_ALL=C sort)

for relative in "${expected_sorted[@]}" SHA256SUMS; do
  [[ -f $stage/$relative && ! -L $stage/$relative ]] || {
    echo "missing or unsafe hosted release member: $relative" >&2
    exit 66
  }
  mode=$(stat -c %a "$stage/$relative")
  permissions=$((8#$mode))
  (( (permissions & 18) == 0 )) || {
    echo "hosted release member is writable by group/other: $relative" >&2
    exit 65
  }
done

mapfile -t actual < <(cd "$stage" && find architecture bin libexec release-id source-commit systemd -type f -print | LC_ALL=C sort)
(( ${#actual[@]} == ${#expected_sorted[@]} )) || {
  echo "hosted release membership count is not exact" >&2
  exit 65
}
for index in "${!expected_sorted[@]}"; do
  [[ ${actual[$index]} == "${expected_sorted[$index]}" ]] || {
    echo "hosted release membership differs at ${actual[$index]}" >&2
    exit 65
  }
done

release_id=$(<"$stage/release-id")
source_commit=$(<"$stage/source-commit")
architecture=$(<"$stage/architecture")
[[ $release_id =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ && $source_commit =~ ^[0-9a-f]{40}$ && $release_id == *-"${source_commit:0:12}" ]] || {
  echo "hosted release identity is invalid" >&2
  exit 65
}
case "$(uname -m):$architecture" in
  x86_64:amd64|aarch64:arm64) ;;
  *) echo "hosted release architecture $architecture does not match $(uname -m)" >&2; exit 65 ;;
esac

manifest_members=$(awk '{print $2}' "$stage/SHA256SUMS")
[[ $manifest_members == "$(printf '%s\n' "${expected_sorted[@]}")" ]] || {
  echo "hosted release checksum membership is not exact" >&2
  exit 65
}
(cd "$stage" && sha256sum --check --strict SHA256SUMS >/dev/null)

# Every released binary must agree about its own release identity AND carry
# Go's VCS stamp naming the recorded source commit of an unmodified tree.
#
# The stamp is not decoration. `scripts/build-hosted-linux-release.sh` builds
# with `-buildvcs=true`, but when it is invoked from a linked git worktree (a
# `.git` FILE holding `gitdir: .../worktrees/NAME`, not a `.git` directory)
# Go's VCS support degrades silently and stamps NOTHING, producing a
# provenance-stripped artifact that every other check here still accepts. An
# absent stamp is therefore the failure this gate exists to catch and is never
# tolerated as "not applicable".
#
# `go version -m` is the authoritative reader and is used whenever a toolchain
# is on PATH, which is how CI verifies (it runs actions/setup-go before
# building). It reads the binary rather than executing it, so a cross-built
# linux/amd64 release verifies from any host. Release hosts run this same
# script out of the deploy tarball as root and have no Go installed, so the
# fallback reads the identical settings straight out of the embedded
# runtime/debug build-info blob. Neither path is allowed to return nothing.
tab=$'\t'
go_toolchain=$(command -v go || true)
vcs_build_setting() {
  local binary=$1 key=$2 raw=
  if [[ -n $go_toolchain ]]; then
    raw=$("$go_toolchain" version -m "$binary" 2>/dev/null | sed -n "s/^${tab}build${tab}${key}=//p") || true
  else
    raw=$(LC_ALL=C grep -a -o "build${tab}${key}=[!-~]*" "$binary" | sed "s/^build${tab}${key}=//") || true
  fi
  printf '%s\n' "${raw%%$'\n'*}"
}

for relative in \
  bin/portablefs \
  bin/portablefs-archiver \
  bin/portablefs-authority \
  bin/portablefs-cell-agent \
  bin/portablefs-hydrator \
  bin/portablefs-manager \
  libexec/portablefs-authority-launcher \
  libexec/portablefs-cell-helper; do
  case "$relative" in
    bin/portablefs) reported_identity=$("$stage/$relative" version); expected_identity="portablefs $release_id" ;;
    *) reported_identity=$("$stage/$relative" -version); expected_identity=$release_id ;;
  esac
  [[ $reported_identity == "$expected_identity" ]] || {
    echo "hosted binary release identity mismatch: $relative" >&2
    exit 65
  }

  revision=$(vcs_build_setting "$stage/$relative" vcs.revision)
  [[ -n $revision ]] || {
    echo "hosted binary carries no build vcs.revision stamp: $relative (found none, expected vcs.revision=$source_commit; -buildvcs stamping is silently dropped when the release is built from a linked git worktree or with -buildvcs=false)" >&2
    exit 65
  }
  [[ $revision == "$source_commit" ]] || {
    echo "hosted binary vcs.revision does not name the release source commit: $relative (found vcs.revision=$revision, expected vcs.revision=$source_commit)" >&2
    exit 65
  }

  modified=$(vcs_build_setting "$stage/$relative" vcs.modified)
  [[ $modified == false ]] || {
    echo "hosted binary is not stamped as built from a clean tree: $relative (found vcs.modified=${modified:-none}, expected vcs.modified=false)" >&2
    exit 65
  }
done

for unit in "$stage"/systemd/*.service; do
  grep -Fq '/opt/portablefs/current/' "$unit" || {
    echo "hosted unit does not execute through the atomic release root: ${unit##*/}" >&2
    exit 65
  }
done

# The authority listens on a loopback admin socket in addition to its UNIX
# socket, so its sandbox must permit exactly AF_UNIX, AF_INET, and AF_INET6.
# The line is asserted whole and exact rather than by substring: a release that
# narrowed, widened, or dropped the directive would otherwise ship a sandbox
# that silently disagrees with the contract the units in-tree encode.
authority_unit=$stage/systemd/portablefs-authority@.service
grep -Fxq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' "$authority_unit" || {
  echo "hosted authority unit does not carry the exact address-family sandbox: expected 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', found '$(grep -F 'RestrictAddressFamilies=' "$authority_unit" || echo none)'" >&2
  exit 65
}

echo "$release_id"
