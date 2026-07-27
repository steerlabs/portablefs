#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--dry-run] OUTPUT_DIRECTORY [REVISION]" >&2
}

dry_run=false
if [ "${1:-}" = "--dry-run" ]; then
  dry_run=true
  shift
fi
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage; exit 2; }

output_directory="$1"
revision="${2:-HEAD}"
repo_root="$(git rev-parse --show-toplevel)"
audit_script="$repo_root/scripts/audit-public-source.sh"

output_parent="$(dirname "$output_directory")"
output_name="$(basename "$output_directory")"
if [ ! -d "$output_parent" ]; then
  echo "public-source export: output parent does not exist: $output_parent" >&2
  exit 2
fi
output_parent="$(cd "$output_parent" && pwd -P)"
output_directory="$output_parent/$output_name"

case "$output_name" in
  ""|"."|"..")
    echo "public-source export: refusing unsafe output directory" >&2
    exit 2
    ;;
esac
if [ "$output_directory" = "/" ] || [ "$output_directory" = "$repo_root" ]; then
  echo "public-source export: refusing unsafe output directory" >&2
  exit 2
fi

if [ -e "$output_directory" ]; then
  echo "public-source export: output already exists: $output_directory" >&2
  exit 2
fi

if [ "$dry_run" = false ] &&
  [ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]; then
  echo "public-source export: source worktree must be clean" >&2
  exit 1
fi

commit="$(git -C "$repo_root" rev-parse --verify "$revision^{commit}")"
"$audit_script" --revision "$commit"

if [ "$dry_run" = true ]; then
  if git -C "$repo_root" archive --format=tar "$commit" |
    tar -tf - |
    LC_ALL=C grep -E '^\.git(/|$)' >/dev/null; then
    echo "public-source export: archive unexpectedly contains Git metadata" >&2
    exit 1
  fi
  echo "public-source export: dry run ok for tracked files at $commit"
  echo "public-source export: would write to $output_directory"
  exit 0
fi

mkdir -p "$output_directory"
git -C "$repo_root" archive --format=tar "$commit" |
  tar -xf - -C "$output_directory"

if [ -e "$output_directory/.git" ]; then
  echo "public-source export: unexpected Git metadata in export" >&2
  exit 1
fi

echo "public-source export: wrote tracked files from $commit to $output_directory"
echo "public-source export: initialize a new repository there; never copy source Git metadata"
