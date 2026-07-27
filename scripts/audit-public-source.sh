#!/usr/bin/env bash
set -euo pipefail

# Fail closed when a public source tree, ref name, or Git object contains a
# protected product marker. The default marker is assembled so this scanner
# does not match its own source.
default_forbidden_regex='open''steer'
forbidden_regex="$default_forbidden_regex"
if [ -n "${PORTABLEFS_PUBLIC_FORBIDDEN_REGEX:-}" ]; then
  forbidden_regex="$forbidden_regex|(${PORTABLEFS_PUBLIC_FORBIDDEN_REGEX})"
fi
revision=""
scan_all_objects=false

usage() {
  echo "Usage: $0 [--revision REV] [--all-objects] [--forbid ERE]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --revision)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      revision="$2"
      shift 2
      ;;
    --all-objects)
      scan_all_objects=true
      shift
      ;;
    --forbid)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      forbidden_regex="$forbidden_regex|($2)"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

set +e
printf '' | LC_ALL=C grep -Eq "$forbidden_regex"
regex_check_status=$?
set -e
if [ "$regex_check_status" -eq 2 ]; then
  echo "public-source audit: invalid forbidden-marker regular expression" >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

failures=0
object_inventory=""

cleanup() {
  if [ -n "$object_inventory" ]; then
    rm -f -- "$object_inventory"
  fi
}
trap cleanup EXIT

scan_paths() {
  if [ -n "$revision" ]; then
    if git ls-tree -r --name-only "$revision" |
      LC_ALL=C grep -Ei "$forbidden_regex" >/dev/null; then
      echo "public-source audit: forbidden marker found in a path at $revision" >&2
      failures=$((failures + 1))
    fi
  elif git ls-files --cached --others --exclude-standard |
    LC_ALL=C grep -Ei "$forbidden_regex" >/dev/null; then
    echo "public-source audit: forbidden marker found in a tracked or untracked path" >&2
    failures=$((failures + 1))
  fi
}

scan_tree_content() {
  local matches file
  if [ -n "$revision" ]; then
    matches="$(git grep -a -i -l -E "$forbidden_regex" "$revision" -- . || true)"
  else
    matches="$(git grep -a -i -l -E "$forbidden_regex" -- . || true)"
    while IFS= read -r -d '' file; do
      if [ -L "$file" ]; then
        if readlink -- "$file" | LC_ALL=C grep -aEi "$forbidden_regex" >/dev/null; then
          matches="${matches}${matches:+$'\n'}$file"
        fi
      elif [ -f "$file" ] &&
        LC_ALL=C grep -aEiq "$forbidden_regex" -- "$file"; then
        matches="${matches}${matches:+$'\n'}$file"
      fi
    done < <(git ls-files -z --others --exclude-standard)
  fi
  if [ -n "$matches" ]; then
    echo "public-source audit: forbidden marker found in source content:" >&2
    printf '%s\n' "$matches" >&2
    failures=$((failures + 1))
  fi
}

scan_object_database() {
  local object_id object_type
  object_inventory="$(mktemp)"
  git cat-file --batch-all-objects \
    --batch-check='%(objectname) %(objecttype)' >"$object_inventory"

  while IFS=' ' read -r object_id object_type; do
    if git cat-file "$object_type" "$object_id" |
      LC_ALL=C grep -aEi "$forbidden_regex" >/dev/null; then
      echo "public-source audit: forbidden marker in Git object $object_id ($object_type)" >&2
      failures=$((failures + 1))
    fi
  done <"$object_inventory"

  if git for-each-ref --format='%(refname)' |
    LC_ALL=C grep -Ei "$forbidden_regex" >/dev/null; then
    echo "public-source audit: forbidden marker found in a ref name" >&2
    failures=$((failures + 1))
  fi
}

scan_paths
scan_tree_content
if [ "$scan_all_objects" = true ]; then
  scan_object_database
fi

if [ "$failures" -ne 0 ]; then
  echo "public-source audit: FAILED ($failures contaminated surfaces)" >&2
  exit 1
fi

scope="worktree tracked and untracked files"
if [ -n "$revision" ]; then
  scope="tracked tree at $revision"
fi
if [ "$scan_all_objects" = true ]; then
  scope="$scope, refs, and complete object database"
fi
echo "public-source audit: ok ($scope)"
