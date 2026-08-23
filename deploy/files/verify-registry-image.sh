#!/usr/bin/env bash
set -euo pipefail

emit_infra_record=false
if [[ ${1:-} == --emit-infra-record ]]; then
  emit_infra_record=true
  shift
fi

[[ $# == 3 || $# == 4 ]] || {
  echo "usage: $0 [--emit-infra-record] files|release IMAGE:sha-<commit> <commit> [expected-portablefs-files@sha256:<digest>]" >&2
  exit 64
}

kind=$1
reference=$2
source_revision=$3
files_image=${4:-}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
registry=us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases

[[ $source_revision =~ ^[0-9a-f]{40}$ && $source_revision != 0000000000000000000000000000000000000000 ]] || {
  echo "source revision must be one full nonzero lowercase commit" >&2
  exit 64
}
case "$kind" in
  files)
    [[ $emit_infra_record == false && $reference == "$registry/portablefs-files:sha-$source_revision" && -z $files_image ]] || exit 64
    ;;
  release)
    [[ $reference == "$registry/portablefs-release:sha-$source_revision" ]] || exit 64
    [[ -z $files_image || $files_image =~ ^$registry/portablefs-files@sha256:[0-9a-f]{64}$ ]] || exit 64
    ;;
  *) exit 64 ;;
esac

command -v crane >/dev/null || {
  echo "the pinned crane executable is not on PATH" >&2
  exit 69
}
command -v timeout >/dev/null || {
  echo "GNU timeout is required for bounded registry verification" >&2
  exit 69
}

stage=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/portablefs-registry-verify.XXXXXXXX")
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT

registry_read() {
  timeout --kill-after=5s 120s crane "$@"
}

resolve_digest() {
  local digest_directory digest_file resolved
  digest_directory=$(mktemp -d "$stage/digest.XXXXXXXX")
  digest_file="$digest_directory/value"
  registry_read digest "$1" |
    python3 "$root/deploy/files/release_registry.py" bounded-copy \
      --output "$digest_file" --maximum 128
  resolved=$(<"$digest_file")
  [[ $resolved =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "registry did not resolve $1 to one SHA-256 digest" >&2
    return 65
  }
  printf '%s\n' "$resolved"
}

expected_digest=$(resolve_digest "$reference")

registry_read manifest "$reference" |
  python3 "$root/deploy/files/release_registry.py" bounded-copy \
    --output "$stage/root-manifest.json" --maximum 2097152
registry_read manifest --platform linux/amd64 "$reference" |
  python3 "$root/deploy/files/release_registry.py" bounded-copy \
    --output "$stage/manifest.json" --maximum 2097152
mkdir -m 0700 "$stage/blobs"
python3 "$root/deploy/files/release_registry.py" list-blob-descriptors \
  "$stage/manifest.json" >"$stage/blob-descriptors"
repository=${reference%:sha-*}
while IFS=$'\t' read -r digest size; do
  [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || exit 65
  [[ $size =~ ^[1-9][0-9]*$ ]] || exit 65
  destination="$stage/blobs/${digest#sha256:}"
  registry_read blob "$repository@$digest" |
    python3 "$root/deploy/files/release_registry.py" bounded-copy \
      --output "$destination" --maximum "$size" --exact-size "$size"
done <"$stage/blob-descriptors"

arguments=(
  --kind "$kind"
  --source "$source_revision"
  --digest "$expected_digest"
  --root-manifest "$stage/root-manifest.json"
  --manifest "$stage/manifest.json"
  --blobs "$stage/blobs"
)
if [[ $kind == release ]]; then
  registry_record="$registry/portablefs-release@$expected_digest"
  infra_record="$stage/infra-release.json"
  arguments+=(--emit-infra-record "$registry_record")
  if [[ $emit_infra_record == false ]]; then
    arguments+=(--source-root "$root")
  fi
  if [[ -n $files_image ]]; then
    arguments+=(--files-image "$files_image")
  fi
fi
if [[ $kind == release ]]; then
  timeout --kill-after=5s 300s python3 "$root/deploy/files/release_registry.py" \
    verify-remote "${arguments[@]}" >"$infra_record"
  record_files_image=$(timeout --kill-after=2s 10s python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["components"]["portablefs-files"]["image"])' \
    "$infra_record")
  record_files_digest=${record_files_image##*@}
  files_tag="$registry/portablefs-files:sha-$source_revision"
  verified_files_digest=$(
    "$root/deploy/files/verify-registry-image.sh" \
      files "$files_tag" "$source_revision"
  )
  [[ $verified_files_digest == "$record_files_digest" ]] || {
    echo "capsule-selected portablefs-files digest does not match its immutable source tag" >&2
    exit 65
  }
  final_digest=$(resolve_digest "$reference")
  [[ $final_digest == "$expected_digest" ]] || {
    echo "release source tag changed during verification" >&2
    exit 75
  }
  if [[ $emit_infra_record == true ]]; then
    cat "$infra_record"
  else
    printf '%s\n' "$expected_digest"
  fi
else
  timeout --kill-after=5s 300s python3 \
    "$root/deploy/files/release_registry.py" \
    verify-remote "${arguments[@]}" >/dev/null
  final_digest=$(resolve_digest "$reference")
  [[ $final_digest == "$expected_digest" ]] || {
    echo "portablefs-files source tag changed during verification" >&2
    exit 75
  }
  printf '%s\n' "$expected_digest"
fi
