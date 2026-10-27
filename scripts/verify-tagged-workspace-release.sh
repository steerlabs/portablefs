#!/usr/bin/env bash
# Read-only qualification of the exact draft release; never install/register it.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
assets="$1"
version="$(cat "$repo/VERSION")"
test "${GITHUB_REF_NAME:?}" = "v$version"
test "$(git -C "$repo" rev-parse HEAD)" = "${GITHUB_SHA:?}"
python3 - "$assets" "$version" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1]); v=sys.argv[2]
expected={'checksums.txt','workspace.attestation.jsonl','macos.attestation.jsonl',
 'workspace-manifest.json','workspace-source-manifest.json','workspace-distribution.json','workspace-reproducibility.json',
 f'portablefs-workspace_{v}_linux_arm64.tar.gz',f'portablefs-workspace_{v}_source.tar.gz',
 f'portablefs_{v}_darwin_universal_app.zip',f'portablefs_{v}_darwin_universal_app.zip.sha256',f'portablefs_{v}_darwin_universal_app.zip.space.json'}
for prefix in ('portablefs','portablefs-server'):
 for arch in ('amd64','arm64'):
  archive=f'{prefix}_{v}_linux_{arch}.tar.gz'
  expected.update((archive,archive+'.attestation.jsonl'))
assert {p.name for p in root.iterdir()}==expected, 'draft release membership differs from the exact installer/source asset inventory'
assert all(p.is_file() and not p.is_symlink() for p in root.iterdir())
PY
for asset in "$assets"/portablefs-workspace_*.tar.gz "$assets"/workspace-*.json; do
  gh attestation verify "$asset" --repo "$GITHUB_REPOSITORY" \
    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
    --source-ref "refs/tags/$GITHUB_REF_NAME" --source-digest "$GITHUB_SHA" \
    --deny-self-hosted-runners --bundle "$assets/workspace.attestation.jsonl"
done
archive="$assets/portablefs_${version}_darwin_universal_app.zip"
for asset in "$archive" "$archive.sha256" "$archive.space.json"; do
  gh attestation verify "$asset" --repo "$GITHUB_REPOSITORY" \
    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
    --source-ref "refs/tags/$GITHUB_REF_NAME" --source-digest "$GITHUB_SHA" \
    --deny-self-hosted-runners --bundle "$assets/macos.attestation.jsonl"
done
sh "$repo/scripts/test-macos-installer-zip-namespace.sh" "$archive"
work="$(mktemp -d "$RUNNER_TEMP/signed-workspace.XXXXXX")"
trap 'rm -rf "$work"' EXIT
# The real installer has just proven the complete ZIP namespace, signature and
# image boundary. Re-extract those same immutable bytes for full CLI validation.
ditto -x -k "$archive" "$work"
app="$work/PortableFS.app"
"$app/Contents/Helpers/portablefs" lifecycle verify-macos-bundle --app "$app"
bash "$repo/scripts/test-workspace-bundle-trust.sh" "$app" --signed
python3 - "$assets" "$app" "$version" "$GITHUB_SHA" <<'PY'
import hashlib,json,pathlib,sys
assets,app=map(pathlib.Path,sys.argv[1:3]);v,commit=sys.argv[3:]
sys.path.insert(0,str(pathlib.Path.cwd()/'deploy/linux-workspace'))
from redistribute import digest
manifest=app/'Contents/Resources/LinuxWorkspace/manifest.json'
assert manifest.read_bytes()==(assets/'workspace-manifest.json').read_bytes(), 'signed app uses a different guest build'
assert json.loads(manifest.read_text())['release']['commit']==commit
sources=app/'Contents/Resources/LinuxWorkspace/source-manifest.json'
assert sources.read_bytes()==(assets/'workspace-source-manifest.json').read_bytes()
assert json.loads(sources.read_text())['archive']==digest(assets/f'portablefs-workspace_{v}_source.tar.gz')
distribution=json.loads((assets/'workspace-distribution.json').read_text())
assert distribution['commit']==commit
assert distribution['assets']['guest-image.tar.gz']==digest(assets/f'portablefs-workspace_{v}_linux_arm64.tar.gz')
assert distribution['assets']['manifest.json']==digest(manifest)
assert distribution['assets']['source-manifest.json']==digest(sources)
assert json.loads((assets/'workspace-reproducibility.json').read_text())['commit']==commit
(assets/'signed-qualification.json').write_text(json.dumps(dict(commit=commit,version=v,installer=digest(assets/f'portablefs_{v}_darwin_universal_app.zip'),manifest=digest(manifest),source=digest(assets/f'portablefs-workspace_{v}_source.tar.gz'),space=json.loads((assets/f'portablefs_{v}_darwin_universal_app.zip.space.json').read_text())),indent=2)+'\n')
PY
