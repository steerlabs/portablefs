#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const installer = await readFile(path.join(root, "scripts/install.sh"), "utf8");
const workflow = await readFile(path.join(root, ".github/workflows/release.yml"), "utf8");
const goreleaser = await readFile(path.join(root, ".goreleaser.yaml"), "utf8");

const failures = [];
const requireText = (source, text, label) => {
  if (!source.includes(text)) failures.push(`missing ${label}`);
};

requireText(installer, "gh_version=2.93.0", "pinned GitHub CLI version");
requireText(
  installer,
  "amd64) gh_sha256=02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0",
  "GitHub CLI amd64 digest"
);
requireText(
  installer,
  "arm64) gh_sha256=c55feb33684abba57e9909737340d5b39282257c0363e1edde6785ac4a413be7",
  "GitHub CLI arm64 digest"
);
for (const flag of [
  "--hostname github.com",
  '--repo "$REPO"',
  '--signer-workflow "$REPO/.github/workflows/release.yml"',
  '--source-ref "refs/tags/$tag"',
  "--deny-self-hosted-runners",
  '--bundle "$tmp/$attestation_bundle"',
]) {
  requireText(installer, flag, `attestation policy ${flag}`);
}

const canonicalStart = installer.indexOf('if [ "$REPO" = "steerlabs/portablefs" ]; then');
const canonicalEnd = installer.indexOf("\nelse", canonicalStart);
const canonicalPolicy =
  canonicalStart >= 0 && canonicalEnd > canonicalStart
    ? installer.slice(canonicalStart, canonicalEnd)
    : "";
for (const identity of [
  "EXPECTED_TEAM_ID=B47U2LLKHW",
  "EXPECTED_BUNDLE_ID=dev.portablefs.PortableFSApp",
  "EXPECTED_APP_GROUP=B47U2LLKHW.pfsoss",
  "EXPECTED_FS_TYPE=pfs",
  "EXPECTED_RESOURCE_SCHEME=dev.portablefs.oss",
]) {
  requireText(canonicalPolicy, identity, `canonical identity ${identity}`);
}
if (/PORTABLEFS_EXPECTED_/.test(canonicalPolicy)) {
  failures.push("canonical Apple identities remain environment-overridable");
}

const attestationIndex = installer.indexOf('"$tmp/gh" attestation verify');
const extractionIndex = installer.indexOf('tar -xzf "$tmp/$archive"');
if (attestationIndex < 0 || extractionIndex < 0 || attestationIndex >= extractionIndex) {
  failures.push("PortableFS archive extraction can happen before provenance verification");
}
for (const archiveContract of [
  "id: portablefs-client",
  "ids: [portablefs, portablefsd]",
  'name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"',
  "id: portablefs-server",
  'name_template: "{{ .ProjectName }}-server_{{ .Version }}_{{ .Os }}_{{ .Arch }}"',
  "replace_existing_draft: false",
  "use_existing_draft: false",
  "replace_existing_artifacts: false",
]) {
  requireText(goreleaser, archiveContract, `GoReleaser release contract ${archiveContract}`);
}
for (const exactMemberCheck of [
  'printf \'%s\\n\' "$BINARY" "$DAEMON"',
  "does not contain exactly the PortableFS CLI/daemon pair",
  "contains a link, special entry, or duplicate binary",
]) {
  requireText(installer, exactMemberCheck, `exact installer archive membership check ${exactMemberCheck}`);
}
for (const strictReleaseInput of [
  "curl -fsSL --retry 3 -o /dev/null -w '%{url_effective}'",
  'tag_prefix="https://github.com/$REPO/releases/tag/"',
  "'^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$'",
]) {
  requireText(installer, strictReleaseInput, `strict release input ${strictReleaseInput}`);
}
for (const macArchiveBoundary of [
  'zipinfo -1 "$tmp/$archive"',
  "contains an out-of-bundle member",
  "contains duplicate member",
  "contains a symlink or special filesystem entry",
]) {
  requireText(installer, macArchiveBoundary, `macOS pre-extraction archive boundary ${macArchiveBoundary}`);
}

for (const permission of ["id-token: write", "attestations: write"]) {
  requireText(workflow, permission, `release permission ${permission}`);
}
requireText(
  workflow,
  "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
  "pinned attestation action"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs_*_linux_amd64.tar.gz"',
  "Linux amd64 attestation subject"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs_*_linux_arm64.tar.gz"',
  "Linux arm64 attestation subject"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs-server_*_linux_amd64.tar.gz"',
  "Linux server amd64 attestation subject"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs-server_*_linux_arm64.tar.gz"',
  "Linux server arm64 attestation subject"
);
requireText(
  workflow,
  "portablefs_${version}_linux_amd64.tar.gz.attestation.jsonl",
  "deterministic amd64 attestation bundle asset"
);
requireText(
  workflow,
  "portablefs_${version}_linux_arm64.tar.gz.attestation.jsonl",
  "deterministic arm64 attestation bundle asset"
);
requireText(
  workflow,
  "portablefs-server_${version}_linux_amd64.tar.gz.attestation.jsonl",
  "deterministic server amd64 attestation bundle asset"
);
requireText(
  workflow,
  "portablefs-server_${version}_linux_arm64.tar.gz.attestation.jsonl",
  "deterministic server arm64 attestation bundle asset"
);
for (const serverArchiveContract of [
  'server_archive="dist/portablefs-server_${version}_linux_${arch}.tar.gz"',
  "printf '%s\\n' vcs",
  '"$RUNNER_TEMP/server-member-types-${arch}"',
]) {
  requireText(workflow, serverArchiveContract, `exact server archive contract ${serverArchiveContract}`);
}
for (const immutablePublication of [
  "Refuse a pre-existing GitHub release for this tag",
  "Verify exact Linux installer archive membership",
  "test \"$(gh release view",
]) {
  requireText(workflow, immutablePublication, `immutable release publication ${immutablePublication}`);
}
if (workflow.includes("--clobber")) {
  failures.push("release workflow can replace an existing asset with --clobber");
}
for (const releaseGate of [
  "Prove an exact stable tag at this source revision",
  "run: pnpm verify",
  "run: pnpm audit --prod --audit-level high",
  "govulncheck@v1.6.0",
  "args: check",
  "needs: validate",
  "needs: [validate, goreleaser]",
  "needs: [validate, goreleaser, macos-app]",
  "needs: [validate, goreleaser, macos-app, docker]",
  "run: swift test --package-path swift/PortableFSKit",
]) {
  requireText(workflow, releaseGate, `release validation gate ${releaseGate}`);
}
if (/^\s+ghcr\.io\/.*:latest\s*$/m.test(workflow)) {
  failures.push("release workflow publishes a mutable latest container tag");
}

if (failures.length > 0) {
  process.stderr.write(`install release trust policy failed:\n- ${failures.join("\n- ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("install release trust policy ok\n");
}
