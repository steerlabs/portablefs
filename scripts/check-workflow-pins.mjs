#!/usr/bin/env node

import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Executable supply-chain policy for .github/workflows (offline, no YAML
// dependency: the checks are line-anchored and fail closed on anything they
// cannot prove):
//
// 1. `uses:` references. First-party `actions/*` steps may float on a major
//    tag (GitHub maintains them) or be SHA-pinned. EVERY other owner is
//    third-party and MUST be pinned to a full 40-hex commit SHA with a
//    trailing `# <version>` evidence comment. Local `./` composite actions
//    and `docker://` images pinned by digest are allowed.
// 2. `runs-on:` must name an explicitly versioned runner image (for example
//    ubuntu-24.04), never a mutable `-latest` alias.
// 3. Every workflow must declare top-level `permissions:` (least privilege)
//    and `concurrency:`.
//
// This mirrors the vendored-protocol posture: mutable identities cannot
// reach CI/release without an immutable pin and reviewable evidence.

const FIRST_PARTY_OWNERS = new Set(["actions"]);
const USES_PATTERN = /^\s*(?:-\s+)?uses:\s*(.+?)\s*(?:#(.*))?$/;
const RUNS_ON_PATTERN = /^\s*runs-on:\s*(.+?)\s*$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const TAG_PATTERN = /^v\d+(?:\.\d+){0,2}$/;

export async function verifyWorkflowPins(workflowsDir) {
  const root =
    typeof workflowsDir === "string" ? path.resolve(workflowsDir) : fileURLToPath(workflowsDir);
  const entries = (await readdir(root)).filter((file) => /\.ya?ml$/.test(file)).sort();
  if (entries.length === 0) {
    throw new Error("workflow pin check found no workflow files");
  }
  const failures = [];
  const checked = [];
  for (const file of entries) {
    const source = await readFile(path.join(root, file), "utf8");
    const lines = source.split("\n");
    if (!lines.some((line) => /^permissions:/.test(line))) {
      failures.push(`${file}: missing top-level least-privilege permissions block`);
    }
    if (!lines.some((line) => /^concurrency:/.test(line))) {
      failures.push(`${file}: missing top-level concurrency block`);
    }
    lines.forEach((line, index) => {
      const location = `${file}:${index + 1}`;
      const runsOn = RUNS_ON_PATTERN.exec(line);
      if (runsOn) {
        const image = runsOn[1].replace(/["']/g, "");
        if (image.includes("latest") || image.includes("${{")) {
          failures.push(`${location}: runs-on must pin a versioned image, got "${image}"`);
        }
      }
      const uses = USES_PATTERN.exec(line);
      if (!uses) return;
      const reference = uses[1].replace(/["']/g, "");
      const comment = (uses[2] ?? "").trim();
      if (reference.startsWith("./")) return; // local, versioned with the repo
      if (reference.startsWith("docker://")) {
        if (!reference.includes("@sha256:")) {
          failures.push(`${location}: docker action must be pinned by digest`);
        }
        return;
      }
      const at = reference.lastIndexOf("@");
      if (at <= 0) {
        failures.push(`${location}: uses reference "${reference}" has no ref`);
        return;
      }
      const action = reference.slice(0, at);
      const ref = reference.slice(at + 1);
      const owner = action.split("/")[0];
      if (SHA_PATTERN.test(ref)) {
        if (comment === "") {
          failures.push(
            `${location}: SHA-pinned action "${action}" needs a trailing "# vX.Y.Z" evidence comment`
          );
        }
        checked.push(`${action}@${ref}`);
        return;
      }
      if (FIRST_PARTY_OWNERS.has(owner) && TAG_PATTERN.test(ref)) {
        checked.push(`${action}@${ref}`);
        return;
      }
      failures.push(
        `${location}: third-party action "${action}" must be pinned to a 40-hex commit SHA ` +
          `with a version comment (got "@${ref}")`
      );
    });
  }
  const ciWorkflow = await readFile(path.join(root, "ci.yml"), "utf8");
  for (const semanticGate of [
    "Validate GitHub Actions workflow semantics",
    'GOBIN="$RUNNER_TEMP/actionlint-bin"',
    "go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.10",
    '"$RUNNER_TEMP/actionlint-bin/actionlint" .github/workflows/*.yml',
    "Verify the artifact-only staging publication boundary",
    "python3 deploy/files/test_release_registry.py",
    "node --test deploy/opensteer/release-inventory.test.mjs",
  ]) {
    if (!ciWorkflow.includes(semanticGate)) {
      failures.push(`ci.yml: missing frozen workflow semantic gate ${semanticGate}`);
    }
  }
  if (ciWorkflow.includes("actionlint/cmd/actionlint@latest")) {
    failures.push("ci.yml: actionlint must use an exact reviewed version, not @latest");
  }
  const filesImageWorkflow = await readFile(path.join(root, "files-image.yml"), "utf8");
  const filesImageBake = await readFile(
    path.resolve(root, "../../deploy/files/docker-bake.hcl"),
    "utf8"
  );
  const releaseContainerfile = await readFile(
    path.resolve(root, "../../deploy/files/ReleaseContainerfile"),
    "utf8"
  );
  const registryVerifier = await readFile(
    path.resolve(root, "../../deploy/files/verify-registry-image.sh"),
    "utf8"
  );
  if (entries.includes("deploy-opensteer-staging.yml")) {
    failures.push(
      "deploy-opensteer-staging.yml: PortableFS may publish staging artifacts but opensteer-infra Cloud Build is the sole staging activation authority"
    );
  }
  if (/type=registry[^\n]*cache/u.test(filesImageBake)) {
    failures.push(
      "deploy/files/docker-bake.hcl: release repository must not contain a mutable registry cache"
    );
  }
  if (
    !filesImageBake.includes(
      'default = "us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases"'
    ) ||
    filesImageBake.includes('default = "us-west1-docker.pkg.dev/opensteer-admin/staging"')
  ) {
    failures.push(
      "deploy/files/docker-bake.hcl: images must target the dedicated PortableFS release repository"
    );
  }
  for (const cacheContract of [
    "*.cache-from=type=gha,scope=portablefs-files",
    "*.cache-to=type=gha,scope=portablefs-files,mode=max",
  ]) {
    if (!filesImageWorkflow.includes(cacheContract)) {
      failures.push(`files-image.yml: missing immutable-registry cache separation ${cacheContract}`);
    }
  }
  for (const artifactContract of [
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0",
    "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16 # v6.5.0",
    "branches:\n      - main",
    "REGISTRY: us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases",
    "test \"$GITHUB_REPOSITORY_OWNER_ID\" = 252926615",
    "test \"$GITHUB_REPOSITORY_ID\" = 1313214092",
    "test \"$GITHUB_WORKFLOW_REF\" = steerlabs/portablefs/.github/workflows/files-image.yml@refs/heads/main",
    "github/providers/github-portablefs-publisher",
    "gha-portablefs-publisher@opensteer-admin.iam.gserviceaccount.com",
    "BUILDX_NO_DEFAULT_ATTESTATIONS: \"1\"",
    "create_credentials_file: false",
    "go install github.com/google/go-containerregistry/cmd/crane@v0.20.3",
    'timeout --kill-after=5s 60s crane digest "$tag"',
    'timeout --kill-after=30s 600s crane push "$layout" "$tag"',
    'grep -Fq \'MANIFEST_UNKNOWN\' "$digest_error"',
    "deploy/files/verify-registry-image.sh files",
    'release "$tag" "$SOURCE_REVISION" "$FILES_IMAGE"',
    "portablefs-files:sha-$SOURCE_REVISION",
    "portablefs-release:sha-$SOURCE_REVISION",
    "python3 deploy/files/release_registry.py assemble",
  ]) {
    if (!filesImageWorkflow.includes(artifactContract)) {
      failures.push(`files-image.yml: missing immutable artifact contract ${artifactContract}`);
    }
  }
  for (const sharedWriter of [
    "opensteer-admin/staging/portablefs-files",
    "opensteer-admin/staging/portablefs-release",
    "github/providers/github-image-publisher",
    "gha-deployer@opensteer-admin.iam.gserviceaccount.com",
  ]) {
    if (filesImageWorkflow.includes(sharedWriter)) {
      failures.push(`files-image.yml: publisher still trusts shared writer ${sharedWriter}`);
    }
  }
  if (/workflow_dispatch:|\n\s+paths:/u.test(filesImageWorkflow)) {
    failures.push("files-image.yml: artifact publication must run on every main push only");
  }
  if (/NAME_UNKNOWN|not found/u.test(filesImageWorkflow)) {
    failures.push(
      "files-image.yml: only MANIFEST_UNKNOWN may authorize creation of an absent immutable tag"
    );
  }
  if (!registryVerifier.includes('arguments+=(--source-root "$root")')) {
    failures.push(
      "verify-registry-image.sh: publisher must compare every embedded deployment helper with the exact source checkout"
    );
  }
  for (const registryContract of [
    'record_files_image=$(timeout --kill-after=2s 10s python3 -c',
    'files_tag="$registry/portablefs-files:sha-$source_revision"',
    '"$root/deploy/files/verify-registry-image.sh"',
    '[[ $verified_files_digest == "$record_files_digest" ]]',
  ]) {
    if (!registryVerifier.includes(registryContract)) {
      failures.push(
        `verify-registry-image.sh: missing capsule-selected component verification ${registryContract}`
      );
    }
  }
  for (const forbiddenLiveSurface of [
    "E2B_API_KEY",
    "gcloud compute",
    "deploy-production.sh",
    "deploy-staging",
    "e2b-release.mjs",
    "staging-release-lock",
  ]) {
    if (filesImageWorkflow.includes(forbiddenLiveSurface)) {
      failures.push(
        `files-image.yml: artifact-only publisher contains live staging surface ${forbiddenLiveSurface}`
      );
    }
  }
  const filesPosition = filesImageWorkflow.indexOf("id: files");
  const releasePosition = filesImageWorkflow.indexOf("id: release");
  if (filesPosition < 0 || releasePosition <= filesPosition) {
    failures.push("files-image.yml: aggregate release must publish after portablefs-files");
  }
  const releaseInstructions = releaseContainerfile
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
  if (
    releaseInstructions[0] !== "FROM scratch" ||
    releaseInstructions.filter((line) => /^COPY\b/u.test(line)).length !== 1 ||
    releaseInstructions.some((line) => /^(?:ADD|CMD|ENTRYPOINT|ENV|RUN|USER|WORKDIR)\b/u.test(line))
  ) {
    failures.push(
      "deploy/files/ReleaseContainerfile: release capsule must be a non-executable one-COPY scratch artifact"
    );
  }
  const privilegedJob = /\n  linux-xfs-fuse:\n([\s\S]*?)(?=\n  [a-zA-Z0-9_-]+:\n|\s*$)/u.exec(
    ciWorkflow
  );
  const privilegedJobTimeout = privilegedJob
    ? /timeout-minutes:\s*(\d+)/u.exec(privilegedJob[1])
    : null;
  const privilegedSuite = await readFile(
    path.resolve(root, "../../scripts/xfs-fuse-integration.sh"),
    "utf8"
  );
  const privilegedProfileTimeout = /-timeout\s+(\d+)m/u.exec(privilegedSuite);
  if (!privilegedJobTimeout || !privilegedProfileTimeout) {
    failures.push(
      "ci.yml: privileged XFS/FUSE job and native go-test timeout must remain explicit"
    );
  } else {
    // The plain and capability-limited profiles run sequentially. Preserve
    // enough outer budget for both native timeout diagnostics plus bounded
    // image pull, package installation, filesystem provisioning, and teardown.
    const requiredMinutes = Number(privilegedProfileTimeout[1]) * 2 + 10;
    if (Number(privilegedJobTimeout[1]) < requiredMinutes) {
      failures.push(
        `ci.yml: linux-xfs-fuse timeout must be at least ${requiredMinutes} minutes ` +
          `for two ${privilegedProfileTimeout[1]}-minute native profiles`
      );
    }
  }
  if (failures.length > 0) {
    throw new Error(`workflow pin policy failed:\n- ${failures.join("\n- ")}`);
  }
  return Object.freeze({ files: entries, references: checked });
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href;

if (invokedDirectly) {
  const target = process.argv[2] ?? new URL("../.github/workflows/", import.meta.url);
  verifyWorkflowPins(target)
    .then((result) => {
      process.stdout.write(
        `workflow pins ok: ${result.files.join(", ")} (${result.references.length} action refs)\n`
      );
    })
    .catch((error) => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}
