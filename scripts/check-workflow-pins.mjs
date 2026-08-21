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
  ]) {
    if (!ciWorkflow.includes(semanticGate)) {
      failures.push(`ci.yml: missing frozen workflow semantic gate ${semanticGate}`);
    }
  }
  if (ciWorkflow.includes("actionlint/cmd/actionlint@latest")) {
    failures.push("ci.yml: actionlint must use an exact reviewed version, not @latest");
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
