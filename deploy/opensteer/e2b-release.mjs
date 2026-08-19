#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const sdkRoot = resolve(required("OPENSTEER_E2B_SDK_ROOT"));
const apiKey = required("E2B_API_KEY");
const requireFromSdk = createRequire(join(sdkRoot, "package.json"));
const e2b = await import(
  pathToFileURL(requireFromSdk.resolve("e2b")).href
);
const { Sandbox, SandboxNotFoundError, Template } = e2b;

const [command, ...args] = process.argv.slice(2);
switch (command) {
  case "smoke":
    await smoke(...args);
    break;
  case "drain":
    await drain(...args);
    break;
  case "promote":
    await promote(...args);
    break;
  default:
    fail(
      "usage: e2b-release.mjs smoke TEMPLATE RELEASE_ID | drain EVIDENCE_FILE PHASE | promote TEMPLATE",
    );
}

async function smoke(template, expectedRelease) {
  requireTemplate(template);
  requireRelease(expectedRelease);
  let sandbox;
  try {
    sandbox = await Sandbox.create(template, {
      apiKey,
      metadata: {
        opensteer_deployment_release: expectedRelease,
        opensteer_deployment_smoke: "true",
      },
      timeoutMs: 5 * 60 * 1_000,
    });
    const versionResult = await sandbox.commands.run(
      "/opt/opensteer/portablefs/portablefs version --json",
      { timeoutMs: 30_000, user: "root" },
    );
    const version = JSON.parse(versionResult.stdout);
    if (version.version !== expectedRelease) {
      throw new Error(
        `candidate client reports ${String(version.version)}, expected ${expectedRelease}`,
      );
    }
    await sandbox.commands.run(
      "test -c /dev/fuse && /opt/opensteer/portablefs/portablefs mount-check --strategy fuse --json",
      { timeoutMs: 30_000, user: "root" },
    );
    report({
      command: "smoke",
      releaseId: expectedRelease,
      sandboxId: sandbox.sandboxId,
      template,
    });
  } finally {
    if (sandbox)
      await Sandbox.kill(sandbox.sandboxId, { apiKey }).catch(ignoreMissing);
  }
}

async function drain(evidenceFile, phase) {
  if (!evidenceFile || !resolve(evidenceFile).startsWith("/")) {
    fail("drain evidence path must be absolute");
  }
  if (!/^[a-z][a-z0-9-]{0,63}$/u.test(phase ?? ""))
    fail("drain phase is invalid");

  const killed = new Set();
  for (let pass = 1; pass <= 10; pass += 1) {
    const sandboxes = await listOpenSteerSandboxes();
    if (sandboxes.length === 0) break;
    for (const sandbox of sandboxes) {
      await Sandbox.kill(sandbox.sandboxId, { apiKey }).catch(ignoreMissing);
      killed.add(sandbox.sandboxId);
    }
    if (pass === 10) {
      throw new Error(
        "OpenSteer sandboxes did not reach zero after ten drain passes",
      );
    }
  }
  const remaining = await listOpenSteerSandboxes();
  if (remaining.length !== 0)
    throw new Error("OpenSteer sandbox drain did not reach zero");

  const evidence = {
    completedAt: new Date().toISOString(),
    filter: {
      metadataKey: "opensteer_provider_identity",
      states: ["paused", "running"],
    },
    killedSandboxIds: [...killed].sort(),
    phase,
    provider: "e2b",
    remainingSandboxIds: [],
    schemaVersion: 1,
  };
  const encoded = `${JSON.stringify(evidence, null, 2)}\n`;
  await mkdir(dirname(resolve(evidenceFile)), { recursive: true });
  await writeFile(resolve(evidenceFile), encoded, { mode: 0o600 });
  report({
    command: "drain",
    evidenceFile: resolve(evidenceFile),
    evidenceSHA256: createHash("sha256").update(encoded).digest("hex"),
    killed: killed.size,
    phase,
  });
}

async function promote(template) {
  requireTemplate(template);
  const assigned = await Template.assignTags(template, "default", { apiKey });
  report({ command: "promote", assigned, template });
}

async function listOpenSteerSandboxes() {
  const paginator = Sandbox.list({
    apiKey,
    limit: 100,
    query: { state: ["running", "paused"] },
  });
  const result = [];
  while (paginator.hasNext) {
    for (const sandbox of await paginator.nextItems()) {
      if (typeof sandbox.metadata?.opensteer_provider_identity === "string") {
        result.push(sandbox);
      }
    }
  }
  return result.sort((left, right) =>
    left.sandboxId.localeCompare(right.sandboxId),
  );
}

function ignoreMissing(error) {
  if (!(error instanceof SandboxNotFoundError)) throw error;
}

function requireTemplate(value) {
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(
      value ?? "",
    )
  ) {
    fail("template must be an explicit name:tag");
  }
}

function requireRelease(value) {
  if (!/^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$/u.test(value ?? "")) {
    fail("release ID is invalid");
  }
}

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function report(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function fail(message) {
  throw new Error(message);
}
