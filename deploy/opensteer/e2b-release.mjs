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

// smoke is a candidate-template gate, not a qualification. It runs inside one
// sandbox with no manager and no authority, so there is nothing for a mount to
// attach to and no honest way to fake one. What it can do — and what the
// earlier version did not — is make the shipped client prove it can complete a
// real kernel FUSE INIT handshake.
//
// What a passing smoke proves:
//   - the template contains this exact release's client, and the client agrees
//     about its own version;
//   - the sandbox kernel exposes a usable /dev/fuse to this client;
//   - the client's own mount options are accepted by this kernel, INIT
//     completes, the capabilities the coherence contract requires (atomic
//     O_TRUNC, explicit data-cache control, forwarded POSIX and BSD locks,
//     entry and inode invalidation, a 1 MiB request bound) are all offered,
//     and the mount unmounts cleanly.
//
// What it does NOT prove: anything about the authority, the wire protocol,
// visibility, durability, locking across mounts, leases, recalls, or any
// workload. A client that completes INIT can still be wrong about every one of
// those. Full qualification is the real-workload corpus in
// deploy/opensteer/staging-qualification.sh, run against a live staging cell.
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

    // The device node existing, opening, CAP_SYS_ADMIN being held and a helper
    // being installed are all equally true of a client that can never complete
    // FUSE INIT. --probe-mount installs one real throwaway mount instead, so
    // that failure class fails here rather than at a tenant's first mount.
    const probeResult = await sandbox.commands.run(
      "test -c /dev/fuse && /opt/opensteer/portablefs/portablefs mount-check --strategy fuse --probe-mount --json",
      { timeoutMs: 60_000, user: "root" },
    );
    const probe = JSON.parse(probeResult.stdout);
    if (probe.error) {
      throw new Error(
        `candidate client FUSE probe failed: ${String(probe.error.message)}`,
      );
    }
    if (probe.facts?.state !== "verified") {
      throw new Error(
        `candidate client FUSE probe reported state ${String(probe.facts?.state)}, expected verified`,
      );
    }
    if (probe.facts?.transport !== "fuse") {
      throw new Error(
        `candidate client probed transport ${String(probe.facts?.transport)}, expected fuse`,
      );
    }
    const kernelProbe = probe.kernelProbe;
    if (!kernelProbe || typeof kernelProbe.protocolMajor !== "number") {
      throw new Error(
        "candidate client reported verified without a kernel INIT probe; the client is too old to prove it can complete FUSE INIT",
      );
    }
    if (
      kernelProbe.protocolMajor !== 7 ||
      kernelProbe.protocolMinor < 31 ||
      !Number.isInteger(kernelProbe.initFlags) ||
      kernelProbe.initFlags === 0
    ) {
      throw new Error(
        `candidate client negotiated FUSE ${String(kernelProbe.protocolMajor)}.${String(kernelProbe.protocolMinor)} with flags ${String(kernelProbe.initFlags)}`,
      );
    }

    report({
      command: "smoke",
      kernelInitFlags: kernelProbe.initFlags,
      kernelProtocol: `${kernelProbe.protocolMajor}.${kernelProbe.protocolMinor}`,
      proves: "release identity and a completed kernel FUSE INIT handshake",
      provesNot:
        "authority, protocol, coherence, or workload behaviour; see deploy/opensteer/staging-qualification.sh",
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
