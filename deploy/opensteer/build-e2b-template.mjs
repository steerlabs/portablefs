#!/usr/bin/env node

// Build one candidate E2B template from two immutable release inputs: the
// digest-pinned OpenSteer Runner image and this PortableFS release's exact
// Linux client. OpenSteer code stays in its image; this repository supplies
// only the client and the configuration that binds the Runner to its digest.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const sdkRoot = resolve(required("OPENSTEER_E2B_SDK_ROOT"));
const requireFromSdk = createRequire(join(sdkRoot, "package.json"));
const { Template } = await import(
  pathToFileURL(requireFromSdk.resolve("e2b")).href
);

const apiKey = required("E2B_API_KEY");
const templateName = required("OPENSTEER_E2B_TEMPLATE_NAME");
const runnerImage = required("OPENSTEER_RUNNER_IMAGE");
const releaseId = required("OPENSTEER_PORTABLEFS_RELEASE_ID");
const portableFsArtifact = resolve(
  required("OPENSTEER_PORTABLEFS_ARTIFACT_PATH"),
);
const cpuCount = positiveInteger("OPENSTEER_E2B_TEMPLATE_CPU_COUNT", 2);
const memoryMB = positiveInteger("OPENSTEER_E2B_TEMPLATE_MEMORY_MB", 4_096);

if (!/^[^\s@:]+(?:[/:][^\s@:]+)+@sha256:[0-9a-f]{64}$/u.test(runnerImage)) {
  throw new Error("OPENSTEER_RUNNER_IMAGE must be pinned by a sha256 digest");
}
if (!/^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$/u.test(releaseId)) {
  throw new Error("OPENSTEER_PORTABLEFS_RELEASE_ID is invalid");
}
if (
  !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(
    templateName,
  )
) {
  throw new Error("OPENSTEER_E2B_TEMPLATE_NAME must be an explicit name:tag");
}

const portableFsDigest = createHash("sha256")
  .update(readFileSync(portableFsArtifact))
  .digest("hex");
const context = mkdtempSync(join(tmpdir(), "portablefs-e2b-template-"));

try {
  copyFileSync(portableFsArtifact, join(context, "portablefs"));
  writeFileSync(join(context, "cloud-runner.env"), runnerEnvironmentFile());

  const template = Template({ fileContextPath: context })
    .fromImage(runnerImage, registryCredentials())
    .setUser("root")
    .copy("portablefs", "/opt/opensteer/portablefs/portablefs", {
      mode: 0o555,
    })
    .copy("cloud-runner.env", "/etc/opensteer/cloud-runner.env", {
      mode: 0o444,
    })
    .runCmd([
      "install --directory --owner root --group root --mode 0700 /var/lib/opensteer",
      "install --directory --owner root --group root --mode 0700 /var/log/opensteer",
      "install --directory --owner root --group root --mode 0700 /run/opensteer",
      "chown --recursive root:root /var/lib/opensteer",
    ])
    .setReadyCmd(
      [
        "test -x /opt/opensteer/control/opensteer-cloud-activate.mjs",
        "test -x /opt/opensteer/control/opensteer-cloud-activation",
        "test -x /opt/opensteer/control/opensteer-entrypoint.mjs",
        "test -x /opt/opensteer/portablefs/portablefs",
        `/opt/opensteer/portablefs/portablefs version --json | node -e 'const fs=require("node:fs");if(JSON.parse(fs.readFileSync(0,"utf8")).version!==process.argv[1])process.exit(1)' ${shellQuote(releaseId)}`,
      ].join(" && "),
    );

  const build = await Template.build(template, templateName, {
    apiKey,
    cpuCount,
    memoryMB,
    onBuildLogs: (entry) => process.stderr.write(`${entry.message ?? entry}\n`),
  });

  process.stdout.write(
    `${JSON.stringify(
      {
        cpuCount,
        memoryMB,
        portableFsDigest,
        releaseId,
        runnerImage,
        templateId: build.templateId,
        templateName,
      },
      null,
      2,
    )}\n`,
  );
} finally {
  rmSync(context, { force: true, recursive: true });
}

function runnerEnvironmentFile() {
  const values = {
    NODE_ENV: "production",
    OPENSTEER_DEPLOYMENT_PROFILE: "cloud-portablefs",
    // One template serves every managed Host. The activation grant supplies
    // the real origin and rejects any configured origin that does not match.
    OPENSTEER_HOST_URL: "https://managed-host.invalid/",
    OPENSTEER_MAX_CONCURRENT_RUNS: "4",
    OPENSTEER_MODE: "production",
    OPENSTEER_PORTABLEFS_MOUNT_BINARY:
      "/opt/opensteer/portablefs/portablefs",
    OPENSTEER_PORTABLEFS_MOUNT_SHA256: portableFsDigest,
    OPENSTEER_RUNNER_DATA_DIR: "/var/lib/opensteer",
    OPENSTEER_RUNNER_KIND: "managed",
    OPENSTEER_RUNNER_NAME: "Cloud Computer",
    OPENSTEER_RUNNER_WORKSPACE_BACKINGS: "portablefs",
    CODEX_HOME: "/var/lib/opensteer/private/harness-state/codex",
    CODEX_SQLITE_HOME: "/var/cache/opensteer/codex-sqlite",
  };
  return `${Object.entries(values)
    .map(([name, value]) => `${name}=${shellQuote(value)}`)
    .join("\n")}\n`;
}

// GitHub OIDC has already issued gcloud a short-lived access token. E2B uses
// this credential only while pulling the private, digest-pinned base image.
function registryCredentials() {
  return {
    username: "oauth2accesstoken",
    password: execFileSync("gcloud", ["auth", "print-access-token"], {
      encoding: "utf8",
    }).trim(),
  };
}

function positiveInteger(name, fallback) {
  const value = Number(process.env[name]?.trim() || fallback);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}
