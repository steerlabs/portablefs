#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildReleasePlan,
  canonicalJSON,
  readCanonicalInventory,
  validateInventory,
} from "./release-inventory.mjs";

const CELL_A = "11111111-1111-4111-8111-111111111111";
const CELL_B = "22222222-2222-4222-8222-222222222222";
const VOLUME_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const VOLUME_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const VOLUME_C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.dirname(path.dirname(scriptRoot));

function declaration(zone, host, firstProject, firstUID, firstPort) {
  return {
    authority_dns_zone: "cells.staging.internal",
    authority_host: host,
    availability_zone: zone,
    capacity_bytes: 53_687_091_200,
    capacity_inodes: 2_000_000,
    first_port: firstPort,
    first_project_id: firstProject,
    first_service_uid: firstUID,
    last_port: firstPort + 255,
    last_project_id: firstProject + 255,
    last_service_uid: firstUID + 255,
    pool: "product",
  };
}

function inventory() {
  return {
    cells: [
      {
        declaration: declaration("us-west1-b", "cell-a.staging.internal", 10_000, 210_000, 23_000),
        id: CELL_A,
        instance: "portablefs-bench-1",
        leaf_secret: {
          sha256: "a".repeat(64),
          version_resource:
            "projects/opensteer-staging/secrets/portablefs-cell-a/versions/1",
        },
        zone: "us-west1-b",
      },
      {
        declaration: declaration("us-west1-c", "cell-b.staging.internal", 11_000, 211_000, 24_000),
        id: CELL_B,
        instance: "portablefs-cell-2",
        zone: "us-west1-c",
      },
    ],
    manager: { instance: "portablefs-bench-1", zone: "us-west1-b" },
    schema_version: 1,
  };
}

function managerCells() {
  return { cells: [{ id: CELL_A }, { id: CELL_B }] };
}

function managerVolumes() {
  return {
    volumes: [
      { authority_generation: 4, id: VOLUME_A, placement: { cell_id: CELL_A }, state: "READY" },
      { authority_generation: 2, id: VOLUME_B, placement: { cell_id: CELL_B }, state: "FENCING" },
      { authority_generation: 1, id: VOLUME_C, placement: null, state: "ARCHIVED" },
    ],
  };
}

test("schema-v1 inventory is exact, canonical, and allocator-bounded", async () => {
  const value = inventory();
  assert.equal(validateInventory(value), value);
  const directory = await mkdtemp(path.join(tmpdir(), "portablefs-inventory-test-"));
  try {
    const filename = path.join(directory, "cells.json");
    await writeFile(filename, canonicalJSON(value));
    assert.deepEqual(await readCanonicalInventory(filename), value);

    await writeFile(filename, `${JSON.stringify(value, null, 2)}\n`);
    await assert.rejects(readCanonicalInventory(filename), /not canonical/);

    const unbounded = structuredClone(value);
    delete unbounded.cells[0].declaration.last_port;
    assert.throws(() => validateInventory(unbounded), /keys are not schema-v1/);

    const overlappingSentinel = structuredClone(value);
    overlappingSentinel.cells[0].declaration.last_port = 65_535;
    assert.throws(() => validateInventory(overlappingSentinel), /last_port/);

    const unsorted = structuredClone(value);
    unsorted.cells.reverse();
    assert.throws(() => validateInventory(unsorted), /sorted by id/);

    const mismatchedZone = structuredClone(value);
    mismatchedZone.cells[0].zone = "us-west1-c";
    assert.throws(() => validateInventory(mismatchedZone), /must equal declaration/);

    const unknownKey = structuredClone(value);
    unknownKey.mutable_release_hint = true;
    assert.throws(() => validateInventory(unknownKey), /unknown: mutable_release_hint/);

    const hostCollision = structuredClone(value);
    hostCollision.cells[1].instance = hostCollision.cells[0].instance;
    hostCollision.cells[1].zone = hostCollision.cells[0].zone;
    hostCollision.cells[1].declaration.availability_zone = hostCollision.cells[0].zone;
    hostCollision.cells[1].declaration.first_port = 23_200;
    hostCollision.cells[1].declaration.last_port = 23_455;
    assert.throws(() => validateInventory(hostCollision), /overlapping listener port ranges/);
  } finally {
    await rm(directory, { recursive: true });
  }
});

test("release plan groups every discovered volume and supports a shared manager-cell host", () => {
  const plan = buildReleasePlan(inventory(), managerCells(), managerVolumes());
  assert.deepEqual(plan.hosts, [
    {
      cell_ids: [CELL_A],
      instance: "portablefs-bench-1",
      role: "manager-cell",
      volume_ids: [VOLUME_A],
      zone: "us-west1-b",
    },
    {
      cell_ids: [CELL_B],
      instance: "portablefs-cell-2",
      role: "cell",
      volume_ids: [VOLUME_B],
      zone: "us-west1-c",
    },
  ]);
  assert.deepEqual(
    plan.volumes.map((volume) => volume.id),
    [VOLUME_A, VOLUME_B, VOLUME_C],
  );
  assert.equal(plan.volumes[2].cell_id, null);
});

test("inventory planning refuses unknown, missing, and duplicate live state", () => {
  const extraCell = "33333333-3333-4333-8333-333333333333";
  assert.throws(
    () => buildReleasePlan(inventory(), { cells: [...managerCells().cells, { id: extraCell }] }, managerVolumes()),
    /unlisted live cell/,
  );
  assert.doesNotThrow(() =>
    buildReleasePlan(
      inventory(),
      { cells: [...managerCells().cells, { abandoned: true, id: extraCell }] },
      managerVolumes(),
    ),
  );
  assert.throws(
    () => buildReleasePlan(inventory(), { cells: [{ id: CELL_A }] }, managerVolumes()),
    /did not return declared cell/,
  );

  const duplicateCell = managerCells();
  duplicateCell.cells.push(structuredClone(duplicateCell.cells[0]));
  assert.throws(
    () => buildReleasePlan(inventory(), duplicateCell, managerVolumes()),
    /duplicate cell/,
  );

  const unknownPlacement = managerVolumes();
  unknownPlacement.volumes[0].placement.cell_id = extraCell;
  assert.throws(
    () => buildReleasePlan(inventory(), managerCells(), unknownPlacement),
    /placed on unknown cell/,
  );

  const duplicateVolume = managerVolumes();
  duplicateVolume.volumes.push(structuredClone(duplicateVolume.volumes[0]));
  assert.throws(
    () => buildReleasePlan(inventory(), managerCells(), duplicateVolume),
    /duplicate volume/,
  );

  const unplacedLive = managerVolumes();
  unplacedLive.volumes[0].placement = null;
  assert.throws(
    () => buildReleasePlan(inventory(), managerCells(), unplacedLive),
    /live Manager volume .* has no placement/,
  );

  const archivePurge = managerVolumes();
  archivePurge.volumes[0] = {
    archive_cycle_step: "purging-archive",
    authority_generation: 4,
    id: VOLUME_A,
    placement: null,
    state: "DESTROYING",
  };
  assert.doesNotThrow(() => buildReleasePlan(inventory(), managerCells(), archivePurge));
  archivePurge.volumes[0].archive_cycle_step = "destroying";
  assert.throws(
    () => buildReleasePlan(inventory(), managerCells(), archivePurge),
    /outside archive purge/,
  );
});

test("SSH transport takes each host's explicit zone", () => {
  const deploy = path.join(scriptRoot, "deploy-production.sh");
  const shell = `
    source "$1"
    gcp_project=opensteer-staging
    gcloud() { printf '%s\\n' "$@"; }
    ssh_run us-west1-c portablefs-cell-2 true
  `;
  const result = spawnSync("bash", ["-c", shell, "test", deploy], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /portablefs-cell-2/);
  assert.match(result.stdout, /--zone\nus-west1-c/);
  assert.match(result.stdout, /--project\nopensteer-staging/);
});

test("release scripts parse and cannot promote before the final fleet plan", async () => {
  for (const name of [
    "deploy-production.sh",
    "deploy-staging-locked.sh",
    "manager-api.sh",
    "cell-authority-state.sh",
  ]) {
    const filename = path.join(scriptRoot, name);
    const result = spawnSync("bash", ["-n", filename], { encoding: "utf8" });
    assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  }
  const deploy = await readFile(path.join(scriptRoot, "deploy-production.sh"), "utf8");
  assert.equal(deploy.includes(`OPENSTEER_${"VOLUME"}_IDS`), false);
  assert.ok((deploy.match(/manager_call list-volumes/g)?.length ?? 0) >= 3);
  const activate = deploy.indexOf('activate_host "$manager_host_key"');
  const finalPlan = deploy.indexOf('>"$evidence_dir/release-plan-after-restart.json"');
  const promote = deploy.indexOf('e2b_release promote "$OPENSTEER_E2B_CANDIDATE"');
  assert.ok(activate >= 0 && finalPlan > activate && promote > finalPlan);
  assert.equal(deploy.match(/e2b_release promote/g)?.length, 1);
  assert.match(deploy, /cell_call "\$cell_id" verify-control-release/);
  assert.match(deploy, /manager_call wait-cell-release/);
  assert.match(deploy, /cell_call "\$cell_id" inspect-release/);
  assert.doesNotMatch(deploy, /cell_call[^\n]*\|\| true/);
  assert.match(deploy, /release_lock_check/);
  assert.match(deploy, /global staging release lock was lost; refusing the next live mutation/);
  assert.match(deploy, /opensteer-staging requires the global release-lock transaction wrapper/);
  assert.match(deploy, /staging-release-lock\.py" assert-owned/);

  const lockedDeploy = await readFile(
    path.join(scriptRoot, "deploy-staging-locked.sh"),
    "utf8",
  );
  const acquire = lockedDeploy.indexOf("acquire-once");
  const heartbeat = lockedDeploy.indexOf("heartbeat-loop");
  const liveDeploy = lockedDeploy.indexOf('"$root/deploy/opensteer/deploy-production.sh"');
  const release = lockedDeploy.indexOf('"$lock_script" release');
  assert.ok(acquire >= 0 && heartbeat > acquire && liveDeploy > heartbeat && release > liveDeploy);
  assert.match(lockedDeploy, /--owner-kind github-actions/);
  assert.match(lockedDeploy, /--owner-id "\$owner_id"/);
  assert.match(lockedDeploy, /--source-commit "\$source_commit"/);
  assert.match(lockedDeploy, /--hold-seconds 7200/);
  assert.match(lockedDeploy, /OPENSTEER_RELEASE_LOCK_LOST_FILE/);

  const managerAPI = await readFile(path.join(scriptRoot, "manager-api.sh"), "utf8");
  const converge = managerAPI.slice(
    managerAPI.indexOf("  converge-cell)"),
    managerAPI.indexOf("  list-volumes)"),
  );
  assert.match(converge, /request operator PUT/);
  assert.doesNotMatch(converge, /Idempotency-Key/);

  const stagingWorkflow = await readFile(
    path.join(repositoryRoot, ".github/workflows/deploy-opensteer-staging.yml"),
    "utf8",
  );
  assert.match(stagingWorkflow, /\n      cell_inventory:\n/);
  assert.match(stagingWorkflow, /cell_inventory:[\s\S]*?required: true/);
  assert.doesNotMatch(stagingWorkflow, /vars\.OPENSTEER_CELL_INVENTORY/);
  assert.match(stagingWorkflow, /permissions:\n  actions: read\n  contents: read\n  id-token: write/);
  assert.match(stagingWorkflow, /run: deploy\/opensteer\/deploy-staging-locked\.sh/);
  assert.doesNotMatch(stagingWorkflow, /run: deploy\/opensteer\/deploy-production\.sh/);
  assert.ok(
    stagingWorkflow.indexOf("Build and smoke-test the candidate E2B template") <
      stagingWorkflow.indexOf("deploy/opensteer/deploy-staging-locked.sh"),
  );
  assert.ok(
    stagingWorkflow.indexOf("release-inventory.mjs validate") <
      stagingWorkflow.indexOf("google-github-actions/auth@"),
  );
});
