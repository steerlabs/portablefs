#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INSTANCE = /^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/;
const ZONE = /^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/;
const DNS_NAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const SECRET_VERSION = /^projects\/[a-z0-9-]+\/secrets\/[A-Za-z0-9_-]+\/versions\/[1-9][0-9]*$/;
const SHA256 = /^[0-9a-f]{64}$/;
const POOLS = new Set(["product", "system", "test"]);
const VOLUME_STATES = new Set([
  "PROVISIONING",
  "READY",
  "FENCING",
  "QUARANTINED",
  "ARCHIVING",
  "ARCHIVED",
  "RESTORING",
  "DESTROYING",
  "DESTROYED",
]);

function fail(message) {
  throw new Error(`release inventory: ${message}`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireObject(value, location) {
  if (!isObject(value)) fail(`${location} must be an object`);
  return value;
}

function requireExactKeys(value, required, optional, location) {
  const actual = Object.keys(requireObject(value, location)).sort();
  const allowed = new Set([...required, ...optional]);
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  const unknown = actual.filter((key) => !allowed.has(key));
  if (missing.length > 0 || unknown.length > 0) {
    fail(
      `${location} keys are not schema-v1 (missing: ${missing.join(",") || "none"}; ` +
        `unknown: ${unknown.join(",") || "none"})`,
    );
  }
}

function requireString(value, pattern, location) {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${location} is invalid`);
}

function requireAuthorityHost(value, location) {
  if (
    typeof value !== "string" ||
    value !== value.trim() ||
    value !== value.toLowerCase() ||
    (isIP(value) === 0 && !DNS_NAME.test(value))
  ) {
    fail(`${location} is invalid`);
  }
}

function requireInteger(value, minimum, maximum, location) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${location} must be a safe integer from ${minimum} through ${maximum}`);
  }
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!isObject(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, sortKeys(value[key])]),
  );
}

export function canonicalJSON(value) {
  return `${JSON.stringify(sortKeys(value))}\n`;
}

function validateDeclaration(declaration, location) {
  requireExactKeys(
    declaration,
    [
      "authority_dns_zone",
      "authority_host",
      "availability_zone",
      "capacity_bytes",
      "capacity_inodes",
      "first_port",
      "first_project_id",
      "first_service_uid",
      "last_port",
      "last_project_id",
      "last_service_uid",
      "pool",
    ],
    [],
    location,
  );
  requireString(declaration.availability_zone, ZONE, `${location}.availability_zone`);
  requireAuthorityHost(declaration.authority_host, `${location}.authority_host`);
  requireString(declaration.authority_dns_zone, DNS_NAME, `${location}.authority_dns_zone`);
  requireInteger(declaration.capacity_bytes, 1, Number.MAX_SAFE_INTEGER, `${location}.capacity_bytes`);
  requireInteger(declaration.capacity_inodes, 1, Number.MAX_SAFE_INTEGER, `${location}.capacity_inodes`);
  requireInteger(declaration.first_project_id, 1, 4_294_967_295, `${location}.first_project_id`);
  requireInteger(declaration.first_service_uid, 1_000, 4_294_967_295, `${location}.first_service_uid`);
  requireInteger(declaration.first_port, 1_024, 65_535, `${location}.first_port`);
  requireInteger(declaration.last_project_id, declaration.first_project_id, 4_294_967_294, `${location}.last_project_id`);
  requireInteger(declaration.last_service_uid, declaration.first_service_uid, 4_294_967_294, `${location}.last_service_uid`);
  requireInteger(declaration.last_port, declaration.first_port, 65_534, `${location}.last_port`);
  if (!POOLS.has(declaration.pool)) fail(`${location}.pool is invalid`);
}

export function validateInventory(value) {
  requireExactKeys(value, ["cells", "manager", "schema_version"], [], "root");
  if (value.schema_version !== 1) fail("schema_version must equal 1");

  requireExactKeys(value.manager, ["instance", "zone"], [], "manager");
  requireString(value.manager.instance, INSTANCE, "manager.instance");
  requireString(value.manager.zone, ZONE, "manager.zone");

  if (!Array.isArray(value.cells) || value.cells.length === 0) {
    fail("cells must be a non-empty array");
  }
  const seen = new Set();
  let previousID = "";
  for (const [index, cell] of value.cells.entries()) {
    const location = `cells[${index}]`;
    requireExactKeys(
      cell,
      ["declaration", "id", "instance", "zone"],
      ["leaf_secret"],
      location,
    );
    requireString(cell.id, UUID, `${location}.id`);
    requireString(cell.instance, INSTANCE, `${location}.instance`);
    requireString(cell.zone, ZONE, `${location}.zone`);
    if (seen.has(cell.id)) fail(`duplicate cell id ${cell.id}`);
    if (previousID !== "" && compareStrings(previousID, cell.id) >= 0) {
      fail("cells must be sorted by id");
    }
    seen.add(cell.id);
    previousID = cell.id;
    validateDeclaration(cell.declaration, `${location}.declaration`);
    if (cell.declaration.availability_zone !== cell.zone) {
      fail(`${location}.zone must equal declaration.availability_zone`);
    }
    if (cell.leaf_secret !== undefined) {
      requireExactKeys(
        cell.leaf_secret,
        ["sha256", "version_resource"],
        [],
        `${location}.leaf_secret`,
      );
      requireString(
        cell.leaf_secret.version_resource,
        SECRET_VERSION,
        `${location}.leaf_secret.version_resource`,
      );
      requireString(cell.leaf_secret.sha256, SHA256, `${location}.leaf_secret.sha256`);
    }
  }
  const ranges = [
    ["project ID", "first_project_id", "last_project_id"],
    ["service UID", "first_service_uid", "last_service_uid"],
    ["listener port", "first_port", "last_port"],
  ];
  for (let left = 0; left < value.cells.length; left += 1) {
    for (let right = left + 1; right < value.cells.length; right += 1) {
      const first = value.cells[left];
      const second = value.cells[right];
      if (first.zone !== second.zone || first.instance !== second.instance) continue;
      for (const [name, start, end] of ranges) {
        if (
          first.declaration[start] <= second.declaration[end] &&
          second.declaration[start] <= first.declaration[end]
        ) {
          fail(
            `cells ${first.id} and ${second.id} share ${first.zone}/${first.instance} with overlapping ${name} ranges`,
          );
        }
      }
    }
  }
  return value;
}

export async function readCanonicalInventory(filename) {
  const source = await readFile(filename, "utf8");
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    fail(`${filename} is not JSON: ${error.message}`);
  }
  validateInventory(value);
  if (source !== canonicalJSON(value)) {
    fail(`${filename} is not canonical; rewrite it with this command's validate output`);
  }
  return value;
}

function validateManagerCells(value) {
  requireExactKeys(value, ["cells"], [], "Manager cell response");
  if (!Array.isArray(value.cells)) fail("Manager cell response cells must be an array");
  const byID = new Map();
  for (const [index, cell] of value.cells.entries()) {
    requireObject(cell, `Manager cells[${index}]`);
    requireString(cell.id, UUID, `Manager cells[${index}].id`);
    if (byID.has(cell.id)) fail(`Manager returned duplicate cell ${cell.id}`);
    byID.set(cell.id, cell);
  }
  return byID;
}

function validateManagerVolumes(value) {
  requireExactKeys(value, ["volumes"], [], "Manager volume response");
  if (!Array.isArray(value.volumes)) fail("Manager volume response volumes must be an array");
  const byID = new Map();
  for (const [index, volume] of value.volumes.entries()) {
    requireObject(volume, `Manager volumes[${index}]`);
    requireString(volume.id, UUID, `Manager volumes[${index}].id`);
    if (!VOLUME_STATES.has(volume.state)) fail(`Manager volume ${volume.id} has invalid state`);
    if (byID.has(volume.id)) fail(`Manager returned duplicate volume ${volume.id}`);
    if (volume.placement !== undefined && volume.placement !== null) {
      requireObject(volume.placement, `Manager volume ${volume.id}.placement`);
      requireString(
        volume.placement.cell_id,
        UUID,
        `Manager volume ${volume.id}.placement.cell_id`,
      );
    } else if (volume.state === "DESTROYING") {
      if (volume.archive_cycle_step !== "purging-archive") {
        fail(`destroying Manager volume ${volume.id} has no placement outside archive purge`);
      }
    } else if (!["ARCHIVED", "DESTROYED"].includes(volume.state)) {
      fail(`live Manager volume ${volume.id} has no placement`);
    }
    byID.set(volume.id, volume);
  }
  return byID;
}

export function buildReleasePlan(inventory, managerCells, managerVolumes) {
  validateInventory(inventory);
  const inventoryCells = new Map(inventory.cells.map((cell) => [cell.id, cell]));
  const reportedCells = validateManagerCells(managerCells);
  const reportedVolumes = validateManagerVolumes(managerVolumes);

  for (const [cellID, cell] of reportedCells) {
    if (cell.abandoned !== true && !inventoryCells.has(cellID)) {
      fail(`Manager has unlisted live cell ${cellID}`);
    }
  }
  for (const cellID of inventoryCells.keys()) {
    if (!reportedCells.has(cellID)) fail(`Manager did not return declared cell ${cellID}`);
  }

  const volumeIDsByCell = new Map(inventory.cells.map((cell) => [cell.id, []]));
  const volumes = [];
  for (const volume of reportedVolumes.values()) {
    const cellID = volume.placement?.cell_id ?? null;
    if (cellID !== null) {
      const group = volumeIDsByCell.get(cellID);
      if (group === undefined) fail(`volume ${volume.id} is placed on unknown cell ${cellID}`);
      group.push(volume.id);
    }
    volumes.push({ cell_id: cellID, id: volume.id, state: volume.state });
  }
  volumes.sort((left, right) => compareStrings(left.id, right.id));
  for (const ids of volumeIDsByCell.values()) ids.sort();

  const managerHostKey = `${inventory.manager.zone}/${inventory.manager.instance}`;
  const hosts = new Map([
    [
      managerHostKey,
      {
        cell_ids: [],
        instance: inventory.manager.instance,
        role: "manager",
        volume_ids: [],
        zone: inventory.manager.zone,
      },
    ],
  ]);
  for (const cell of inventory.cells) {
    const hostKey = `${cell.zone}/${cell.instance}`;
    const host = hosts.get(hostKey) ?? {
      cell_ids: [],
      instance: cell.instance,
      role: "cell",
      volume_ids: [],
      zone: cell.zone,
    };
    host.cell_ids.push(cell.id);
    host.volume_ids.push(...volumeIDsByCell.get(cell.id));
    if (hostKey === managerHostKey) host.role = "manager-cell";
    hosts.set(hostKey, host);
  }
  const orderedHosts = [...hosts.values()].sort(
    (left, right) => compareStrings(left.zone, right.zone) || compareStrings(left.instance, right.instance),
  );
  for (const host of orderedHosts) {
    host.cell_ids.sort();
    host.volume_ids.sort();
  }

  return {
    cells: inventory.cells.map((cell) => ({
      id: cell.id,
      instance: cell.instance,
      volume_ids: volumeIDsByCell.get(cell.id),
      zone: cell.zone,
    })),
    hosts: orderedHosts,
    manager: inventory.manager,
    schema_version: 1,
    volumes,
  };
}

async function readJSON(filename, label) {
  try {
    return JSON.parse(await readFile(filename, "utf8"));
  } catch (error) {
    fail(`${label} ${filename} is not JSON: ${error.message}`);
  }
}

async function main(argv) {
  const [command, ...args] = argv;
  switch (command) {
    case "validate": {
      if (args.length !== 1) fail("usage: release-inventory.mjs validate INVENTORY.json");
      process.stdout.write(canonicalJSON(await readCanonicalInventory(args[0])));
      return;
    }
    case "plan": {
      if (args.length !== 3) {
        fail(
          "usage: release-inventory.mjs plan INVENTORY.json MANAGER-CELLS.json MANAGER-VOLUMES.json",
        );
      }
      const inventory = await readCanonicalInventory(args[0]);
      const cells = await readJSON(args[1], "Manager cell response");
      const volumes = await readJSON(args[2], "Manager volume response");
      process.stdout.write(canonicalJSON(buildReleasePlan(inventory, cells, volumes)));
      return;
    }
    default:
      fail("usage: release-inventory.mjs validate|plan ...");
  }
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (invokedDirectly) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
