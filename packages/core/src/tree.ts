import { createHash } from "node:crypto";
import {
  protocolVersion,
  type BlobDigest,
  type TreeEntry,
  type TreeManifestDiff,
  type TreeManifest,
} from "@portablefs/protocol";
import { stableJson } from "./hash.js";

const manifestTreeHashShardCount = 1024;
const manifestTreeHashRootVersion = "portablefs-tree-root-v2";
const manifestTreeHashShardVersion = "portablefs-tree-shard-v2";

/**
 * Deterministic, locale-independent ordering by UTF-16 code unit.
 *
 * Content-addressed structures (the sharded tree hash, canonical manifests, and
 * diffs) MUST order paths the same way on every machine, exactly like the byte
 * pathname sort Git uses. `String.prototype.localeCompare` is collation-based and
 * varies with the host locale and ICU version, so using it here makes the tree
 * hash of identical content differ between a daemon and the API (e.g. a macOS
 * client under one locale vs a Linux server under another), causing spurious
 * tree-hash-mismatch commit rejections. This comparator matches `Object.keys().sort()`
 * used by stableJson, keeping the whole content-addressing layer consistent.
 */
export function comparePaths(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export type ManifestDiff = TreeManifestDiff;

export interface ManifestIndex {
  manifest: TreeManifest;
  entriesByPath: ReadonlyMap<string, TreeEntry>;
  comparableKeysByPath: ReadonlyMap<string, string>;
  storedBlobDigests: ReadonlySet<BlobDigest>;
  storedBlobDigestCounts: ReadonlyMap<BlobDigest, number>;
  treeHashState: ManifestTreeHashState;
}

export interface IndexedManifestResult {
  manifest: TreeManifest;
  index: ManifestIndex;
}

export interface ManifestTreeHashState {
  treeHash: BlobDigest;
  shards: ReadonlyMap<number, ManifestTreeHashShard>;
}

export interface ManifestTreeHashShard {
  hash: BlobDigest;
  entriesByPath: ReadonlyMap<string, string>;
}

export interface ManifestMutationPath {
  path: string;
  recursive: boolean;
  reason: "add" | "change" | "remove" | "parent";
}

interface BlobUploadSource {
  digest: BlobDigest;
  path: string;
  size: number;
  offset?: number;
}

export function computeTreeHash(entries: TreeEntry[]): BlobDigest {
  return buildManifestTreeHashState(
    entries.map((entry) => [entry.path, comparableEntryKey(entry)] as const)
  ).treeHash;
}

export function diffManifests(
  previous: TreeManifest | null | undefined,
  next: TreeManifest
): ManifestDiff {
  return diffManifestIndexes(
    previous ? createManifestIndex(previous) : undefined,
    createManifestIndex(next)
  );
}

export function createManifestIndex(manifest: TreeManifest): ManifestIndex {
  const entries = sortedManifestEntries(manifest.entries);
  const entriesByPath = new Map<string, TreeEntry>();
  const comparableKeysByPath = new Map<string, string>();
  const storedBlobDigestCounts = new Map<BlobDigest, number>();
  for (const entry of entries) {
    entriesByPath.set(entry.path, entry);
    comparableKeysByPath.set(entry.path, comparableEntryKey(entry));
    incrementStoredBlobDigestCounts(storedBlobDigestCounts, entry);
  }
  const treeHashState = buildManifestTreeHashState(comparableKeysByPath.entries());
  const indexedManifest =
    manifest.treeHash === treeHashState.treeHash && entries === manifest.entries
      ? manifest
      : { ...manifest, treeHash: treeHashState.treeHash, entries };
  return {
    manifest: indexedManifest,
    entriesByPath,
    comparableKeysByPath,
    storedBlobDigests: new Set(storedBlobDigestCounts.keys()),
    storedBlobDigestCounts,
    treeHashState,
  };
}

export function diffManifestIndexes(
  previous: ManifestIndex | null | undefined,
  next: ManifestIndex
): ManifestDiff {
  const added: TreeEntry[] = [];
  const changed: TreeEntry[] = [];
  const removed: TreeEntry[] = [];

  for (const entry of next.manifest.entries) {
    const prior = previous?.entriesByPath.get(entry.path);
    if (!prior) {
      added.push(entry);
      continue;
    }
    if (previous?.comparableKeysByPath.get(entry.path) !== next.comparableKeysByPath.get(entry.path)) {
      changed.push(entry);
    }
  }
  for (const entry of previous?.entriesByPath.values() ?? []) {
    if (!next.entriesByPath.has(entry.path)) {
      removed.push(entry);
    }
  }

  const previousDigests = previous?.storedBlobDigests ?? new Set<BlobDigest>();
  const byteCount = [...added, ...changed].reduce(
    (total, entry) => total + missingStoredBlobByteCount(entry, previousDigests),
    0
  );

  return {
    added,
    changed,
    removed,
    mutationCount: added.length + changed.length + removed.length,
    byteCount,
  };
}

export function canonicalizeManifestDiff(
  previous: ManifestIndex,
  diff: ManifestDiff
): ManifestDiff {
  const finalTouchedEntries = new Map<string, TreeEntry | undefined>();
  for (const entry of diff.removed) {
    finalTouchedEntries.set(entry.path, undefined);
  }
  for (const entry of [...diff.added, ...diff.changed]) {
    finalTouchedEntries.set(entry.path, entry);
  }

  const added: TreeEntry[] = [];
  const changed: TreeEntry[] = [];
  const removed: TreeEntry[] = [];
  const paths = [...finalTouchedEntries.keys()].sort((left, right) => comparePaths(left, right));
  for (const pathValue of paths) {
    const prior = previous.entriesByPath.get(pathValue);
    const next = finalTouchedEntries.get(pathValue);
    if (!next) {
      if (prior) {
        removed.push(prior);
      }
      continue;
    }
    if (!prior) {
      added.push(next);
      continue;
    }
    if (previous.comparableKeysByPath.get(pathValue) !== comparableEntryKey(next)) {
      changed.push(next);
    }
  }

  const byteCount = [...added, ...changed].reduce(
    (total, entry) => total + missingStoredBlobByteCount(entry, previous.storedBlobDigests),
    0
  );

  return {
    added,
    changed,
    removed,
    mutationCount: added.length + changed.length + removed.length,
    byteCount,
  };
}

export function applyManifestDiffIndexed(
  current: ManifestIndex,
  diff: ManifestDiff,
  rootPath = ""
): IndexedManifestResult {
  const entriesByPath = new Map(current.entriesByPath);
  const comparableKeysByPath = new Map(current.comparableKeysByPath);
  const storedBlobDigestCounts = new Map(current.storedBlobDigestCounts);
  const treeHashState = mutableManifestTreeHashState(current.treeHashState);
  const removedPaths = new Set<string>();
  const upsertedByPath = new Map<string, TreeEntry>();
  for (const entry of diff.removed) {
    const fullPath = joinVolumePath(rootPath, entry.path);
    const existing = entriesByPath.get(fullPath);
    if (existing) {
      decrementStoredBlobDigestCounts(storedBlobDigestCounts, existing);
    }
    entriesByPath.delete(fullPath);
    comparableKeysByPath.delete(fullPath);
    removeManifestHashKey(treeHashState, fullPath);
    removedPaths.add(fullPath);
    upsertedByPath.delete(fullPath);
  }
  for (const entry of [...diff.added, ...diff.changed]) {
    const fullPath = joinVolumePath(rootPath, entry.path);
    const existing = entriesByPath.get(fullPath);
    if (existing) {
      decrementStoredBlobDigestCounts(storedBlobDigestCounts, existing);
    }
    const nextEntry = { ...entry, path: fullPath };
    const comparableKey = comparableEntryKey(nextEntry);
    entriesByPath.set(fullPath, nextEntry);
    comparableKeysByPath.set(fullPath, comparableKey);
    incrementStoredBlobDigestCounts(storedBlobDigestCounts, nextEntry);
    setManifestHashKey(treeHashState, fullPath, comparableKey);
    upsertedByPath.set(fullPath, nextEntry);
    removedPaths.delete(fullPath);
  }
  const entries = applySortedManifestEntryUpdates(current.manifest.entries, upsertedByPath, removedPaths);
  const finalizedTreeHashState = finalizeMutableManifestTreeHashState(treeHashState);
  const manifest: TreeManifest = {
    version: protocolVersion,
    treeHash: finalizedTreeHashState.treeHash,
    entries,
  };
  return {
    manifest,
    index: {
      manifest,
      entriesByPath,
      comparableKeysByPath,
      storedBlobDigests: new Set(storedBlobDigestCounts.keys()),
      storedBlobDigestCounts,
      treeHashState: finalizedTreeHashState,
    },
  };
}

function comparableEntry(entry: TreeEntry): unknown {
  // mtimeMs, ctimeMs, atimeMs, and ino are persisted manifest metadata, but deliberately
  // excluded from the canonical tree hash.
  return {
    path: entry.path,
    kind: entry.kind,
    mode: entry.mode,
    size: entry.size,
    executable: entry.executable,
    // Ownership is omitted when 0/unset (root), so existing manifests hash
    // identically — stableJson drops undefined keys and sorts the rest.
    uid: entry.uid || undefined,
    gid: entry.gid || undefined,
    blob: entry.blob
      ? {
          digest: entry.blob.digest,
          size: entry.blob.size,
          compression: entry.blob.compression,
          packed: entry.blob.packed,
        }
      : undefined,
    // An empty chunk list hashes as OMITTED (not "chunks":[]), matching Go's
    // omitempty — so an explicit [] and an absent field produce the identical tree
    // hash on both sides. Without the length guard, [].map() => [] would diverge.
    chunks: entry.chunks?.length
      ? entry.chunks.map((chunk) => ({
          digest: chunk.digest,
          size: chunk.size,
          offset: chunk.offset,
        }))
      : undefined,
    linkTarget: entry.linkTarget,
  };
}

function comparableEntryKey(entry: TreeEntry): string {
  return stableJson(comparableEntry(entry));
}

function hashToDigest(hash: ReturnType<typeof createHash>): BlobDigest {
  return `sha256:${hash.digest("hex")}`;
}

function buildManifestTreeHashState(
  comparableKeysByPath: Iterable<readonly [string, string]>
): ManifestTreeHashState {
  const shardEntries = new Map<number, Map<string, string>>();
  for (const [pathValue, comparableKey] of comparableKeysByPath) {
    const shardId = manifestTreeHashShardId(pathValue);
    let shard = shardEntries.get(shardId);
    if (!shard) {
      shard = new Map<string, string>();
      shardEntries.set(shardId, shard);
    }
    shard.set(pathValue, comparableKey);
  }
  const shards = new Map<number, ManifestTreeHashShard>();
  for (const [shardId, entries] of shardEntries) {
    shards.set(shardId, {
      hash: computeManifestShardHash(entries),
      entriesByPath: entries,
    });
  }
  return {
    treeHash: computeManifestRootHash(shards),
    shards,
  };
}

function mutableManifestTreeHashState(state: ManifestTreeHashState): {
  shards: Map<number, ManifestTreeHashShard>;
  dirtyShardIds: Set<number>;
} {
  return {
    shards: new Map(state.shards),
    dirtyShardIds: new Set<number>(),
  };
}

function setManifestHashKey(
  state: { shards: Map<number, ManifestTreeHashShard>; dirtyShardIds: Set<number> },
  pathValue: string,
  comparableKey: string
): void {
  const shardId = manifestTreeHashShardId(pathValue);
  const shard = mutableManifestTreeHashShard(state, shardId);
  shard.set(pathValue, comparableKey);
}

function removeManifestHashKey(
  state: { shards: Map<number, ManifestTreeHashShard>; dirtyShardIds: Set<number> },
  pathValue: string
): void {
  const shardId = manifestTreeHashShardId(pathValue);
  const shard = mutableManifestTreeHashShard(state, shardId);
  shard.delete(pathValue);
}

function mutableManifestTreeHashShard(
  state: { shards: Map<number, ManifestTreeHashShard>; dirtyShardIds: Set<number> },
  shardId: number
): Map<string, string> {
  const existing = state.shards.get(shardId);
  if (state.dirtyShardIds.has(shardId)) {
    return (existing?.entriesByPath as Map<string, string> | undefined) ?? new Map<string, string>();
  }
  const entriesByPath = new Map(existing?.entriesByPath ?? []);
  state.shards.set(shardId, {
    hash: existing?.hash ?? emptyManifestShardHash(),
    entriesByPath,
  });
  state.dirtyShardIds.add(shardId);
  return entriesByPath;
}

function finalizeMutableManifestTreeHashState(
  state: { shards: Map<number, ManifestTreeHashShard>; dirtyShardIds: Set<number> }
): ManifestTreeHashState {
  for (const shardId of state.dirtyShardIds) {
    const entriesByPath = state.shards.get(shardId)?.entriesByPath ?? new Map<string, string>();
    if (entriesByPath.size === 0) {
      state.shards.delete(shardId);
      continue;
    }
    state.shards.set(shardId, {
      hash: computeManifestShardHash(entriesByPath),
      entriesByPath,
    });
  }
  const shards = new Map(state.shards);
  return {
    treeHash: computeManifestRootHash(shards),
    shards,
  };
}

function computeManifestShardHash(entriesByPath: ReadonlyMap<string, string>): BlobDigest {
  const hash = createHash("sha256");
  hash.update(manifestTreeHashShardVersion);
  hash.update("\n");
  const sortedPaths = [...entriesByPath.keys()].sort((left, right) => comparePaths(left, right));
  sortedPaths.forEach((pathValue, index) => {
    if (index > 0) {
      hash.update("\n");
    }
    hash.update(pathValue);
    hash.update("\0");
    hash.update(entriesByPath.get(pathValue) ?? "");
  });
  return hashToDigest(hash);
}

function emptyManifestShardHash(): BlobDigest {
  return computeManifestShardHash(new Map());
}

function computeManifestRootHash(shards: ReadonlyMap<number, ManifestTreeHashShard>): BlobDigest {
  const hash = createHash("sha256");
  hash.update(manifestTreeHashRootVersion);
  hash.update("\n");
  hash.update(String(manifestTreeHashShardCount));
  const shardIds = [...shards.keys()].sort((left, right) => left - right);
  for (const shardId of shardIds) {
    const shard = shards.get(shardId);
    if (!shard) {
      continue;
    }
    hash.update("\n");
    hash.update(String(shardId));
    hash.update("\0");
    hash.update(shard.hash);
  }
  return hashToDigest(hash);
}

function manifestTreeHashShardId(pathValue: string): number {
  let hash = 2166136261;
  for (let index = 0; index < pathValue.length; index += 1) {
    hash ^= pathValue.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % manifestTreeHashShardCount;
}

function sortedManifestEntries(entries: readonly TreeEntry[]): TreeEntry[] {
  for (let index = 1; index < entries.length; index += 1) {
    if (comparePaths(entries[index - 1]!.path, entries[index]!.path) > 0) {
      return [...entries].sort((left, right) => comparePaths(left.path, right.path));
    }
  }
  return entries as TreeEntry[];
}

function applySortedManifestEntryUpdates(
  currentEntries: readonly TreeEntry[],
  upsertedByPath: ReadonlyMap<string, TreeEntry>,
  removedPaths: ReadonlySet<string>
): TreeEntry[] {
  if (upsertedByPath.size === 0 && removedPaths.size === 0) {
    return currentEntries as TreeEntry[];
  }
  const upsertedPaths = [...upsertedByPath.keys()].sort((left, right) => comparePaths(left, right));
  const entries: TreeEntry[] = [];
  let upsertIndex = 0;
  for (const currentEntry of currentEntries) {
    while (
      upsertIndex < upsertedPaths.length &&
      comparePaths(upsertedPaths[upsertIndex]!, currentEntry.path) < 0
    ) {
      entries.push(upsertedByPath.get(upsertedPaths[upsertIndex]!)!);
      upsertIndex += 1;
    }
    if (upsertedPaths[upsertIndex] === currentEntry.path) {
      entries.push(upsertedByPath.get(currentEntry.path)!);
      upsertIndex += 1;
      continue;
    }
    if (!removedPaths.has(currentEntry.path)) {
      entries.push(currentEntry);
    }
  }
  while (upsertIndex < upsertedPaths.length) {
    entries.push(upsertedByPath.get(upsertedPaths[upsertIndex]!)!);
    upsertIndex += 1;
  }
  return entries;
}

export function normalizeVolumePath(value: string | undefined | null): string {
  const trimmed = (value ?? "").trim();
  if (!trimmed || trimmed === "." || trimmed === "/") {
    return "";
  }
  const normalized = trimmed
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .split("/")
    .filter(Boolean)
    .join("/");
  if (normalized.includes("\0") || normalized.split("/").includes("..")) {
    throw new Error(`Invalid volume path: ${value}`);
  }
  return normalized;
}

export function joinVolumePath(rootPath: string, childPath: string): string {
  const root = normalizeVolumePath(rootPath);
  const child = normalizeVolumePath(childPath);
  if (!root) {
    return child;
  }
  if (!child) {
    return root;
  }
  return `${root}/${child}`;
}

export function parentVolumePath(pathValue: string): string {
  const normalized = normalizeVolumePath(pathValue);
  if (!normalized || !normalized.includes("/")) {
    return "";
  }
  return normalized.slice(0, normalized.lastIndexOf("/"));
}

export function isEqualOrDescendantPath(candidate: string, ancestor: string): boolean {
  const normalizedCandidate = normalizeVolumePath(candidate);
  const normalizedAncestor = normalizeVolumePath(ancestor);
  if (!normalizedAncestor) {
    return true;
  }
  return (
    normalizedCandidate === normalizedAncestor ||
    normalizedCandidate.startsWith(`${normalizedAncestor}/`)
  );
}

export function pathDelegationsOverlap(
  left: { path: string; recursive: boolean },
  right: { path: string; recursive: boolean }
): boolean {
  const leftPath = normalizeVolumePath(left.path);
  const rightPath = normalizeVolumePath(right.path);
  if (leftPath === rightPath) {
    return true;
  }
  if (left.recursive && isEqualOrDescendantPath(rightPath, leftPath)) {
    return true;
  }
  return right.recursive && isEqualOrDescendantPath(leftPath, rightPath);
}

export function projectManifest(manifest: TreeManifest, rootPath: string): TreeManifest {
  const root = normalizeVolumePath(rootPath);
  if (!root) {
    return manifest;
  }
  const prefix = `${root}/`;
  const entries = manifest.entries
    .filter((entry) => entry.path.startsWith(prefix))
    .map((entry) => ({
      ...entry,
      path: entry.path.slice(prefix.length),
    }))
    .filter((entry) => entry.path.length > 0);
  return {
    version: protocolVersion,
    treeHash: computeTreeHash(entries),
    entries,
  };
}

export function collectMutationPaths(diff: ManifestDiff, rootPath = ""): ManifestMutationPath[] {
  const paths = new Map<string, ManifestMutationPath>();
  const addPath = (pathValue: string, recursive: boolean, reason: ManifestMutationPath["reason"]) => {
    const fullPath = joinVolumePath(rootPath, pathValue);
    const key = `${fullPath}\0${recursive ? "r" : "f"}\0${reason}`;
    paths.set(key, { path: fullPath, recursive, reason });
  };

  for (const entry of diff.added) {
    addPath(entry.path, entry.kind === "directory", "add");
  }
  for (const entry of diff.changed) {
    addPath(entry.path, entry.kind === "directory", "change");
  }
  for (const entry of diff.removed) {
    addPath(entry.path, entry.kind === "directory", "remove");
  }

  return compactMutationPaths([...paths.values()]);
}

function compactMutationPaths(paths: ManifestMutationPath[]): ManifestMutationPath[] {
  const sorted = paths
    .map((entry) => ({ ...entry, path: normalizeVolumePath(entry.path) }))
    .sort((left, right) => comparePaths(left.path, right.path) || Number(right.recursive) - Number(left.recursive));
  const compacted: ManifestMutationPath[] = [];
  for (const candidate of sorted) {
    const covered = compacted.some(
      (existing) =>
        existing.recursive &&
        isEqualOrDescendantPath(candidate.path, existing.path) &&
        (existing.path !== candidate.path || existing.recursive || !candidate.recursive)
    );
    if (!covered) {
      compacted.push(candidate);
    }
  }
  return compacted;
}

export function diffHasPathConflict(left: ManifestDiff, right: ManifestDiff): boolean {
  const leftPaths = collectMutationPaths(left);
  const rightPaths = collectMutationPaths(right);
  return leftPaths.some((leftPath) =>
    rightPaths.some((rightPath) => pathDelegationsOverlap(leftPath, rightPath))
  );
}

function incrementStoredBlobDigestCounts(
  counts: Map<BlobDigest, number>,
  entry: TreeEntry
): void {
  for (const source of storedBlobSources(entry)) {
    counts.set(source.digest, (counts.get(source.digest) ?? 0) + 1);
  }
}

function decrementStoredBlobDigestCounts(
  counts: Map<BlobDigest, number>,
  entry: TreeEntry
): void {
  for (const source of storedBlobSources(entry)) {
    const nextCount = (counts.get(source.digest) ?? 0) - 1;
    if (nextCount > 0) {
      counts.set(source.digest, nextCount);
    } else {
      counts.delete(source.digest);
    }
  }
}

function missingStoredBlobByteCount(
  entry: TreeEntry,
  previousDigests: ReadonlySet<BlobDigest>
): number {
  if (entry.kind !== "file") {
    return 0;
  }
  return storedBlobSources(entry).reduce(
    (total, source) => total + (previousDigests.has(source.digest) ? 0 : source.size),
    0
  );
}

function storedBlobSources(entry: TreeEntry): BlobUploadSource[] {
  if (entry.kind !== "file") {
    return [];
  }
  if (entry.chunks?.length) {
    return entry.chunks.map((chunk) => ({
      digest: chunk.digest,
      path: entry.path,
      size: chunk.size,
      offset: chunk.offset,
    }));
  }
  if (!entry.blob) {
    return [];
  }
  return [
    {
      digest: entry.blob.digest,
      path: entry.path,
      size: entry.blob.size,
    },
  ];
}
