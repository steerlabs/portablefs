import { lstat, open, readFile, readdir, readlink } from "node:fs/promises";
import { type Stats } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import {
  protocolVersion,
  type BlobDigest,
  type ChunkRef,
  type TreeEntry,
  type TreeManifestDiff,
  type TreeManifest,
} from "@portablefs/protocol";
import { sha256Buffer, stableJson } from "./hash.js";

export const volumeMetadataDirName = ".portablefs";
export const defaultLargeFileThresholdBytes = 8 * 1024 * 1024;
export const defaultLargeFileChunkBytes = 4 * 1024 * 1024;
export const defaultStableReadRetries = 5;
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

export interface ScanWorkspaceOptions {
  ignoreNames?: ReadonlySet<string>;
  largeFileThresholdBytes?: number;
  largeFileChunkBytes?: number;
  stableReadRetries?: number;
  cache?: ScanWorkspaceCache;
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

export interface ScanWorkspaceCache {
  version: 1;
  entries: Record<string, ScanWorkspaceCacheEntry>;
  treeHash?: BlobDigest;
  changed?: boolean;
}

export interface ScanWorkspaceCacheEntry {
  fingerprint: ScanWorkspaceFingerprint;
  entry: TreeEntry;
}

export interface ScanWorkspaceFingerprint {
  kind: TreeEntry["kind"];
  mode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  linkTarget?: string;
}

type NormalizedScanOptions = Required<
  Omit<ScanWorkspaceOptions, "ignoreNames" | "cache">
>;

interface ScanContext {
  options: NormalizedScanOptions;
  cache?: ScanWorkspaceCache;
  nextCache?: ScanWorkspaceCache;
}

export interface ManifestMutationPath {
  path: string;
  recursive: boolean;
  reason: "add" | "change" | "remove" | "parent";
}

export interface BlobUploadSource {
  digest: BlobDigest;
  path: string;
  size: number;
  offset?: number;
}

export async function scanWorkspace(
  root: string,
  options: ScanWorkspaceOptions = {}
): Promise<TreeManifest> {
  const absoluteRoot = path.resolve(root);
  const ignoreNames =
    options.ignoreNames ?? new Set<string>([volumeMetadataDirName]);
  const entries: TreeEntry[] = [];
  const context = scanContext(options);
  await scanIntoManifest(absoluteRoot, "", entries, ignoreNames, context);
  entries.sort((left, right) => comparePaths(left.path, right.path));
  const cachedTreeHash = finalizeScanCache(context, entries);
  const treeHash = cachedTreeHash ?? computeTreeHash(entries);
  rememberScanCacheTreeHash(context, treeHash);
  return {
    version: protocolVersion,
    treeHash,
    entries,
  };
}

export async function scanWorkspacePaths(
  root: string,
  previous: TreeManifest,
  dirtyPaths: readonly string[],
  options: ScanWorkspaceOptions = {}
): Promise<TreeManifest> {
  const absoluteRoot = path.resolve(root);
  const ignoreNames =
    options.ignoreNames ?? new Set<string>([volumeMetadataDirName]);
  const paths = compactDirtyScanPaths(dirtyPaths, ignoreNames);
  if (paths.length === 0) {
    return previous;
  }
  if (paths.includes("")) {
    return scanWorkspace(absoluteRoot, options);
  }

  const entriesByPath = new Map(previous.entries.map((entry) => [entry.path, entry]));
  const context = scanContext(options);
  for (const dirtyPath of paths) {
    for (const entryPath of [...entriesByPath.keys()]) {
      if (entryPath === dirtyPath || entryPath.startsWith(`${dirtyPath}/`)) {
        entriesByPath.delete(entryPath);
      }
    }
    await scanPathIntoManifest(absoluteRoot, dirtyPath, entriesByPath, ignoreNames, context);
  }

  const entries = [...entriesByPath.values()].sort((left, right) => comparePaths(left.path, right.path));
  const cachedTreeHash = finalizeScanCache(context, entries);
  const treeHash = cachedTreeHash ?? computeTreeHash(entries);
  rememberScanCacheTreeHash(context, treeHash);
  return {
    version: protocolVersion,
    treeHash,
    entries,
  };
}

export function emptyScanWorkspaceCache(): ScanWorkspaceCache {
  return { version: 1, entries: {} };
}

export async function buildScanWorkspaceCache(
  root: string,
  manifest: TreeManifest
): Promise<ScanWorkspaceCache> {
  const absoluteRoot = path.resolve(root);
  const cache = emptyScanWorkspaceCache();
  cache.treeHash = manifest.treeHash;
  for (const entry of manifest.entries) {
    const targetPath = resolveEntryPath(absoluteRoot, entry.path);
    const info = await lstat(targetPath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return null;
      }
      throw error;
    });
    if (!info) {
      continue;
    }
    const fingerprint = await fingerprintForManifestEntry(targetPath, entry, info);
    if (fingerprint) {
      cache.entries[entry.path] = { fingerprint, entry };
    }
  }
  return cache;
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

export function expandManifest(manifest: TreeManifest, rootPath: string): TreeManifest {
  const root = normalizeVolumePath(rootPath);
  if (!root) {
    return manifest;
  }
  const entries = manifest.entries.map((entry) => ({
    ...entry,
    path: joinVolumePath(root, entry.path),
  }));
  return {
    version: protocolVersion,
    treeHash: computeTreeHash(entries),
    entries,
  };
}

export function applyManifestDiff(
  current: TreeManifest,
  diff: ManifestDiff,
  rootPath = ""
): TreeManifest {
  return applyManifestDiffIndexed(createManifestIndex(current), diff, rootPath).manifest;
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

export function compactMutationPaths(paths: ManifestMutationPath[]): ManifestMutationPath[] {
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

export function collectMissingBlobDigests(
  previous: TreeManifest | null | undefined,
  next: TreeManifest
): BlobDigest[] {
  return collectMissingBlobUploads(previous, next).map((upload) => upload.digest);
}

export function collectMissingBlobUploads(
  previous: TreeManifest | null | undefined,
  next: TreeManifest
): BlobUploadSource[] {
  const previousDigests = collectStoredBlobDigestSet(previous);
  const uploads = new Map<BlobDigest, BlobUploadSource>();
  for (const entry of next.entries) {
    if (entry.kind !== "file") {
      continue;
    }
    for (const source of storedBlobSources(entry)) {
      if (!previousDigests.has(source.digest) && !uploads.has(source.digest)) {
        uploads.set(source.digest, source);
      }
    }
  }
  return [...uploads.values()].sort((left, right) => comparePaths(left.digest, right.digest));
}

async function scanIntoManifest(
  root: string,
  relativeDir: string,
  entries: TreeEntry[],
  ignoreNames: ReadonlySet<string>,
  context: ScanContext
): Promise<void> {
  const directoryPath = path.join(root, relativeDir);
  const children = await readdir(directoryPath, { withFileTypes: true });
  children.sort((left, right) => comparePaths(left.name, right.name));
  for (const child of children) {
    if (!relativeDir && ignoreNames.has(child.name)) {
      continue;
    }
    const relativePath = toPosixPath(path.join(relativeDir, child.name));
    const absolutePath = path.join(root, relativePath);
    const info = await lstat(absolutePath);
    const mode = info.mode & 0o777;
    if (info.isDirectory()) {
      const entry: TreeEntry = {
        path: relativePath,
        kind: "directory",
        mode,
        size: 0,
        mtimeMs: info.mtimeMs,
        executable: Boolean(mode & 0o111),
      };
      entries.push(entry);
      rememberScanCacheEntry(context, entry, fingerprintForStats("directory", info));
      await scanIntoManifest(root, relativePath, entries, ignoreNames, context);
      continue;
    }
    if (info.isSymbolicLink()) {
      const linkTarget = await readlink(absolutePath);
      const entry: TreeEntry = {
        path: relativePath,
        kind: "symlink",
        mode,
        size: Buffer.byteLength(linkTarget),
        mtimeMs: info.mtimeMs,
        executable: false,
        linkTarget,
      };
      entries.push(entry);
      rememberScanCacheEntry(context, entry, fingerprintForStats("symlink", info, linkTarget));
      continue;
    }
    if (!info.isFile()) {
      continue;
    }
    const fileFingerprint = fingerprintForStats("file", info);
    const cached = context.cache?.entries[relativePath];
    if (
      cached?.entry.kind === "file" &&
      scanFingerprintsEqual(cached.fingerprint, fileFingerprint)
    ) {
      entries.push(cached.entry);
      rememberScanCacheEntry(context, cached.entry, cached.fingerprint);
      continue;
    }
    const scanned = await scanStableFile(absolutePath, context.options);
    const fileEntry: TreeEntry = {
      path: relativePath,
      kind: "file",
      mode: scanned.mode,
      size: scanned.size,
      mtimeMs: scanned.mtimeMs,
      executable: Boolean(scanned.mode & 0o111),
      blob: {
        digest: scanned.digest,
        size: scanned.size,
        compression: "none",
        packed: false,
      },
    };
    if (scanned.chunks) {
      fileEntry.chunks = scanned.chunks;
    }
    entries.push(fileEntry);
    rememberScanCacheEntry(context, fileEntry, {
      kind: "file",
      mode: scanned.mode,
      size: scanned.size,
      mtimeMs: scanned.mtimeMs,
      ctimeMs: scanned.ctimeMs,
    });
  }
}

async function scanPathIntoManifest(
  root: string,
  relativePath: string,
  entriesByPath: Map<string, TreeEntry>,
  ignoreNames: ReadonlySet<string>,
  context: ScanContext
): Promise<void> {
  const normalizedPath = normalizeVolumePath(relativePath);
  const topLevelName = normalizedPath.split("/")[0];
  if (topLevelName && ignoreNames.has(topLevelName)) {
    return;
  }
  const absolutePath = resolveEntryPath(root, normalizedPath);
  const info = await lstat(absolutePath).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  });
  if (!info) {
    return;
  }
  const mode = info.mode & 0o777;
  if (info.isDirectory()) {
    const entry: TreeEntry = {
      path: normalizedPath,
      kind: "directory",
      mode,
      size: 0,
      mtimeMs: info.mtimeMs,
      executable: Boolean(mode & 0o111),
    };
    entriesByPath.set(normalizedPath, entry);
    rememberScanCacheEntry(context, entry, fingerprintForStats("directory", info));
    const nested: TreeEntry[] = [];
    await scanIntoManifest(root, normalizedPath, nested, ignoreNames, context);
    for (const entry of nested) {
      entriesByPath.set(entry.path, entry);
    }
    return;
  }
  if (info.isSymbolicLink()) {
    const linkTarget = await readlink(absolutePath);
    const entry: TreeEntry = {
      path: normalizedPath,
      kind: "symlink",
      mode,
      size: Buffer.byteLength(linkTarget),
      mtimeMs: info.mtimeMs,
      executable: false,
      linkTarget,
    };
    entriesByPath.set(normalizedPath, entry);
    rememberScanCacheEntry(context, entry, fingerprintForStats("symlink", info, linkTarget));
    return;
  }
  if (!info.isFile()) {
    return;
  }
  const fileFingerprint = fingerprintForStats("file", info);
  const cached = context.cache?.entries[normalizedPath];
  if (
    cached?.entry.kind === "file" &&
    scanFingerprintsEqual(cached.fingerprint, fileFingerprint)
  ) {
    entriesByPath.set(normalizedPath, cached.entry);
    rememberScanCacheEntry(context, cached.entry, cached.fingerprint);
    return;
  }
  const scanned = await scanStableFile(absolutePath, context.options);
  const fileEntry: TreeEntry = {
    path: normalizedPath,
    kind: "file",
    mode: scanned.mode,
    size: scanned.size,
    mtimeMs: scanned.mtimeMs,
    executable: Boolean(scanned.mode & 0o111),
    blob: {
      digest: scanned.digest,
      size: scanned.size,
      compression: "none",
      packed: false,
    },
  };
  if (scanned.chunks) {
    fileEntry.chunks = scanned.chunks;
  }
  entriesByPath.set(fileEntry.path, fileEntry);
  rememberScanCacheEntry(context, fileEntry, {
    kind: "file",
    mode: scanned.mode,
    size: scanned.size,
    mtimeMs: scanned.mtimeMs,
    ctimeMs: scanned.ctimeMs,
  });
}

function compactDirtyScanPaths(
  dirtyPaths: readonly string[],
  ignoreNames: ReadonlySet<string>
): string[] {
  const normalized = new Set<string>();
  for (const dirtyPath of dirtyPaths) {
    const value = normalizeVolumePath(dirtyPath);
    const topLevelName = value.split("/")[0];
    if (topLevelName && ignoreNames.has(topLevelName)) {
      continue;
    }
    normalized.add(value);
  }
  const sorted = [...normalized].sort(
    (left, right) => comparePaths(left, right) || left.length - right.length
  );
  const compacted: string[] = [];
  for (const candidate of sorted) {
    if (
      compacted.some(
        (existing) => existing === "" || candidate === existing || candidate.startsWith(`${existing}/`)
      )
    ) {
      continue;
    }
    compacted.push(candidate);
  }
  return compacted;
}

function scanContext(options: ScanWorkspaceOptions): ScanContext {
  const context: ScanContext = {
    options: normalizedScanOptions(options),
  };
  if (options.cache) {
    options.cache.changed = false;
    context.cache = options.cache;
    context.nextCache = emptyScanWorkspaceCache();
  }
  return context;
}

function rememberScanCacheEntry(
  context: ScanContext,
  entry: TreeEntry,
  fingerprint: ScanWorkspaceFingerprint
): void {
  if (!context.nextCache) {
    return;
  }
  const previous = context.cache?.entries[entry.path];
  if (
    !previous ||
    !scanFingerprintsEqual(previous.fingerprint, fingerprint) ||
    stableJson(comparableEntry(previous.entry)) !== stableJson(comparableEntry(entry))
  ) {
    context.nextCache.changed = true;
  }
  context.nextCache.entries[entry.path] = {
    fingerprint,
    entry,
  };
}

function finalizeScanCache(context: ScanContext, entries: readonly TreeEntry[]): BlobDigest | undefined {
  if (!context.cache || !context.nextCache) {
    return undefined;
  }
  const previousEntries = context.cache.entries;
  const previousTreeHash = context.cache.treeHash;
  const finalized = emptyScanWorkspaceCache();
  for (const entry of entries) {
    const next = context.nextCache.entries[entry.path];
    const previous = context.cache.entries[entry.path];
    if (next) {
      finalized.entries[entry.path] = next;
    } else if (
      previous &&
      stableJson(comparableEntry(previous.entry)) === stableJson(comparableEntry(entry))
    ) {
      finalized.entries[entry.path] = previous;
    }
  }
  const previousKeys = Object.keys(previousEntries);
  const finalizedKeys = Object.keys(finalized.entries);
  const removedOrAdded =
    previousKeys.length !== finalizedKeys.length ||
    previousKeys.some((key) => finalized.entries[key] === undefined);
  context.cache.changed = Boolean(context.nextCache.changed || removedOrAdded);
  context.cache.entries = finalized.entries;
  return !context.cache.changed && previousTreeHash ? previousTreeHash : undefined;
}

function rememberScanCacheTreeHash(context: ScanContext, treeHash: BlobDigest): void {
  if (!context.cache) {
    return;
  }
  if (context.cache.treeHash !== treeHash) {
    context.cache.treeHash = treeHash;
    context.cache.changed = true;
  }
}

function fingerprintForStats(
  kind: TreeEntry["kind"],
  info: Stats,
  linkTarget?: string
): ScanWorkspaceFingerprint {
  return Object.assign(
    {
      kind,
      mode: info.mode & 0o777,
      size: kind === "directory" ? 0 : info.size,
      mtimeMs: info.mtimeMs,
      ctimeMs: info.ctimeMs,
    },
    linkTarget === undefined ? {} : { linkTarget }
  );
}

async function fingerprintForManifestEntry(
  targetPath: string,
  entry: TreeEntry,
  info: Stats
): Promise<ScanWorkspaceFingerprint | undefined> {
  if (entry.kind === "directory") {
    if (!info.isDirectory()) {
      return undefined;
    }
    return fingerprintForStats("directory", info);
  }
  if (entry.kind === "symlink") {
    if (!info.isSymbolicLink()) {
      return undefined;
    }
    const linkTarget = await readlink(targetPath);
    if (linkTarget !== (entry.linkTarget ?? "")) {
      return undefined;
    }
    return fingerprintForStats("symlink", info, linkTarget);
  }
  if (!info.isFile()) {
    return undefined;
  }
  return fingerprintForStats("file", info);
}

function scanFingerprintsEqual(
  left: ScanWorkspaceFingerprint,
  right: ScanWorkspaceFingerprint
): boolean {
  return (
    left.kind === right.kind &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    (left.linkTarget ?? "") === (right.linkTarget ?? "")
  );
}

function resolveEntryPath(root: string, relativePath: string): string {
  const target = path.resolve(root, relativePath);
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
    throw new Error(`Manifest path escapes workspace root: ${relativePath}`);
  }
  return target;
}

function toPosixPath(value: string): string {
  return value.split(path.sep).join(path.posix.sep);
}

function normalizedScanOptions(
  options: ScanWorkspaceOptions
): NormalizedScanOptions {
  return {
    largeFileThresholdBytes:
      options.largeFileThresholdBytes ?? defaultLargeFileThresholdBytes,
    largeFileChunkBytes: options.largeFileChunkBytes ?? defaultLargeFileChunkBytes,
    stableReadRetries: options.stableReadRetries ?? defaultStableReadRetries,
  };
}

function collectStoredBlobDigestSet(
  manifest: TreeManifest | null | undefined
): Set<BlobDigest> {
  const digests = new Set<BlobDigest>();
  for (const entry of manifest?.entries ?? []) {
    for (const source of storedBlobSources(entry)) {
      digests.add(source.digest);
    }
  }
  return digests;
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

async function scanStableFile(
  absolutePath: string,
  options: NormalizedScanOptions
): Promise<{
  digest: BlobDigest;
  size: number;
  mode: number;
  mtimeMs: number;
  ctimeMs: number;
  chunks?: ChunkRef[];
}> {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt < options.stableReadRetries; attempt += 1) {
    const before = await lstat(absolutePath);
    try {
      const scanned =
        before.size >= options.largeFileThresholdBytes && before.size > 0
          ? await scanChunkedFile(absolutePath, before.size, options.largeFileChunkBytes)
          : await scanWholeFile(absolutePath);
      const after = await lstat(absolutePath);
      if (before.size === after.size && before.mtimeMs === after.mtimeMs) {
        return {
          ...scanned,
          size: after.size,
          mode: after.mode & 0o777,
          mtimeMs: after.mtimeMs,
          ctimeMs: after.ctimeMs,
        };
      }
      lastError = new Error(`File changed while scanning: ${absolutePath}`);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
    }
  }
  throw lastError ?? new Error(`Could not scan stable file: ${absolutePath}`);
}

async function scanWholeFile(absolutePath: string): Promise<{
  digest: BlobDigest;
  chunks?: ChunkRef[];
}> {
  const bytes = await readFile(absolutePath);
  return { digest: sha256Buffer(bytes) };
}

async function scanChunkedFile(
  absolutePath: string,
  size: number,
  chunkBytes: number
): Promise<{
  digest: BlobDigest;
  chunks: ChunkRef[];
}> {
  const handle = await open(absolutePath, "r");
  const fullHash = createHash("sha256");
  const chunks: ChunkRef[] = [];
  try {
    for (let offset = 0; offset < size; offset += chunkBytes) {
      const expectedBytes = Math.min(chunkBytes, size - offset);
      const bytes = await readFileRangeFromHandle(handle, expectedBytes, offset);
      fullHash.update(bytes);
      chunks.push({
        digest: sha256Buffer(bytes),
        size: bytes.byteLength,
        offset,
      });
    }
  } finally {
    await handle.close();
  }
  return {
    digest: `sha256:${fullHash.digest("hex")}`,
    chunks,
  };
}

async function readFileRangeFromHandle(
  handle: Awaited<ReturnType<typeof open>>,
  size: number,
  offset: number
): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(size);
  let readOffset = 0;
  while (readOffset < size) {
    const result = await handle.read(
      buffer,
      readOffset,
      size - readOffset,
      offset + readOffset
    );
    if (result.bytesRead === 0) {
      throw new Error(`Unexpected EOF while reading file chunk at ${offset}.`);
    }
    readOffset += result.bytesRead;
  }
  return buffer;
}
