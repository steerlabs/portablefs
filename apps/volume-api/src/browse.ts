// Read-only browse over committed trees: GET /v1/volumes/:id/tree (directory
// listings) and GET /v1/volumes/:id/file (bytes). Both resolve a commit — the
// branch head by default, or a pinned ?commit= — and read the immutable
// manifest, so they never touch the live authority and are safe to cache.
import type { IncomingMessage, ServerResponse } from "node:http";
import { sha256Buffer, type BlobStore } from "@portablefs/core";
import { MetadataConflictError, type MetadataRepository } from "@portablefs/metadata-db";
import {
  volumePathSchema,
  type TreeEntry,
  type TreeManifest,
  type VolumeTreeEntry,
  type VolumeTreeResponse,
} from "@portablefs/protocol";

interface BrowseDeps {
  metadata: MetadataRepository;
  blobStore: BlobStore;
  browseIndexes: CommitBrowseIndexCache;
}

// One commit's manifest, indexed for directory listing and path lookup. Built
// once per commit and cached: manifests are immutable, so an index can never
// go stale — the cache is bounded only to cap memory, not for correctness.
interface CommitBrowseIndex {
  entriesByPath: Map<string, TreeEntry>;
  childrenByDir: Map<string, VolumeTreeEntry[]>;
}

export class CommitBrowseIndexCache {
  private readonly indexes = new Map<string, CommitBrowseIndex>();

  constructor(private readonly maxCommits = 8) {}

  get(commitId: string, manifest: () => TreeManifest): CommitBrowseIndex {
    const hit = this.indexes.get(commitId);
    if (hit) {
      // Refresh LRU position.
      this.indexes.delete(commitId);
      this.indexes.set(commitId, hit);
      return hit;
    }
    const built = buildCommitBrowseIndex(manifest());
    while (this.indexes.size >= this.maxCommits) {
      const oldest = this.indexes.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.indexes.delete(oldest);
    }
    this.indexes.set(commitId, built);
    return built;
  }
}

function parentDir(path: string): string {
  const slash = path.lastIndexOf("/");
  return slash === -1 ? "" : path.slice(0, slash);
}

function baseName(path: string): string {
  const slash = path.lastIndexOf("/");
  return slash === -1 ? path : path.slice(slash + 1);
}

function toBrowseEntry(entry: TreeEntry): VolumeTreeEntry {
  return {
    name: baseName(entry.path),
    path: entry.path,
    kind: entry.kind,
    size: entry.size,
    mode: entry.mode,
    executable: entry.executable,
    mtimeMs: entry.mtimeMs,
    ...(entry.linkTarget !== undefined ? { linkTarget: entry.linkTarget } : {}),
    ...(entry.kind === "file" && entry.blob ? { digest: entry.blob.digest } : {}),
  };
}

// Directories sort before files and symlinks; within each group, names sort in
// UTF-16 code unit order (plain JS `<`), matching the manifest path sort.
function compareBrowseEntries(left: VolumeTreeEntry, right: VolumeTreeEntry): number {
  const leftRank = left.kind === "directory" ? 0 : 1;
  const rightRank = right.kind === "directory" ? 0 : 1;
  if (leftRank !== rightRank) {
    return leftRank - rightRank;
  }
  return left.name < right.name ? -1 : left.name > right.name ? 1 : 0;
}

function buildCommitBrowseIndex(manifest: TreeManifest): CommitBrowseIndex {
  const entriesByPath = new Map<string, TreeEntry>();
  const childrenByDir = new Map<string, VolumeTreeEntry[]>();
  const childNamesByDir = new Map<string, Set<string>>();

  const pushChild = (dir: string, child: VolumeTreeEntry): void => {
    let names = childNamesByDir.get(dir);
    if (!names) {
      names = new Set();
      childNamesByDir.set(dir, names);
    }
    if (names.has(child.name)) {
      // An explicit entry replaces a synthesized placeholder for the same name.
      const children = childrenByDir.get(dir) ?? [];
      const index = children.findIndex((existing) => existing.name === child.name);
      if (index !== -1) {
        children[index] = child;
      }
      return;
    }
    names.add(child.name);
    const children = childrenByDir.get(dir);
    if (children) {
      children.push(child);
    } else {
      childrenByDir.set(dir, [child]);
    }
  };

  // Scanners emit explicit directory entries, but a manifest is not required to
  // include one for every ancestor — synthesize placeholders so any file's
  // ancestor chain is always listable.
  const ensureAncestors = (path: string): void => {
    let dir = parentDir(path);
    while (dir !== "" && !entriesByPath.has(dir)) {
      const placeholder: TreeEntry = {
        path: dir,
        kind: "directory",
        mode: 0o755,
        size: 0,
        mtimeMs: 0,
        executable: false,
      };
      entriesByPath.set(dir, placeholder);
      pushChild(parentDir(dir), toBrowseEntry(placeholder));
      dir = parentDir(dir);
    }
  };

  for (const entry of manifest.entries) {
    entriesByPath.set(entry.path, entry);
  }
  for (const entry of manifest.entries) {
    ensureAncestors(entry.path);
    pushChild(parentDir(entry.path), toBrowseEntry(entry));
  }
  for (const children of childrenByDir.values()) {
    children.sort(compareBrowseEntries);
  }
  return { entriesByPath, childrenByDir };
}

interface ResolvedCommit {
  commitId: string;
  branchName: string;
  treeHash: string;
  pinned: boolean;
  manifest: TreeManifest;
}

// Resolves ?branch=/&commit= to a concrete commit + manifest. A pinned commit
// must belong to the addressed volume: the tenant guard has already verified
// volume ownership, and this check stops a commit id from another of the same
// tenant's volumes (or a guessed id) from being read through this volume's URL.
async function resolveBrowseCommit(
  deps: BrowseDeps,
  tenantId: string,
  volumeId: string,
  url: URL
): Promise<ResolvedCommit | null> {
  const branchName = url.searchParams.get("branch") || "main";
  const commitParam = url.searchParams.get("commit");
  if (commitParam) {
    const commit = await deps.metadata.getCommit(commitParam);
    if (!commit || commit.volumeId !== volumeId) {
      return null;
    }
    const branches = await deps.metadata.listBranches({ tenantId, volumeId });
    const branch = branches?.find((candidate) => candidate.id === commit.branchId);
    return {
      commitId: commit.id,
      branchName: branch?.name ?? branchName,
      treeHash: commit.treeHash,
      pinned: true,
      manifest: commit.manifest,
    };
  }
  const head = await deps.metadata.getHead({ tenantId, volumeId, branchName });
  if (!head) {
    return null;
  }
  const manifest = await deps.metadata.getManifest(head.head.id);
  if (!manifest) {
    return null;
  }
  return {
    commitId: head.head.id,
    branchName: head.branch.name,
    treeHash: head.head.treeHash,
    pinned: false,
    manifest,
  };
}

function parseBrowseLimit(raw: string | null): number {
  const parsed = raw ? Number(raw) : 500;
  if (!Number.isFinite(parsed)) {
    return 500;
  }
  return Math.max(1, Math.min(Math.trunc(parsed), 2000));
}

export async function browseVolumeTree(
  deps: BrowseDeps,
  tenantId: string,
  volumeId: string,
  url: URL
): Promise<VolumeTreeResponse> {
  const path = volumePathSchema.parse(url.searchParams.get("path") ?? "");
  const limit = parseBrowseLimit(url.searchParams.get("limit"));
  const cursor = url.searchParams.get("cursor");

  const resolved = await resolveBrowseCommit(deps, tenantId, volumeId, url);
  if (!resolved) {
    throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume, branch, or commit not found.", 404);
  }
  const index = deps.browseIndexes.get(resolved.commitId, () => resolved.manifest);

  if (path !== "") {
    const entry = index.entriesByPath.get(path);
    const isDirectory = entry ? entry.kind === "directory" : index.childrenByDir.has(path);
    if (!entry && !index.childrenByDir.has(path)) {
      throw new MetadataConflictError("VOLUME_PATH_NOT_FOUND", `No such path: ${path}`, 404);
    }
    if (!isDirectory) {
      throw new MetadataConflictError(
        "VOLUME_PATH_NOT_DIRECTORY",
        `Not a directory: ${path}`,
        409
      );
    }
  }

  const children = index.childrenByDir.get(path) ?? [];
  let startIndex = 0;
  if (cursor) {
    // The cursor is the last returned child's name; resume strictly after it.
    // Names are unique within a directory, so a linear scan is exact; a missing
    // cursor name (possible only when browsing an unpinned branch that moved)
    // degrades to the nearest position by sort order.
    const probe: VolumeTreeEntry = {
      name: cursor,
      path: path === "" ? cursor : `${path}/${cursor}`,
      kind: index.entriesByPath.get(path === "" ? cursor : `${path}/${cursor}`)?.kind ?? "file",
      size: 0,
      mode: 0,
      executable: false,
      mtimeMs: 0,
    };
    while (startIndex < children.length) {
      const child = children[startIndex];
      if (!child || compareBrowseEntries(child, probe) > 0) {
        break;
      }
      startIndex += 1;
    }
  }
  const page = children.slice(startIndex, startIndex + limit);
  const lastReturned = page[page.length - 1];
  const hasMore = startIndex + limit < children.length;

  return {
    volumeId,
    branchName: resolved.branchName,
    commitId: resolved.commitId,
    treeHash: resolved.treeHash,
    path,
    entries: page,
    ...(hasMore && lastReturned ? { nextCursor: lastReturned.name } : {}),
  };
}

type ByteRange = { start: number; end: number };

// Single-range parser per RFC 9110: returns null when there is no Range header,
// "invalid" when the header is unsatisfiable or multi-range.
function parseByteRange(header: string | undefined, size: number): ByteRange | "invalid" | null {
  if (!header) {
    return null;
  }
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!match) {
    return "invalid";
  }
  const [, rawStart, rawEnd] = match;
  if (rawStart === "" && rawEnd === "") {
    return "invalid";
  }
  if (rawStart === "") {
    // Suffix range: last N bytes.
    const suffix = Number(rawEnd);
    if (!Number.isFinite(suffix) || suffix <= 0 || size === 0) {
      return "invalid";
    }
    const start = Math.max(0, size - suffix);
    return { start, end: size - 1 };
  }
  const start = Number(rawStart);
  if (!Number.isFinite(start) || start >= size) {
    return "invalid";
  }
  const end = rawEnd === "" ? size - 1 : Math.min(Number(rawEnd), size - 1);
  if (!Number.isFinite(end) || end < start) {
    return "invalid";
  }
  return { start, end };
}

function etagMatches(header: string | undefined, etag: string): boolean {
  if (!header) {
    return false;
  }
  if (header.trim() === "*") {
    return true;
  }
  return header
    .split(",")
    .map((candidate) => candidate.trim().replace(/^W\//, ""))
    .some((candidate) => candidate === etag);
}

// Reads [start, end] of a file entry. Chunked entries fetch only the chunks
// overlapping the range and are verified to tile it exactly; whole-file reads
// of chunked entries additionally verify the assembled bytes against the
// entry's whole-file digest (ranged reads cannot verify the full digest by
// construction, but never return bytes with a gap).
async function readEntryRange(
  blobStore: BlobStore,
  entry: TreeEntry,
  range: ByteRange
): Promise<Buffer> {
  if (!entry.blob) {
    return Buffer.alloc(0);
  }
  if (entry.chunks?.length) {
    const overlapping = [...entry.chunks]
      .sort((left, right) => left.offset - right.offset)
      .filter((chunk) => chunk.offset <= range.end && chunk.offset + chunk.size > range.start);
    const parts: Buffer[] = [];
    let covered = range.start;
    for (const chunk of overlapping) {
      if (chunk.offset > covered) {
        break; // gap in the chunk list
      }
      const bytes = await blobStore.get(chunk.digest);
      const sliceStart = Math.max(0, range.start - chunk.offset);
      const sliceEnd = Math.min(chunk.size, range.end + 1 - chunk.offset);
      parts.push(bytes.subarray(sliceStart, sliceEnd));
      covered = chunk.offset + sliceEnd;
    }
    if (covered < range.end + 1) {
      throw new MetadataConflictError(
        "VOLUME_BLOB_DIGEST_MISMATCH",
        `Chunk list for ${entry.path} does not cover the requested bytes.`,
        500
      );
    }
    const body = Buffer.concat(parts);
    const wholeFile = range.start === 0 && range.end === entry.size - 1;
    if (wholeFile) {
      const actual = sha256Buffer(body);
      if (actual !== entry.blob.digest) {
        throw new MetadataConflictError(
          "VOLUME_BLOB_DIGEST_MISMATCH",
          `Chunked file digest mismatch for ${entry.path}.`,
          500
        );
      }
    }
    return body;
  }
  const bytes = await blobStore.get(entry.blob.digest);
  return bytes.subarray(range.start, range.end + 1);
}

export async function serveVolumeFile(
  deps: BrowseDeps,
  req: IncomingMessage,
  res: ServerResponse,
  tenantId: string,
  volumeId: string,
  url: URL
): Promise<void> {
  const path = volumePathSchema.parse(url.searchParams.get("path") ?? "");
  if (path === "") {
    throw new MetadataConflictError("VOLUME_PATH_NOT_FILE", "The volume root is a directory.", 409);
  }
  const resolved = await resolveBrowseCommit(deps, tenantId, volumeId, url);
  if (!resolved) {
    throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume, branch, or commit not found.", 404);
  }
  const index = deps.browseIndexes.get(resolved.commitId, () => resolved.manifest);
  const entry = index.entriesByPath.get(path);
  if (!entry) {
    if (index.childrenByDir.has(path)) {
      throw new MetadataConflictError("VOLUME_PATH_NOT_FILE", `Not a file: ${path}`, 409);
    }
    throw new MetadataConflictError("VOLUME_PATH_NOT_FOUND", `No such path: ${path}`, 404);
  }
  if (entry.kind === "directory") {
    throw new MetadataConflictError("VOLUME_PATH_NOT_FILE", `Not a file: ${path}`, 409);
  }

  // Pinned commits are immutable, so their bytes are cacheable forever; branch
  // reads track a moving head and must never be cached.
  const cacheControl = resolved.pinned ? "public, max-age=31536000, immutable" : "no-store";
  res.setHeader("cache-control", cacheControl);

  if (entry.kind === "symlink") {
    const body = Buffer.from(entry.linkTarget ?? "", "utf8");
    res.statusCode = 200;
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.setHeader("content-length", String(body.byteLength));
    res.setHeader("x-portablefs-kind", "symlink");
    res.end(body);
    return;
  }

  const digest = entry.blob?.digest;
  const etag = digest ? `"${digest}"` : undefined;
  if (etag) {
    res.setHeader("etag", etag);
  }
  res.setHeader("x-portablefs-kind", "file");
  res.setHeader("accept-ranges", "bytes");

  if (etag && etagMatches(req.headers["if-none-match"], etag)) {
    res.statusCode = 304;
    res.end();
    return;
  }

  const size = entry.size;
  if (url.searchParams.get("download") === "1") {
    const filename = baseName(path).replace(/["\\\r\n]/g, "_");
    res.setHeader("content-disposition", `attachment; filename="${filename}"`);
  }
  res.setHeader("content-type", "application/octet-stream");

  const range = parseByteRange(req.headers.range, size);
  if (range === "invalid") {
    res.statusCode = 416;
    res.setHeader("content-range", `bytes */${size}`);
    res.setHeader("content-length", "0");
    res.end();
    return;
  }
  if (range) {
    const body = await readEntryRange(deps.blobStore, entry, range);
    res.statusCode = 206;
    res.setHeader("content-range", `bytes ${range.start}-${range.end}/${size}`);
    res.setHeader("content-length", String(body.byteLength));
    res.end(body);
    return;
  }

  const body =
    size === 0 ? Buffer.alloc(0) : await readEntryRange(deps.blobStore, entry, { start: 0, end: size - 1 });
  res.statusCode = 200;
  res.setHeader("content-length", String(body.byteLength));
  res.end(body);
}
