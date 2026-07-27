import type { IncomingMessage, ServerResponse } from "node:http";
import {
  PFT2_CELL_BYTES,
  PFT2_ROOT_INO,
  Pft2BoundExceededError,
  Pft2CorruptError,
  Pft2FileKind,
  Pft2NotFoundError,
  Pft2TreeReader,
  verifyCellBytes,
  type Pft2BaseTree,
  type Pft2Extent,
  type Pft2Fetcher,
  type Pft2Inode,
  type Pft2Ref,
} from "@portablefs/core";
import {
  MetadataConflictError,
  type PostgresHistoryRepository,
} from "@portablefs/metadata-db";
import type { VolumeTreeEntry, VolumeTreeResponse } from "@portablefs/protocol";
import type { HistoryStoreRegistry } from "./history-stores.js";
import {
  HistoryServingUnavailableError,
  parseObjectLocation,
  readVerifiedCopy,
} from "./history-serving.js";
import type { VolumeApiTelemetry } from "./telemetry.js";
import { VolumeApiError } from "./errors.js";

// ---------------------------------------------------------------------------
// Tree/file browse over PFT2 commits.
//
// A pft2 commit carries no JSON manifest: its content is the content-
// addressed PFT2 root recorded in pfh.pft2_commits. Browse resolves the
// commit's DB-proven provenance first (positive proof that a ready cut
// published it), then reads objects lazily through the strict PFT2 reader —
// every fetched node is size-bounded and hash-verified before decode, and
// every byte comes from database-recorded exact storage keys in declared
// failure domains (the same read discipline as GET /v1/history/objects).
//
// The wire shapes are the frozen browse contracts. Two documented
// differences from manifest listings, inherent to the format: entries come
// in PFT2's canonical raw-byte name order (not directories-first), and file
// entries carry no whole-file sha256 digest (PFT2 content is page-addressed).
// ---------------------------------------------------------------------------

const maxPft2FileResponseBytes = 64 * 1024 * 1024;

export interface Pft2ReadContext {
  history: PostgresHistoryRepository;
  stores: HistoryStoreRegistry;
  tenantId: string;
  requestSignal: AbortSignal;
  events: VolumeApiTelemetry;
  copyTimeoutMs: number;
}

/** Pft2Fetcher over the located-copy verified read path. */
class HistoryObjectFetcher implements Pft2Fetcher {
  constructor(private readonly context: Pft2ReadContext) {}

  async fetch(ref: Pft2Ref): Promise<Uint8Array> {
    const digest = `sha256:${Buffer.from(ref.digest).toString("hex")}`;
    const location = await this.context.history.locateObject(
      this.context.tenantId,
      "pft2",
      digest
    );
    const parsed = parseObjectLocation(location, this.context.tenantId, digest);
    if (!parsed || parsed.copies.length === 0) {
      throw new HistoryServingUnavailableError();
    }
    return readVerifiedCopy(
      this.context.history,
      this.context.stores,
      parsed,
      this.context.requestSignal,
      this.context.events,
      this.context.copyTimeoutMs
    );
  }
}

export interface Pft2CommitTree {
  reader: Pft2BaseTree;
  fetcher: Pft2Fetcher;
  rootDigestHex: string;
}

/**
 * Opens one pft2 commit for reading: provenance proof first (the commit must
 * be a ready cut's published result for THIS tenant), then a bounded lazy
 * reader over its verified object closure.
 */
export async function openPft2CommitTree(
  context: Pft2ReadContext,
  commitId: string
): Promise<Pft2CommitTree | null> {
  const provenance = await context.history.pft2CommitProvenance(context.tenantId, commitId);
  if (!provenance) {
    return null;
  }
  const rootDigest = provenance.rootDigest;
  const rootSize = BigInt(provenance.rootSize);
  if (!/^[0-9a-f]{64}$/u.test(rootDigest) || rootSize <= 0n) {
    throw new MetadataConflictError(
      "HISTORY_BASE_PROOF_REJECTED",
      "PFT2 commit provenance is malformed.",
      409
    );
  }
  const fetcher = new HistoryObjectFetcher(context);
  const rootRef: Pft2Ref = { digest: Buffer.from(rootDigest, "hex"), size: rootSize };
  const reader = new Pft2TreeReader({ fetcher }, rootRef);
  return { reader, fetcher, rootDigestHex: rootDigest };
}

export interface ResolvedPft2Path {
  inode: Pft2Inode;
  ref: Pft2Ref;
}

// Walks one volume path segment by segment from the root inode. Every hop is
// a verified lookup; a missing segment is the typed browse 404.
export async function resolvePft2Path(tree: Pft2BaseTree, path: string): Promise<ResolvedPft2Path> {
  let view = await tree.getInode(PFT2_ROOT_INO);
  if (path === "") {
    return { inode: view.inode, ref: view.ref };
  }
  for (const segment of path.split("/")) {
    if (view.inode.kind !== Pft2FileKind.Directory) {
      throw new MetadataConflictError("VOLUME_PATH_NOT_FOUND", `No such path: ${path}`, 404);
    }
    let entry;
    try {
      entry = await tree.lookup(view.ref, segment);
    } catch (error) {
      if (error instanceof Pft2NotFoundError) {
        throw new MetadataConflictError("VOLUME_PATH_NOT_FOUND", `No such path: ${path}`, 404);
      }
      throw error;
    }
    view = await tree.getInode(entry.ino);
  }
  return { inode: view.inode, ref: view.ref };
}

function pft2EntryKind(kind: Pft2FileKind): "file" | "directory" | "symlink" {
  if (kind === Pft2FileKind.Directory) {
    return "directory";
  }
  if (kind === Pft2FileKind.Symlink) {
    return "symlink";
  }
  return "file";
}

function pft2InodeToBrowseEntry(name: string, path: string, inode: Pft2Inode): VolumeTreeEntry {
  const kind = pft2EntryKind(inode.kind);
  return {
    name,
    path,
    kind,
    size: Number(inode.size),
    mode: inode.mode,
    executable: kind === "file" && (inode.mode & 0o111) !== 0,
    mtimeMs: Number(inode.mtimeMs),
    ...(kind === "symlink" ? { linkTarget: inode.symlinkTarget } : {}),
    // PFT2 file content is page-addressed; there is no whole-file sha256 to
    // advertise (the optional digest field is absent on pft2 listings).
  };
}

function parsePft2BrowseLimit(raw: string | null): number {
  const parsed = raw ? Number(raw) : 500;
  if (!Number.isFinite(parsed)) {
    return 500;
  }
  return Math.max(1, Math.min(Math.trunc(parsed), 2000));
}

export async function browsePft2Tree(
  context: Pft2ReadContext,
  input: {
    volumeId: string;
    branchName: string;
    commitId: string;
    treeHash: string;
    path: string;
    url: URL;
  }
): Promise<VolumeTreeResponse> {
  const opened = await openPft2CommitTree(context, input.commitId);
  if (!opened) {
    throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume, branch, or commit not found.", 404);
  }
  const limit = parsePft2BrowseLimit(input.url.searchParams.get("limit"));
  const cursor = input.url.searchParams.get("cursor") ?? "";
  try {
    const resolved = await resolvePft2Path(opened.reader, input.path);
    if (resolved.inode.kind !== Pft2FileKind.Directory) {
      throw new MetadataConflictError(
        "VOLUME_PATH_NOT_DIRECTORY",
        `Not a directory: ${input.path}`,
        409
      );
    }
    const page = await opened.reader.readDir(resolved.ref, cursor, limit);
    const entries: VolumeTreeEntry[] = [];
    for (const entry of page.entries) {
      const child = await opened.reader.getInode(entry.ino);
      const childPath = input.path === "" ? entry.name : `${input.path}/${entry.name}`;
      entries.push(pft2InodeToBrowseEntry(entry.name, childPath, child.inode));
    }
    return {
      volumeId: input.volumeId,
      branchName: input.branchName,
      commitId: input.commitId,
      treeHash: input.treeHash,
      path: input.path,
      entries,
      ...(page.next !== "" ? { nextCursor: page.next } : {}),
    };
  } catch (error) {
    throw mapPft2ReadError(error);
  }
}

export async function servePft2File(
  context: Pft2ReadContext,
  req: IncomingMessage,
  res: ServerResponse,
  input: {
    commitId: string;
    path: string;
    url: URL;
  }
): Promise<void> {
  if (input.path === "") {
    throw new MetadataConflictError("VOLUME_PATH_NOT_FILE", "The volume root is a directory.", 409);
  }
  const opened = await openPft2CommitTree(context, input.commitId);
  if (!opened) {
    throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume, branch, or commit not found.", 404);
  }
  try {
    const resolved = await resolvePft2Path(opened.reader, input.path);
    // Pinned pft2 commits are immutable: their bytes are cacheable forever.
    res.setHeader("cache-control", "public, max-age=31536000, immutable");
    if (resolved.inode.kind === Pft2FileKind.Symlink) {
      const body = Buffer.from(resolved.inode.symlinkTarget, "utf8");
      res.statusCode = 200;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.setHeader("content-length", String(body.byteLength));
      res.setHeader("x-portablefs-kind", "symlink");
      res.end(body);
      return;
    }
    if (resolved.inode.kind !== Pft2FileKind.Regular) {
      throw new MetadataConflictError("VOLUME_PATH_NOT_FILE", `Not a file: ${input.path}`, 409);
    }
    res.setHeader("x-portablefs-kind", "file");
    res.setHeader("accept-ranges", "bytes");
    const size = Number(resolved.inode.size);
    if (input.url.searchParams.get("download") === "1") {
      const filename = (input.path.split("/").pop() ?? "file").replace(/["\\\r\n]/g, "_");
      res.setHeader("content-disposition", `attachment; filename="${filename}"`);
    }
    res.setHeader("content-type", "application/octet-stream");

    const range = parsePft2ByteRange(req.headers.range, size);
    if (range === "invalid") {
      res.statusCode = 416;
      res.setHeader("content-range", `bytes */${size}`);
      res.setHeader("content-length", "0");
      res.end();
      return;
    }
    const start = range ? range.start : 0;
    const end = range ? range.end : size - 1;
    const length = size === 0 ? 0 : end - start + 1;
    if (length > maxPft2FileResponseBytes) {
      throw new VolumeApiError(
        "VOLUME_RESPONSE_TOO_LARGE",
        `PFT2 file reads are bounded at ${maxPft2FileResponseBytes} bytes per request; use Range requests.`,
        413
      );
    }
    const body =
      length === 0
        ? Buffer.alloc(0)
        : await readPft2Range(opened, resolved.ref, BigInt(start), BigInt(length));
    res.statusCode = range ? 206 : 200;
    if (range) {
      res.setHeader("content-range", `bytes ${range.start}-${range.end}/${size}`);
    }
    res.setHeader("content-length", String(body.byteLength));
    res.end(body);
  } catch (error) {
    throw mapPft2ReadError(error);
  }
}

// Assembles [offset, offset+length) from present extents; absent pages and
// cells are holes that read as zero. Every cell's bytes are verified against
// its recorded cell digest (verifyCellBytes) after the pack object itself was
// digest-verified at fetch. Shared with cut-workspace materialization, which
// reads files window-by-window through it (fresh read budget per call).
export async function readPft2Range(
  tree: Pft2CommitTree,
  file: Pft2Ref,
  offset: bigint,
  length: bigint
): Promise<Buffer> {
  const out = Buffer.alloc(Number(length));
  const extents = await tree.reader.readExtents(file, offset, length);
  for (const extent of extents) {
    const bytes = await readExtentBytes(tree, extent);
    // Clamp the extent's cell window onto the requested range.
    const extentStart = extent.fileOffset;
    const copyStart = extentStart > offset ? extentStart : offset;
    const extentEnd = extentStart + extent.length;
    const rangeEnd = offset + length;
    const copyEnd = extentEnd < rangeEnd ? extentEnd : rangeEnd;
    if (copyEnd <= copyStart) {
      continue;
    }
    const sourceFrom = Number(copyStart - extentStart);
    const sourceTo = Number(copyEnd - extentStart);
    const targetAt = Number(copyStart - offset);
    Buffer.from(bytes).copy(out, targetAt, sourceFrom, sourceTo);
  }
  return out;
}

async function readExtentBytes(tree: Pft2CommitTree, extent: Pft2Extent): Promise<Uint8Array> {
  if (!extent.cell) {
    // The TS reader only emits cell-backed extents for PFT2-native files;
    // legacy adapter extents never appear under a history commit.
    throw new MetadataConflictError(
      "HISTORY_REQUEST_INVALID",
      "PFT2 extent without a cell reference.",
      500
    );
  }
  const packBytes = await tree.fetcher.fetch(extent.cell.object);
  const logicalValid = extent.length > BigInt(PFT2_CELL_BYTES) ? BigInt(PFT2_CELL_BYTES) : extent.length;
  return verifyCellBytes(extent.cell, packBytes, logicalValid);
}

type Pft2ByteRange = { start: number; end: number };

// Single-range parser per RFC 9110 (mirrors the manifest browse behavior).
function parsePft2ByteRange(
  header: string | undefined,
  size: number
): Pft2ByteRange | "invalid" | null {
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
    const suffix = Number(rawEnd);
    if (!Number.isFinite(suffix) || suffix <= 0 || size === 0) {
      return "invalid";
    }
    return { start: Math.max(0, size - suffix), end: size - 1 };
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

// PFT2 read failures map onto the serving vocabulary: absence 404s, budget
// overruns are typed 413s, and verification failures fail closed as 503
// (the copy read path already scheduled scrub work for damaged copies).
export function mapPft2ReadError(error: unknown): unknown {
  if (error instanceof Pft2NotFoundError) {
    return new MetadataConflictError("VOLUME_PATH_NOT_FOUND", "No such path.", 404);
  }
  if (error instanceof Pft2BoundExceededError) {
    return new VolumeApiError(
      "VOLUME_RESPONSE_TOO_LARGE",
      "PFT2 read exceeded its node/byte budget; narrow the request.",
      413
    );
  }
  if (error instanceof Pft2CorruptError) {
    return new MetadataConflictError(
      "HISTORY_OBJECT_UNAVAILABLE",
      "PFT2 object verification failed; the copy is queued for repair.",
      503
    );
  }
  if (error instanceof HistoryServingUnavailableError) {
    return new MetadataConflictError(
      "HISTORY_OBJECT_UNAVAILABLE",
      "No verified history object copy is currently available.",
      503
    );
  }
  return error;
}
