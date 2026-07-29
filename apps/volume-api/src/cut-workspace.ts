import {
  PFT2_ROOT_INO,
  Pft2FileKind,
  Pft2NotFoundError,
  type Pft2InodeView,
  type Pft2Ref,
} from "@portablefs/core";
import {
  MetadataConflictError,
  type HistoryCutStatus,
  type MetadataRepository,
  type SnapshotCutRecord,
} from "@portablefs/metadata-db";
import { VolumeApiError } from "./errors.js";
import { BoundedGrepScanner, type GrepStoppedReason } from "./grep-engine.js";
import {
  openPft2CommitTree,
  readPft2Range,
  resolvePft2Path,
  mapPft2ReadError,
  type Pft2CommitTree,
  type Pft2ReadContext,
} from "./pft2-read.js";

// ---------------------------------------------------------------------------
// Cut-based reads for grep on journal-served branches.
//
// A journal-served branch has no manifest head: its live truth is the fenced
// Postgres journal. Grep therefore runs against an immutable HistoryCut —
// the same primitive `portablefs snapshot` uses:
//
// 1. Resolve the read source (resolveCutReadSource): REUSE the branch's
//    newest READY cut when one exists; mint one through metadata.snapshotCut
//    and wait (bounded) for the resident history worker only when the branch
//    has no ready cut at all.
// 2. Scan the tree directly through the verified exact-key read path
//    (grepPft2Commit), without materializing a host workspace.
//
// BOUNDED STALENESS CONTRACT: grep answers an exact immutable state of the
// branch, at most as old as the branch's last ready cut. Staleness is the
// time since that cut was published — with chained/rolling cuts the history
// worker keeps that to seconds. Callers that need the exact CURRENT journal
// position take a snapshot (which always mints at the live boundary) and
// grep that.
//
// Every object byte flows through the same positive-proof discipline as
// GET /v1/history/objects: DB-recorded exact storage keys, size- and
// digest-verified before decode. Nothing here writes journal state; writes
// on a live branch flow only through the single ordered authority
// (`portablefs mount`) and are refused at the route.
// ---------------------------------------------------------------------------

/** The minimal cut-facts surface the exact read path needs (see history.ts). */
export interface CutFactsReader {
  cutStatus(tenantId: string, cutId: string): Promise<HistoryCutStatus | null>;
}

export type CutReadSource =
  // A PFT2 commit published by a ready cut (or already installed as the
  // branch head). cutId is present when a cut record names the commit;
  // reusedCut marks a served-without-minting answer.
  | { kind: "pft2"; commitId: string; cutId?: string; reusedCut: boolean }
  // An unclaimed managed branch whose head is still a manifest_v1 commit
  // (e.g. the journal-born genesis before the first authority claim): the
  // pinned immutable manifest IS the exact live state.
  | { kind: "manifest"; commitId: string };

export interface ResolveCutSourceInput {
  metadata: MetadataRepository;
  cutFacts: CutFactsReader;
  tenantId: string;
  volumeId: string;
  branchName: string;
  route: "live_cut" | "latest_ready_cut";
  /** Absolute deadline for cut readiness (the request's setup share). */
  readyDeadlineAt: number;
  signal: AbortSignal;
}

// Newest-first ready candidates are re-proven through cutStatus; the scan is
// bounded so a pathological record list cannot turn resolution into O(cuts)
// database reads.
const maxReuseCandidateChecks = 4;
const cutReadyPollIntervalMs = 150;

/**
 * Resolves the immutable source grep on a journal-served branch scans. Live
 * branches REUSE the branch's newest READY cut whenever one exists —
 * regardless of its age — and mint a fresh cut (waiting bounded for the
 * resident history worker) only when NO ready cut exists. Staleness is
 * therefore bounded by the time since the last ready cut was published (see
 * the module header). Terminal (retiring/retired) branches run against their
 * newest ready cut, which is their truth by definition.
 */
export async function resolveCutReadSource(
  input: ResolveCutSourceInput
): Promise<CutReadSource> {
  if (input.route === "latest_ready_cut") {
    return resolveLatestReadyCut(input);
  }

  // The branch's current journal position. null = no nonterminal generation:
  // the branch head commit IS the live state (nothing has ever been
  // journaled past it, and a newest ready cut could only be older than the
  // installed head), and the repository would refuse a capture typed.
  const binding = input.metadata.journalBinding
    ? await input.metadata.journalBinding({
        tenantId: input.tenantId,
        volumeId: input.volumeId,
        branchName: input.branchName,
      })
    : undefined;
  if (binding === null) {
    return resolveHeadCommitSource(input);
  }
  const reused = await findNewestReadyCut(input);
  if (reused) {
    return reused;
  }
  // No ready cut exists yet — capture a fresh one and wait bounded.
  return mintAndAwaitCut(input);
}

async function resolveLatestReadyCut(input: ResolveCutSourceInput): Promise<CutReadSource> {
  const records = input.metadata.listSnapshotRecords
      ? await input.metadata.listSnapshotRecords({
        tenantId: input.tenantId,
        volumeId: input.volumeId,
        branchName: input.branchName,
      })
    : [];
  // Records are oldest-first; the newest READY cut-backed record is the
  // branch's terminal truth. Commit-pinned (manifest snapshot) records are
  // not cuts and never serve a retiring/retired branch.
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const record = records[index] as SnapshotCutRecord;
    if (record.state === "ready" && record.cutId && record.resultCommitId) {
      return {
        kind: "pft2",
        commitId: record.resultCommitId,
        cutId: record.cutId,
        reusedCut: true,
      };
    }
  }
  throw new VolumeApiError(
    "HISTORY_CUT_REQUIRED",
    "This branch is retired from live service and has no ready history cut to run against.",
    409
  );
}

// An unclaimed managed branch: the head commit is the exact live state. A
// pft2 head (branch-from-cut, fork, conversion) reads through the verified
// PFT2 path; a manifest_v1 head (journal-born genesis) reads its pinned
// immutable manifest.
async function resolveHeadCommitSource(input: ResolveCutSourceInput): Promise<CutReadSource> {
  const branches = await input.metadata.listBranches({
    tenantId: input.tenantId,
    volumeId: input.volumeId,
  });
  const branch = branches.find((candidate) => candidate.name === input.branchName);
  if (!branch) {
    throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume or branch not found.", 404);
  }
  if (!input.metadata.commitKind) {
    throw new VolumeApiError(
      "VOLUME_BRANCH_MODE_UNAVAILABLE",
      "This metadata repository cannot resolve commit families; the route fails closed.",
      503
    );
  }
  const kind = await input.metadata.commitKind(branch.headCommitId);
  if (kind === "pft2") {
    return { kind: "pft2", commitId: branch.headCommitId, reusedCut: true };
  }
  if (kind === "manifest_v1") {
    return { kind: "manifest", commitId: branch.headCommitId };
  }
  throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume or branch head not found.", 404);
}

// The branch's newest READY cut, re-proven through the full cut facts: a
// stale record projection (canceled cut, missing result commit) never
// serves. Any ready cut is an exact immutable state of this branch — age
// only bounds staleness, never exactness.
async function findNewestReadyCut(input: ResolveCutSourceInput): Promise<CutReadSource | null> {
  if (!input.metadata.listSnapshotRecords) {
    return null;
  }
  const records = await input.metadata.listSnapshotRecords({
    tenantId: input.tenantId,
    volumeId: input.volumeId,
    branchName: input.branchName,
  });
  let checks = 0;
  for (let index = records.length - 1; index >= 0 && checks < maxReuseCandidateChecks; index -= 1) {
    const record = records[index] as SnapshotCutRecord;
    if (record.state !== "ready" || !record.cutId || !record.resultCommitId) {
      continue;
    }
    checks += 1;
    const status = await input.cutFacts.cutStatus(input.tenantId, record.cutId);
    if (!status || status.state !== "ready" || !status.resultCommitId) {
      continue;
    }
    return {
      kind: "pft2",
      commitId: status.resultCommitId,
      cutId: status.cutId,
      reusedCut: true,
    };
  }
  return null;
}

async function mintAndAwaitCut(input: ResolveCutSourceInput): Promise<CutReadSource> {
  if (!input.metadata.snapshotCut) {
    throw new VolumeApiError(
      "VOLUME_BRANCH_MODE_UNAVAILABLE",
      "This metadata repository cannot capture history cuts; the route fails closed.",
      503
    );
  }
  const record = await input.metadata.snapshotCut({
    volumeId: input.volumeId,
    branchName: input.branchName,
    tenantId: input.tenantId,
  });
  if (record.state === "failed" || record.state === "canceled") {
    throw cutFailed(record.state);
  }
  if (record.state === "ready") {
    if (record.resultCommitId && record.cutId) {
      // The dedup key converged onto an already-ready cut at this boundary.
      return { kind: "pft2", commitId: record.resultCommitId, cutId: record.cutId, reusedCut: true };
    }
    if (!record.cutId) {
      // The repository re-resolved the branch as manifest-headed (a capture
      // raced the generation teardown): the commit-pinned record is exact.
      return { kind: "manifest", commitId: record.commitId };
    }
  }
  const cutId = record.cutId ?? record.id;
  const status = await waitForCutReady(input, cutId);
  if (!status.resultCommitId) {
    throw new MetadataConflictError(
      "VOLUME_SNAPSHOT_CUT_INVALID",
      "A ready cut carried no result commit.",
      500
    );
  }
  return { kind: "pft2", commitId: status.resultCommitId, cutId, reusedCut: false };
}

async function waitForCutReady(
  input: ResolveCutSourceInput,
  cutId: string
): Promise<HistoryCutStatus> {
  for (;;) {
    throwIfAborted(input.signal, "The cut readiness wait was aborted.");
    const status = await input.cutFacts.cutStatus(input.tenantId, cutId);
    if (!status) {
      throw new MetadataConflictError(
        "VOLUME_SNAPSHOT_CUT_INVALID",
        "The captured cut no longer resolves.",
        500
      );
    }
    if (status.state === "ready") {
      return status;
    }
    if (status.state === "failed" || status.state === "canceled") {
      throw cutFailed(status.state);
    }
    const remainingMs = input.readyDeadlineAt - Date.now();
    if (remainingMs <= 0) {
      throw new VolumeApiError(
        "HISTORY_CUT_NOT_READY",
        "The live-state cut did not materialize within the request's setup budget; retry.",
        409
      );
    }
    await sleepWithSignal(Math.min(cutReadyPollIntervalMs, remainingMs), input.signal);
  }
}

function cutFailed(state: "failed" | "canceled"): VolumeApiError {
  return new VolumeApiError(
    "HISTORY_CUT_FAILED",
    `The live-state cut is ${state} and cannot serve this read.`,
    409
  );
}

// ---------------------------------------------------------------------------
// Grep directly over a PFT2 commit (no workspace).
// ---------------------------------------------------------------------------

const grepReadWindowBytes = 4n * 1024n * 1024n;
const directoryPageSize = 500;

export interface Pft2GrepInput {
  /** Normalized volume path ("" = root). */
  directory: string;
  recursive: boolean;
  signal: AbortSignal;
  scanner: BoundedGrepScanner;
}

export interface Pft2GrepResult {
  matches: Array<{ file: string; line: number; text: string }>;
  stoppedReason: GrepStoppedReason;
}

/**
 * Scans one PFT2 commit's files for regex matches, mirroring the legacy
 * manifest grep contract: a nonexistent directory yields zero matches (not a
 * 404), while bytes stream through bounded windows into the shared scanner.
 */
export async function grepPft2Commit(
  context: Pft2ReadContext,
  commitId: string,
  input: Pft2GrepInput
): Promise<Pft2GrepResult> {
  const opened = await openPft2CommitTree(context, commitId);
  if (!opened) {
    throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume, branch, or commit not found.", 404);
  }
  try {
    let start;
    try {
      start = await resolvePft2Path(opened.reader, input.directory);
    } catch (error) {
      // Legacy grep filters manifest entries by prefix: a directory that
      // does not exist scans nothing and completes empty.
      if (isPathNotFound(error)) {
        return { matches: input.scanner.matches, stoppedReason: input.scanner.stoppedReason };
      }
      throw error;
    }
    if (start.inode.kind === Pft2FileKind.Regular) {
      // Parity with the legacy prefix filter, which includes the entry whose
      // path EQUALS the requested directory.
      await grepFile(opened, input.scanner, start, input.directory);
    } else if (start.inode.kind === Pft2FileKind.Directory) {
      await grepDirectory(opened, input, start.ref, input.directory);
    }
  } catch (error) {
    throw mapPft2ReadError(error);
  }
  return { matches: input.scanner.matches, stoppedReason: input.scanner.stoppedReason };
}

async function grepDirectory(
  opened: Pft2CommitTree,
  input: Pft2GrepInput,
  dirRef: Pft2Ref,
  dirPath: string
): Promise<boolean> {
  let cursor = "";
  for (;;) {
    if (!input.scanner.checkpoint()) {
      return false;
    }
    const page = await opened.reader.readDir(dirRef, cursor, directoryPageSize);
    for (const entry of page.entries) {
      if (!input.scanner.checkpoint()) {
        return false;
      }
      const view = await opened.reader.getInode(entry.ino);
      const entryPath = dirPath === "" ? entry.name : `${dirPath}/${entry.name}`;
      if (view.inode.kind === Pft2FileKind.Regular) {
        if (!(await grepFile(opened, input.scanner, view, entryPath))) {
          return false;
        }
      } else if (view.inode.kind === Pft2FileKind.Directory && input.recursive) {
        if (!(await grepDirectory(opened, input, view.ref, entryPath))) {
          return false;
        }
      }
    }
    if (page.next === "") {
      return true;
    }
    cursor = page.next;
  }
}

async function grepFile(
  opened: Pft2CommitTree,
  scanner: BoundedGrepScanner,
  view: Pft2InodeView,
  filePath: string
): Promise<boolean> {
  return scanner.scanFile(filePath, view.inode.size, pft2FileBytes(opened, view));
}

async function* pft2FileBytes(
  opened: Pft2CommitTree,
  view: Pft2InodeView
): AsyncGenerator<Buffer> {
  const size = view.inode.size;
  let offset = 0n;
  while (offset < size) {
    const window = size - offset < grepReadWindowBytes ? size - offset : grepReadWindowBytes;
    const bytes = view.inode.extentRoot
      ? await readPft2Range(opened, view.ref, offset, window)
      : zeroBuffer(window);
    offset += window;
    yield bytes;
  }
}

function zeroBuffer(length: bigint): Buffer {
  return Buffer.alloc(Number(length));
}

function isPathNotFound(error: unknown): boolean {
  if (error instanceof Pft2NotFoundError) {
    return true;
  }
  return error instanceof MetadataConflictError && error.code === "VOLUME_PATH_NOT_FOUND";
}

// ---------------------------------------------------------------------------
// Small shared primitives.
// ---------------------------------------------------------------------------

function throwIfAborted(signal: AbortSignal, message: string): void {
  if (signal.aborted) {
    throw new DOMException(message, "AbortError");
  }
}

function sleepWithSignal(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException("The cut readiness wait was aborted.", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
