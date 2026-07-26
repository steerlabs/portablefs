import type { VolumeBranchMode } from "@portablefs/metadata-db";
import { VolumeApiError } from "./errors.js";

// ---------------------------------------------------------------------------
// THE five-state branch-mode action matrix (migration 012).
//
// Every volume/branch/session/lease-addressed route resolves the
// AUTHORITATIVE tenant-scoped branch mode first and passes exactly one row of
// this table. Design rules:
//
// - legacy_manifest is the base-authoring phase of a journal-born volume:
//   manifest reads, mutations, attaches, and exact grep reads are
//   served here — they author the committed base the journal generation
//   starts from.
// - managed_journal branches are served by the live authority (the fenced
//   Postgres journal); exact PFT2/HistoryCut reads use their separate
//   positive-proof contract. Manifest routes refuse with
//   LIVE_AUTHORITY_ROUTE_REQUIRED — the branch head is journal truth, not a
//   manifest head.
// - migrating permits only the receipted attach surface (enforced inside the
//   repository primitive); every manifest route refuses it.
// - retiring / retired are typed terminal (cut-only) states:
//   HISTORY_CUT_REQUIRED.
// - IMMUTABLE commit objects and snapshots are NOT in this matrix: a
//   manifest_v1 commit pinned by a fork/snapshot/session stays readable, and
//   an owned commit-pinned snapshot stays forkable, after its ORIGINAL branch
//   becomes journal-served. Mutable CURRENT-branch routes stay in this
//   matrix, so live journal truth can never flow through a manifest route.
// - Teardown (detach / lease renew) and manifest-free metadata enumeration
//   stay available in every mode: they expose no manifest and mint no
//   manifest writes, and blocking teardown would leak sessions/leases.
// - Exact grep is NOT an action row: it is served in every stable mode and
//   only its immutable SOURCE changes — see
//   branchModeMaterializationMatrix below.
//
// No route may infer safety from a 404, a default mode, an absent header, or
// a caller-supplied generation.
// ---------------------------------------------------------------------------

export type BranchModeAction =
  | "legacy_manifest_read"
  | "legacy_manifest_mutation"
  | "legacy_attach"
  | "session_teardown"
  | "metadata_list_read";

type BranchModeDecision = "allow" | "live_authority" | "history_cut";

const branchModeActionMatrix: Readonly<
  Record<BranchModeAction, Readonly<Record<VolumeBranchMode, BranchModeDecision>>>
> = {
  legacy_manifest_read: {
    legacy_manifest: "allow",
    migrating: "live_authority",
    managed_journal: "live_authority",
    retiring: "history_cut",
    retired: "history_cut",
  },
  legacy_manifest_mutation: {
    legacy_manifest: "allow",
    migrating: "live_authority",
    managed_journal: "live_authority",
    retiring: "history_cut",
    retired: "history_cut",
  },
  legacy_attach: {
    legacy_manifest: "allow",
    migrating: "live_authority",
    managed_journal: "live_authority",
    retiring: "history_cut",
    retired: "history_cut",
  },
  session_teardown: {
    legacy_manifest: "allow",
    migrating: "allow",
    managed_journal: "allow",
    retiring: "allow",
    retired: "allow",
  },
  metadata_list_read: {
    legacy_manifest: "allow",
    migrating: "allow",
    managed_journal: "allow",
    retiring: "allow",
    retired: "allow",
  },
};

/**
 * Applies one matrix row. `mode === null` means the addressed resource does
 * not exist; the caller's operation produces its own typed 404 — a null mode
 * never unlocks anything beyond that not-found path.
 */
export function assertBranchModeAllows(
  action: BranchModeAction,
  mode: VolumeBranchMode | null
): void {
  if (mode === null) {
    return;
  }
  const decision = branchModeActionMatrix[action][mode];
  if (decision === "allow") {
    return;
  }
  if (decision === "live_authority") {
    throw new VolumeApiError(
      "LIVE_AUTHORITY_ROUTE_REQUIRED",
      "This branch is served by a live journal authority; use the live filesystem routes instead of manifest access.",
      409
    );
  }
  throw new VolumeApiError(
    "HISTORY_CUT_REQUIRED",
    "This branch is retiring from live service; its truth is served by history cuts, not manifest access.",
    409
  );
}

// ---------------------------------------------------------------------------
// Exact grep source routing.
//
// Exact grep is served in every stable mode; only its immutable SOURCE
// differs:
//
// - legacy_manifest scans the manifest head (the authoring truth).
// - managed_journal scans an EXACT immutable HistoryCut of the live
//   state — the same primitive `portablefs snapshot` uses. A READY cut whose
//   (generation, cutSeqExclusive) equals the branch's current journal
//   position is reused instead of cutting again.
// - retiring / retired branches are truth-served by cuts already: run against
//   the newest READY cut (none recorded refuses HISTORY_CUT_REQUIRED, the
//   same terminal vocabulary as the manifest rows above).
// - migrating stays a typed refusal: the authority handover is in flight and
//   neither the manifest head nor a fresh cut is a stable statement of truth.
//
// Writes on a journal-served branch flow through the single ordered authority
// (`portablefs mount`) and never through this read-source table.
// ---------------------------------------------------------------------------

export type MaterializationRoute = "legacy_manifest" | "live_cut" | "latest_ready_cut";

const branchModeMaterializationMatrix: Readonly<
  Record<VolumeBranchMode, MaterializationRoute | "live_authority">
> = {
  legacy_manifest: "legacy_manifest",
  migrating: "live_authority",
  managed_journal: "live_cut",
  retiring: "latest_ready_cut",
  retired: "latest_ready_cut",
};

/**
 * Resolves the materialization source for one branch mode. `mode === null`
 * means the addressed resource does not exist; the legacy path produces its
 * own typed 404 — a null mode never unlocks anything beyond that not-found
 * path.
 */
export function materializationRouteFor(mode: VolumeBranchMode | null): MaterializationRoute {
  if (mode === null) {
    return "legacy_manifest";
  }
  const route = branchModeMaterializationMatrix[mode];
  if (route === "live_authority") {
    throw new VolumeApiError(
      "LIVE_AUTHORITY_ROUTE_REQUIRED",
      "This branch is migrating between authorities; neither its manifest head nor a fresh cut is stable truth. Retry once migration completes.",
      409
    );
  }
  return route;
}
