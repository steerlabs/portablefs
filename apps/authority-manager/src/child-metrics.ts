// Semantically valid, fail-closed aggregation of managed-child metrics.
//
// The manager is the ONLY scraper of the children's loopback /metrics
// listeners (child isolation is preserved), and it never "generically sums
// Prometheus lines". Every child metric flows through a CLOSED ALLOWLIST
// registry declaring its type, its safe label set, and its aggregator:
//
//   counter            -> sum across children (monotonic totals)
//   gauge_additive     -> sum (count-style gauges whose meaning is additive)
//   gauge_min          -> minimum (readiness booleans = ALL semantics;
//                         remaining-lease/freshness = worst case)
//   gauge_max          -> maximum, ONLY for metrics that are themselves max
//                         gauges (backlog age / latency maxima)
//   summary            -> _count and _sum aggregate by sum; precomputed
//                         quantile lines are DROPPED — no fake percentile is
//                         ever derived from unmergeable summaries
//   histogram          -> cumulative le-buckets aggregate bucket-by-bucket
//                         ONLY when boundaries match the declared set
//                         exactly (+Inf required); any mismatch rejects
//
// Anything else — unknown/duplicate labels, duplicate series, NaN/Inf,
// oversized responses, line/series/label/bucket overruns — marks that child's
// scrape MALFORMED: its entire contribution is dropped (one bad child cannot
// poison the aggregate) and a bounded error counter increments. Logs carry
// coarse codes only — never the target URL and never raw parse errors.
//
// TWO KINDS OF "not in the allowlist", and they are NOT the same failure.
// The allowlist exists for CARDINALITY AND NAMESPACE CONTROL: no child may
// mint a series in the manager's pfm_child_* namespace that an operator did
// not declare, and no child-chosen label may ride along. It does NOT exist to
// assert that the manager and the child were built from the same commit.
// Treating a merely UNRECOGNIZED metric name as a fatal, whole-body rejection
// conflated the two and cost the fleet all child observability: aad03e9 added
// four vcs_dirty_fold_* metrics to the child, which registers them at package
// init so they appear in EVERY exposition, and the manager then dropped every
// child's entire body — pfm_child_* vanished, including the dirty-block
// residency gauge the fold work exists to be judged by.
//
// So an unrecognized metric NAME (and a HELP/TYPE/comment line, which carries
// no series at all) is now SKIPPED AND COUNTED, never rendered and never
// aggregated: the closed namespace is preserved exactly — nothing undeclared
// reaches the output, and no child-chosen label is even inspected, let alone
// forwarded — while a version-skewed child stays fully observable for every
// metric both sides DO agree on. The drops are visible as
// pfm_child_scrape_unknown_metrics_total (an allowlist gap to close) and
// pfm_child_scrape_ignored_lines_total (comment/HELP/TYPE lines). Structural
// corruption of a KNOWN metric stays fail-closed for the whole body: that is
// a broken or hostile exporter, not a newer one.
import type { ManagerMetrics } from "./manager-metrics.js";

export type ChildMetricAggregator =
  | "counter"
  | "gauge_additive"
  | "gauge_min"
  | "gauge_max"
  | "summary"
  | "histogram";

export interface ChildMetricSpec {
  aggregator: ChildMetricAggregator;
  /** Exact le-boundaries (histogram only); must include "+Inf". */
  bucketBoundaries?: readonly string[];
}

// The closed registry of every metric the Go child exporter
// (vcs/internal/metrics + call sites) may emit. Adding a child metric
// REQUIRES adding it here with an explicit aggregator — nothing passes by
// default. The names are the hosted manager's exact allowlist (ecosystem
// compatibility: the same exposition passes both managers) extended with the
// OSS child's additions: the fixed per-op counters and the dirty-RSS gauges.
export const childMetricAllowlist: Readonly<Record<string, ChildMetricSpec>> = {
  // Readiness boolean: aggregate as ALL (minimum).
  vcs_ready: { aggregator: "gauge_min" },

  // Monotonic counters: sums are meaningful.
  vcs_fsproto_ops: { aggregator: "counter" },
  vcs_fsproto_op_getattr: { aggregator: "counter" },
  vcs_fsproto_op_readdir: { aggregator: "counter" },
  vcs_fsproto_op_read: { aggregator: "counter" },
  vcs_fsproto_op_write: { aggregator: "counter" },
  vcs_fsproto_op_create: { aggregator: "counter" },
  vcs_fsproto_op_mkdir: { aggregator: "counter" },
  vcs_fsproto_op_remove: { aggregator: "counter" },
  vcs_fsproto_op_rename: { aggregator: "counter" },
  vcs_fsproto_op_symlink: { aggregator: "counter" },
  vcs_fsproto_op_readlink: { aggregator: "counter" },
  vcs_fsproto_op_truncate: { aggregator: "counter" },
  vcs_fsproto_op_fsync: { aggregator: "counter" },
  vcs_fsproto_op_subscribe: { aggregator: "counter" },
  vcs_fsproto_op_setattr: { aggregator: "counter" },
  vcs_fsproto_op_checkout: { aggregator: "counter" },
  vcs_fsproto_op_checkin: { aggregator: "counter" },
  vcs_fsproto_op_flush_batch: { aggregator: "counter" },
  vcs_fsproto_op_lock: { aggregator: "counter" },
  vcs_fsproto_op_orphan: { aggregator: "counter" },
  vcs_fsproto_op_reap: { aggregator: "counter" },
  vcs_fsproto_op_renew_orphan_leases: { aggregator: "counter" },
  vcs_fsproto_op_mark_open: { aggregator: "counter" },
  vcs_fsproto_op_renew_open_inodes: { aggregator: "counter" },
  vcs_fsproto_op_unmark_open_inodes: { aggregator: "counter" },
  vcs_fsproto_op_getxattr: { aggregator: "counter" },
  vcs_fsproto_op_setxattr: { aggregator: "counter" },
  vcs_fsproto_op_listxattr: { aggregator: "counter" },
  vcs_fsproto_op_removexattr: { aggregator: "counter" },
  vcs_fsproto_op_link: { aggregator: "counter" },
  vcs_fsproto_op_delegation_acquire: { aggregator: "counter" },
  vcs_fsproto_op_writeback_state: { aggregator: "counter" },
  vcs_fsproto_op_writeback_rebind: { aggregator: "counter" },
  vcs_fsproto_op_writeback_discard: { aggregator: "counter" },
  vcs_fsproto_op_protocol_version: { aggregator: "counter" },
  vcs_fsproto_op_session_open: { aggregator: "counter" },
  vcs_fsproto_op_session_resume: { aggregator: "counter" },
  vcs_fsproto_op_session_attach: { aggregator: "counter" },
  vcs_fsproto_op_session_expire: { aggregator: "counter" },
  vcs_fsproto_op_invalidation_ack: { aggregator: "counter" },
  vcs_fsproto_op_delegation_prepare_release: { aggregator: "counter" },
  vcs_fsproto_op_other: { aggregator: "counter" },
  vcs_mutations: { aggregator: "counter" },
  vcs_wal_replay_skips: { aggregator: "counter" },
  // History-cut dirty fold (vcs/internal/workfs/dirtyfold.go). Registered at
  // package init, so every child exposes all four at value 0 even before a
  // fold ever runs. Released bytes / folded blocks / completed passes are
  // monotonic totals that sum across the fleet.
  vcs_dirty_fold_released_bytes: { aggregator: "counter" },
  vcs_dirty_fold_blocks: { aggregator: "counter" },
  vcs_dirty_fold_passes: { aggregator: "counter" },
  vcs_checkpoint_sidecar_overflows: { aggregator: "counter" },
  vcs_checkpoint_commits: { aggregator: "counter" },
  vcs_checkpoint_bytes: { aggregator: "counter" },
  vcs_checkpoint_reconciles: { aggregator: "counter" },
  vcs_checkpoint_control_rotations: { aggregator: "counter" },
  vcs_lifecycle_evictions: { aggregator: "counter" },
  vcs_lifecycle_eviction_drain_failures: { aggregator: "counter" },
  writeback_flush_total: { aggregator: "counter" },
  writeback_flush_records_total: { aggregator: "counter" },
  writeback_flush_errors_total: { aggregator: "counter" },
  writeback_idle_release_total: { aggregator: "counter" },
  writeback_acquire_total: { aggregator: "counter" },
  writeback_acquire_busy_total: { aggregator: "counter" },
  writeback_recovered_total: { aggregator: "counter" },
  vcs_replication_records: { aggregator: "counter" },
  vcs_bucket_fetches: { aggregator: "counter" },
  vcs_bucket_fetch_bytes: { aggregator: "counter" },
  vcs_prefetch_blobs: { aggregator: "counter" },
  vcs_prefetch_bytes: { aggregator: "counter" },
  vcs_cache_ram_hits: { aggregator: "counter" },
  vcs_cache_disk_hits: { aggregator: "counter" },
  vcs_cache_misses: { aggregator: "counter" },
  authority_ops_total: { aggregator: "counter" },

  // Count-style gauges whose meaning is additive across children.
  vcs_fsproto_conns: { aggregator: "gauge_additive" },
  writeback_sessions: { aggregator: "gauge_additive" },
  writeback_pending_records: { aggregator: "gauge_additive" },
  writeback_pending_bytes: { aggregator: "gauge_additive" },
  vcs_checkpoint_captures_active: { aggregator: "gauge_additive" },
  vcs_checkpoint_capture_retained_bytes: { aggregator: "gauge_additive" },
  // Dirty-RSS accounting (VCS_DIRTY_RSS_MAX_MB work): the resident
  // uncommitted-dirty-block bytes and the configured per-child bound. Both
  // sum meaningfully — total resident dirty bytes on the host, and the total
  // worst-case dirty budget across resident children.
  vcs_dirty_block_bytes: { aggregator: "gauge_additive" },
  vcs_dirty_block_bytes_max: { aggregator: "gauge_additive" },

  // Resident-byte pacing (vcs/internal/workfs/dirtypace.go). Above the
  // setpoint the pacer admits a dirty byte only behind an OBSERVED release,
  // so accepted rate converges on release rate by construction rather than by
  // estimate. Waits / wait-nanos / refusals and released-bytes are monotonic
  // per-child totals that sum across the fleet. The setpoint is a per-child
  // level in bytes and the release rate a per-child byte rate; both sum to a
  // meaningful host-wide total, exactly like vcs_dirty_block_bytes above.
  // vcs_dirty_release_bytes_per_sec is TELEMETRY ONLY — nothing in the
  // admission path reads it, deliberately: a rate estimate goes optimistic
  // precisely when the relief plane is collapsing under WAL back-pressure.
  vcs_dirty_pace_waits: { aggregator: "counter" },
  vcs_dirty_pace_wait_nanos: { aggregator: "counter" },
  vcs_dirty_pace_refusals: { aggregator: "counter" },
  vcs_dirty_released_bytes: { aggregator: "counter" },
  vcs_dirty_pace_setpoint_bytes: { aggregator: "gauge_additive" },
  vcs_dirty_release_bytes_per_sec: { aggregator: "gauge_additive" },

  // The fold's last-folded journal watermark. LSNs belong to each child's OWN
  // journal, so they are NOT comparable across children and summing them
  // would be meaningless arithmetic on unrelated sequences. Aggregated as the
  // MINIMUM — the worst case, "no resident child has folded past this" — the
  // same treatment the other worst-case gauges get. Per-child watermarks are
  // read from the child's own /metrics, never from this fleet series.
  vcs_dirty_fold_watermark: { aggregator: "gauge_min" },

  // Latency summaries (Go histograms rendered as summaries): _count/_sum
  // aggregate; precomputed quantiles are dropped.
  vcs_fsproto_op_latency: { aggregator: "summary" },
  authority_op_seconds: { aggregator: "summary" },
  writeback_flush_seconds: { aggregator: "summary" },
  vcs_checkpoint_duration: { aggregator: "summary" },
  vcs_lifecycle_eviction_drain_duration: { aggregator: "summary" },
  vcs_bucket_fetch_latency: { aggregator: "summary" },
};

// Hard structural bounds on one child exposition.
export const childScrapeBounds = {
  maxResponseBytes: 256 * 1024,
  maxLines: 2_000,
  maxSeries: 500,
  maxLabelsPerLine: 1, // this exporter emits at most {quantile="..."}
  maxBucketsPerHistogram: 64,
} as const;

// The ONLY label key/value pairs a child may emit, as a closed enum. The
// quantile label exists purely to be recognized and dropped.
const allowedQuantileValues = new Set(["0.5", "0.9", "0.99"]);
const allowedLabelKeys = new Set(["quantile", "le"]);

export type ChildParseFailureCode =
  | "response_too_large"
  | "too_many_lines"
  | "too_many_series"
  | "malformed_line"
  | "unknown_label"
  | "duplicate_label"
  | "duplicate_series"
  | "not_finite"
  | "bucket_mismatch"
  | "label_not_allowed";

interface ParsedSeries {
  base: string;
  suffix: "" | "_count" | "_sum" | "_bucket";
  labels: Array<{ key: string; value: string }>;
  value: number;
}

/** Lines a child sent that this manager deliberately did not aggregate. */
export interface ChildParseSkips {
  /** Lines whose metric name is not in the closed allowlist. */
  unknownMetrics: number;
  /** HELP/TYPE/comment lines — no series, nothing to aggregate. */
  ignoredLines: number;
}

export type ChildParseResult =
  | { ok: true; series: ParsedSeries[]; skips: ChildParseSkips }
  | { ok: false; code: ChildParseFailureCode };

// Strict line parser for the child exposition format. Rejection is by coarse
// code only; the raw line is never propagated.
export function parseChildExposition(text: string): ChildParseResult {
  if (Buffer.byteLength(text, "utf8") > childScrapeBounds.maxResponseBytes) {
    return { ok: false, code: "response_too_large" };
  }
  const lines = text.split("\n");
  if (lines.length > childScrapeBounds.maxLines) {
    return { ok: false, code: "too_many_lines" };
  }
  const series: ParsedSeries[] = [];
  const skips: ChildParseSkips = { unknownMetrics: 0, ignoredLines: 0 };
  const seen = new Set<string>();
  for (const [index, line] of lines.entries()) {
    if (line === "" && index === lines.length - 1) {
      continue; // single trailing newline
    }
    if (line === "") {
      return { ok: false, code: "malformed_line" };
    }
    if (line.startsWith("#")) {
      // HELP/TYPE/comment lines carry no series and no cardinality: skipping
      // one cannot pollute the aggregate, so an exporter that starts emitting
      // them (or a hosted child that always did) must not cost the fleet
      // every OTHER metric on the body. Counted, never rendered.
      skips.ignoredLines += 1;
      continue;
    }
    const parsed = parseLine(line);
    if (!parsed.ok) {
      return parsed;
    }
    if (parsed.skip) {
      // Name not in the closed allowlist. The line is dropped WHOLE and
      // unexamined — its labels are never inspected and nothing about it
      // reaches the output — so the namespace stays exactly as closed as
      // before, while every allowlisted metric on the same body survives.
      skips.unknownMetrics += 1;
      continue;
    }
    const key = seriesKey(parsed.series);
    if (seen.has(key)) {
      return { ok: false, code: "duplicate_series" };
    }
    seen.add(key);
    series.push(parsed.series);
    if (series.length > childScrapeBounds.maxSeries) {
      return { ok: false, code: "too_many_series" };
    }
  }
  return { ok: true, series, skips };
}

const namePattern = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
// The metric name is the leading identifier of a line, before any "{" or " ".
const leadingNamePattern = /^[a-zA-Z_:][a-zA-Z0-9_:]*/;

/**
 * Own-property lookup ONLY. A child emitting `constructor 1` or `toString 1`
 * must be an unrecognized name like any other, not an inherited Object.
 * prototype member that reads as truthy and slips past the closed registry.
 */
function allowlistSpec(name: string): ChildMetricSpec | undefined {
  return Object.hasOwn(childMetricAllowlist, name) ? childMetricAllowlist[name] : undefined;
}

type ParseLineOutcome =
  | { ok: true; skip: true }
  | { ok: true; skip: false; series: ParsedSeries }
  | { ok: false; code: ChildParseFailureCode };

function parseLine(line: string): ParseLineOutcome {
  // ALLOWLIST FIRST, on the leading identifier alone. A name this manager
  // does not know is skipped before ANY other structural rule is applied to
  // it, because every one of those rules (label enum, label count, value
  // finiteness, suffix discipline) is a statement about metrics we DO know.
  // Applying them to an unrecognized metric is what turned "the child is
  // newer than the manager" into "the manager reports nothing at all".
  const leadingName = leadingNamePattern.exec(line)?.[0];
  if (leadingName === undefined) {
    // Not even an identifier: genuine corruption, still fail-closed.
    return { ok: false, code: "malformed_line" };
  }
  if (!allowlistSpec(splitSuffix(leadingName).base)) {
    return { ok: true, skip: true };
  }

  // Format: name[{labels}] value   (exactly one space between name and value)
  const spaceIndex = line.lastIndexOf(" ");
  if (spaceIndex <= 0 || spaceIndex === line.length - 1) {
    return { ok: false, code: "malformed_line" };
  }
  const nameAndLabels = line.slice(0, spaceIndex);
  const rawValue = line.slice(spaceIndex + 1);
  const value = Number(rawValue);
  if (rawValue.trim() !== rawValue || rawValue === "" || !Number.isFinite(value)) {
    return { ok: false, code: "not_finite" };
  }

  let name = nameAndLabels;
  const labels: Array<{ key: string; value: string }> = [];
  const braceIndex = nameAndLabels.indexOf("{");
  if (braceIndex >= 0) {
    if (!nameAndLabels.endsWith("}")) {
      return { ok: false, code: "malformed_line" };
    }
    name = nameAndLabels.slice(0, braceIndex);
    const labelBody = nameAndLabels.slice(braceIndex + 1, -1);
    const parts = labelBody.length === 0 ? [] : labelBody.split(",");
    if (parts.length > childScrapeBounds.maxLabelsPerLine) {
      return { ok: false, code: "label_not_allowed" };
    }
    const seenKeys = new Set<string>();
    for (const part of parts) {
      const match = /^([a-zA-Z_][a-zA-Z0-9_]*)="([^"\\]*)"$/.exec(part);
      if (!match || match[1] === undefined || match[2] === undefined) {
        return { ok: false, code: "malformed_line" };
      }
      if (!allowedLabelKeys.has(match[1])) {
        // Child-provided labels never pass through unless from the closed
        // enum — no volume/branch/session/child/path/operation/digest labels.
        return { ok: false, code: "unknown_label" };
      }
      if (seenKeys.has(match[1])) {
        return { ok: false, code: "duplicate_label" };
      }
      seenKeys.add(match[1]);
      labels.push({ key: match[1], value: match[2] });
    }
  }
  if (!namePattern.test(name)) {
    return { ok: false, code: "malformed_line" };
  }

  const { base, suffix } = splitSuffix(name);
  const spec = allowlistSpec(base);
  if (!spec) {
    // Reachable only when the label-stripped name differs from the leading
    // identifier gate above (it cannot today). Skip, never discard the body.
    return { ok: true, skip: true };
  }
  // Label/type discipline per aggregator.
  if (spec.aggregator === "summary") {
    if (suffix === "" && labels.length === 1 && labels[0]!.key === "quantile") {
      if (!allowedQuantileValues.has(labels[0]!.value)) {
        return { ok: false, code: "unknown_label" };
      }
    } else if ((suffix === "_count" || suffix === "_sum") && labels.length === 0) {
      // ok
    } else {
      return { ok: false, code: "label_not_allowed" };
    }
  } else if (spec.aggregator === "histogram") {
    if (suffix === "_bucket") {
      if (labels.length !== 1 || labels[0]!.key !== "le") {
        return { ok: false, code: "label_not_allowed" };
      }
      if (!spec.bucketBoundaries?.includes(labels[0]!.value)) {
        return { ok: false, code: "bucket_mismatch" };
      }
    } else if ((suffix === "_count" || suffix === "_sum") && labels.length === 0) {
      // ok
    } else {
      return { ok: false, code: "label_not_allowed" };
    }
  } else {
    if (suffix !== "" || labels.length !== 0) {
      return { ok: false, code: "label_not_allowed" };
    }
  }
  return { ok: true, skip: false, series: { base, suffix, labels, value } };
}

function splitSuffix(name: string): { base: string; suffix: "" | "_count" | "_sum" | "_bucket" } {
  for (const suffix of ["_bucket", "_count", "_sum"] as const) {
    if (name.endsWith(suffix)) {
      const base = name.slice(0, -suffix.length);
      // Only treat the suffix as structural when the base is an allowlisted
      // summary/histogram — a counter literally named *_total_count would
      // otherwise be misparsed.
      const spec = allowlistSpec(base);
      if (spec && (spec.aggregator === "summary" || spec.aggregator === "histogram")) {
        return { base, suffix };
      }
    }
  }
  return { base: name, suffix: "" };
}

function seriesKey(series: ParsedSeries): string {
  const labels = series.labels.map((label) => `${label.key}=${label.value}`).join(",");
  return `${series.base}${series.suffix}{${labels}}`;
}

// ---------------------------------------------------------------------------
// Aggregation across parsed children.
// ---------------------------------------------------------------------------

export interface AggregatedChildMetrics {
  /** Rendered exposition lines (sorted, deterministic). */
  lines: string[];
  childrenAggregated: number;
  childrenMalformed: number;
  /**
   * Lines skipped because the metric name is not allowlisted. Non-zero means
   * a child emits something this manager does not know how to aggregate —
   * an allowlist gap to close, NOT a reason the rest was lost.
   */
  unknownMetricLines: number;
  /** HELP/TYPE/comment lines skipped (informational; nothing to aggregate). */
  ignoredLines: number;
}

export function aggregateChildMetrics(results: ChildParseResult[]): AggregatedChildMetrics {
  const sums = new Map<string, number>();
  const mins = new Map<string, number>();
  const maxs = new Map<string, number>();
  let aggregated = 0;
  let malformed = 0;
  let unknownMetricLines = 0;
  let ignoredLines = 0;

  for (const result of results) {
    if (!result.ok) {
      malformed += 1;
      continue;
    }
    aggregated += 1;
    unknownMetricLines += result.skips.unknownMetrics;
    ignoredLines += result.skips.ignoredLines;
    for (const series of result.series) {
      const spec = allowlistSpec(series.base)!;
      switch (spec.aggregator) {
        case "counter":
        case "gauge_additive":
          addTo(sums, series.base, series.value);
          break;
        case "gauge_min":
          mergeMin(mins, series.base, series.value);
          break;
        case "gauge_max":
          mergeMax(maxs, series.base, series.value);
          break;
        case "summary":
          if (series.suffix === "_count" || series.suffix === "_sum") {
            addTo(sums, `${series.base}${series.suffix}`, series.value);
          }
          // Quantile lines are DROPPED: summaries are not mergeable and no
          // fake percentile is derived.
          break;
        case "histogram":
          if (series.suffix === "_bucket") {
            addTo(sums, `${series.base}_bucket{le="${series.labels[0]!.value}"}`, series.value);
          } else {
            addTo(sums, `${series.base}${series.suffix}`, series.value);
          }
          break;
      }
    }
  }

  const lines: string[] = [];
  for (const [name, value] of sums) {
    lines.push(`pfm_child_${name} ${renderValue(value)}`);
  }
  for (const [name, value] of mins) {
    lines.push(`pfm_child_${name} ${renderValue(value)}`);
  }
  for (const [name, value] of maxs) {
    lines.push(`pfm_child_${name} ${renderValue(value)}`);
  }
  lines.sort();
  return {
    lines,
    childrenAggregated: aggregated,
    childrenMalformed: malformed,
    unknownMetricLines,
    ignoredLines,
  };
}

function addTo(map: Map<string, number>, key: string, value: number): void {
  map.set(key, (map.get(key) ?? 0) + value);
}

function mergeMin(map: Map<string, number>, key: string, value: number): void {
  map.set(key, map.has(key) ? Math.min(map.get(key)!, value) : value);
}

function mergeMax(map: Map<string, number>, key: string, value: number): void {
  map.set(key, map.has(key) ? Math.max(map.get(key)!, value) : value);
}

function renderValue(value: number): string {
  return String(value);
}

// ---------------------------------------------------------------------------
// Bounded loopback scraper with single-flight cache.
// ---------------------------------------------------------------------------

export interface ChildScrapeTarget {
  /** "127.0.0.1:PORT" (or "[::1]:PORT") EXACTLY — anything else is refused. */
  address: string;
}

export interface ChildMetricsCollectorOptions {
  targets: () => ChildScrapeTarget[];
  fetchImpl?: typeof fetch;
  metrics: ManagerMetrics;
  perChildTimeoutMs?: number;
  overallDeadlineMs?: number;
  cacheTtlMs?: number;
  maxTargets?: number;
  now?: () => number;
}

const loopbackHostPattern = /^(127\.0\.0\.1|\[::1\]):(\d{1,5})$/;

/**
 * SSRF-safe URL construction: the target must be a loopback host:port
 * LITERAL; the URL is assembled from the validated parts with a fixed path.
 * No scheme, path, userinfo, or query from the caller ever enters it.
 */
export function loopbackMetricsUrl(address: string): string | null {
  const match = loopbackHostPattern.exec(address);
  if (!match || match[2] === undefined) {
    return null;
  }
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }
  return `http://${match[1]}:${port}/metrics`;
}

export class ChildMetricsCollector {
  private readonly options: Required<
    Pick<
      ChildMetricsCollectorOptions,
      "perChildTimeoutMs" | "overallDeadlineMs" | "cacheTtlMs" | "maxTargets"
    >
  > &
    ChildMetricsCollectorOptions;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private cache: { at: number; body: AggregatedChildMetrics } | undefined;
  private inflight: Promise<AggregatedChildMetrics> | undefined;

  constructor(options: ChildMetricsCollectorOptions) {
    this.options = {
      perChildTimeoutMs: 2_000,
      overallDeadlineMs: 5_000,
      cacheTtlMs: 1_000,
      maxTargets: 64,
      ...options,
    };
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.now = options.now ?? Date.now;
  }

  /** Single-flight, TTL-cached aggregation of every child's /metrics. */
  collect(): Promise<AggregatedChildMetrics> {
    if (this.cache && this.now() - this.cache.at < this.options.cacheTtlMs) {
      return Promise.resolve(this.cache.body);
    }
    if (this.inflight) {
      return this.inflight;
    }
    this.inflight = this.collectFresh().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }

  private async collectFresh(): Promise<AggregatedChildMetrics> {
    const metrics = this.options.metrics;
    const targets = this.options.targets().slice(0, this.options.maxTargets);
    const overall = new AbortController();
    const overallTimer = setTimeout(() => overall.abort(), this.options.overallDeadlineMs);
    overallTimer.unref?.();
    try {
      const results = await Promise.all(
        targets.map((target) => this.scrapeOne(target, overall.signal))
      );
      const body = aggregateChildMetrics(results);
      metrics.setGauge("pfm_child_scrape_targets", targets.length);
      metrics.setGauge("pfm_child_scrape_aggregated", body.childrenAggregated);
      if (body.childrenMalformed > 0) {
        metrics.counter("pfm_child_scrape_malformed_total").add(body.childrenMalformed);
      }
      // A child emitting a metric this manager does not allowlist no longer
      // costs that child its whole exposition — but it must never be silent
      // either, or the allowlist drifts behind the children unnoticed (which
      // is exactly how aad03e9's four vcs_dirty_fold_* metrics blinded the
      // fleet). This counter climbing is the signal to extend the allowlist.
      // Added unconditionally (0 is a legal increment) so both series are
      // ALWAYS present in the body: an instrument that only exists once it
      // has fired cannot be alerted on, and "absent" would read the same as
      // "healthy" — the precise failure mode this fix exists to end.
      metrics.counter("pfm_child_scrape_unknown_metrics_total").add(body.unknownMetricLines);
      metrics.counter("pfm_child_scrape_ignored_lines_total").add(body.ignoredLines);
      this.cache = { at: this.now(), body };
      return body;
    } finally {
      clearTimeout(overallTimer);
    }
  }

  private async scrapeOne(
    target: ChildScrapeTarget,
    overallSignal: AbortSignal
  ): Promise<ChildParseResult> {
    const metrics = this.options.metrics;
    const url = loopbackMetricsUrl(target.address);
    if (!url) {
      // Non-loopback target: refused before any request. Coarse code only —
      // the address is never logged or labeled.
      metrics.counter("pfm_child_scrape_refused_total").add(1);
      return { ok: false, code: "malformed_line" };
    }
    const controller = new AbortController();
    const onOverallAbort = () => controller.abort();
    overallSignal.addEventListener("abort", onOverallAbort, { once: true });
    const timer = setTimeout(() => controller.abort(), this.options.perChildTimeoutMs);
    try {
      const response = await this.fetchImpl(url, { signal: controller.signal });
      if (!response.ok || !response.body) {
        metrics.counter("pfm_child_scrape_errors_total").add(1);
        return { ok: false, code: "malformed_line" };
      }
      // BOUNDED STREAMING READ: bytes accumulate only up to the cap; an
      // oversized body aborts before whole-response allocation.
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (true) {
        const next = await reader.read();
        if (next.done) {
          break;
        }
        total += next.value.byteLength;
        if (total > childScrapeBounds.maxResponseBytes) {
          await reader.cancel().catch(() => undefined);
          metrics.counter("pfm_child_scrape_errors_total").add(1);
          return { ok: false, code: "response_too_large" };
        }
        chunks.push(next.value);
      }
      const text = Buffer.concat(chunks, total).toString("utf8");
      const parsed = parseChildExposition(text);
      if (!parsed.ok) {
        metrics.counter("pfm_child_scrape_errors_total").add(1);
      }
      return parsed;
    } catch {
      // Timeouts / connection failures: coarse counter, no target, no error
      // body.
      metrics.counter("pfm_child_scrape_errors_total").add(1);
      return { ok: false, code: "malformed_line" };
    } finally {
      clearTimeout(timer);
      overallSignal.removeEventListener("abort", onOverallAbort);
    }
  }
}
