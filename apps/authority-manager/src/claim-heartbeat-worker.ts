// ---------------------------------------------------------------------------
// The singleton claim's LIVENESS THREAD.
//
// This module is the entry point of a dedicated worker_thread whose ONLY job
// is to renew the manager's singleton claim against the control database. It
// exists because liveness must be structurally isolated from load:
//
//   - Its EVENT LOOP carries nothing else. No listener, no tunnel, no HTTP
//     server, no child process, no metrics scrape. A full-speed data-plane
//     flood on the main thread cannot delay this timer, because the flood's
//     callbacks are not queued on this loop at all.
//   - Its DATABASE CONNECTION is reserved. It opens its own single pg Client
//     and never shares it with anything, so a renewal can never queue behind
//     bulk control-plane traffic in a shared pool. This mirrors the reserved
//     liveness connection the Go authority child already uses for its fencing
//     probe, one layer up.
//
// The file is deliberately SELF-CONTAINED: it imports only node builtins and
// `pg`. Nothing else may be added — every import here is another thing that
// can block the fencing authority's heartbeat.
//
// It renders NO judgement. It runs one statement on a fixed cadence and posts
// the raw facts (or the raw failure) to the main thread, which owns the
// deadline arithmetic and the fencing decision. A worker that cannot renew
// simply stops posting successes; the main thread's deadline watchdog then
// fences on schedule. Silence is therefore fail-CLOSED by construction.
// ---------------------------------------------------------------------------

import { isMainThread, parentPort, threadId, workerData } from "node:worker_threads";
import { Client } from "pg";

export interface ClaimHeartbeatWorkerData {
  connectionString: string;
  /** `SELECT pfm.manager_renew($1,$2,$3,$4) AS r` and its bound values. */
  sql: string;
  values: unknown[];
  /** Fixed renewal cadence; also the hard per-attempt bound. */
  intervalMs: number;
  connectTimeoutMs: number;
  statementTimeoutMs: number;
  /**
   * One BigInt64 cell the worker publishes the current claim deadline into
   * (local monotonic milliseconds, floored). The main thread reads it with a
   * plain atomic load — no message, no queue, no scheduling. A renewal is
   * therefore VISIBLE to the fencing watchdog the instant the database
   * confirms it, even if the main event loop is busy: otherwise a renewal
   * message could still be sitting behind a flood's callbacks while the
   * watchdog decides to fence.
   */
  deadlineCell: SharedArrayBuffer;
}

/** Posted once, before any database work, so the main thread can prove isolation. */
export interface ClaimHeartbeatHelloMessage {
  type: "hello";
  threadId: number;
  isMainThread: boolean;
  clockMs: number;
}

export interface ClaimHeartbeatRenewedMessage {
  type: "renewed";
  /** performance.now() captured BEFORE the statement was issued. */
  anchorLocalMs: number;
  dbTimeMs: number;
  claimExpiresAtDbMs: number;
}

export interface ClaimHeartbeatFailedMessage {
  type: "failed";
  anchorLocalMs: number;
  /** The PostgreSQL SQLSTATE when there was one (PF001 = epoch superseded). */
  code: string | null;
  message: string;
}

export type ClaimHeartbeatMessage =
  | ClaimHeartbeatHelloMessage
  | ClaimHeartbeatRenewedMessage
  | ClaimHeartbeatFailedMessage;

// requireIntMs reads one integer millisecond field out of the pfm response
// row. It mirrors the control store's own requireIntNumber EXACTLY: pfm
// renders its 64-bit millisecond timestamps as canonical decimal strings, and
// accepting any other shape here would let a malformed response move a
// fencing deadline. The main thread re-checks every value again before it
// applies one.
export function requireIntMs(row: Record<string, unknown>, field: string): number {
  const value = row[field];
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(
      `manager renew response field ${field} is not a canonical decimal string`
    );
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(
      `manager renew response field ${field} exceeds the safe timestamp boundary`
    );
  }
  return parsed;
}

/**
 * Projects ONE pfm renewal response onto the local monotonic claim deadline.
 * Pure and exported so the projection is proven without a live database: the
 * anchor is the instant BEFORE the statement was issued, so the result can
 * never reach past the true database expiry however slow the response was.
 */
export function projectRenewal(
  anchorLocalMs: number,
  row: unknown
): { dbTimeMs: number; claimExpiresAtDbMs: number; deadlineLocalMs: number } {
  if (typeof row !== "object" || row === null || Array.isArray(row)) {
    throw new Error("manager renew returned an unexpected row shape");
  }
  const record = row as Record<string, unknown>;
  const dbTimeMs = requireIntMs(record, "dbTimeMs");
  const claimExpiresAtDbMs = requireIntMs(record, "expiresAtDbMs");
  return {
    dbTimeMs,
    claimExpiresAtDbMs,
    deadlineLocalMs: anchorLocalMs + (claimExpiresAtDbMs - dbTimeMs),
  };
}

export function runClaimHeartbeatWorker(
  data: ClaimHeartbeatWorkerData,
  post: (message: ClaimHeartbeatMessage) => void
): { stop(): void } {
  let client: Client | null = null;
  // The generation of the attempt currently allowed to hold the connection.
  // An abandoned attempt's late completion can never disturb its successor.
  let attemptSeq = 0;
  let inFlightSeq: number | null = null;
  let stopped = false;
  const deadlineView = new BigInt64Array(data.deadlineCell);

  // publishDeadline projects ONE confirmed renewal onto the local monotonic
  // clock and stores it atomically. The anchor was taken BEFORE the statement
  // was issued, so anchor + granted-remaining can never reach past the true
  // database expiry however slow the response was. The value only ever moves
  // FORWARD: a stale or replayed response can never shorten or rewind it.
  const publishDeadline = (deadlineLocalMs: number): void => {
    const deadline = BigInt(Math.floor(deadlineLocalMs));
    if (deadline > Atomics.load(deadlineView, 0)) {
      Atomics.store(deadlineView, 0, deadline);
    }
  };

  const dropClient = () => {
    const dying = client;
    client = null;
    // end() is best effort: a wedged socket must never hold up the next
    // attempt, so the reference is dropped first and the close is fired and
    // forgotten.
    void dying?.end().catch(() => undefined);
  };

  const attempt = async (): Promise<void> => {
    if (stopped) {
      return;
    }
    if (inFlightSeq !== null) {
      // The previous attempt is still running at its own cadence boundary,
      // which means it already exceeded the per-attempt bound. Drop its
      // connection so it cannot outlive the interval and start fresh: one
      // attempt per interval, always. Its late rejection still reports
      // honestly, but it no longer owns anything.
      dropClient();
    }
    attemptSeq += 1;
    const mySeq = attemptSeq;
    inFlightSeq = mySeq;
    const anchorLocalMs = performance.now();
    try {
      if (!client) {
        const fresh = new Client({
          connectionString: data.connectionString,
          connectionTimeoutMillis: data.connectTimeoutMs,
          statement_timeout: data.statementTimeoutMs,
          query_timeout: data.intervalMs,
        });
        // A backend that dies while idle must not raise an unhandled error
        // on this thread; the next attempt reconnects.
        fresh.on("error", () => undefined);
        await fresh.connect();
        client = fresh;
      }
      const result = await client.query(data.sql, data.values);
      if (result.rows.length !== 1) {
        throw new Error("manager renew returned an unexpected row count");
      }
      const projected = projectRenewal(anchorLocalMs, (result.rows[0] as { r?: unknown }).r);
      // Shared memory FIRST: the deadline must be visible to the fencing
      // watchdog before anything depends on the main loop draining a queue.
      publishDeadline(projected.deadlineLocalMs);
      post({
        type: "renewed",
        anchorLocalMs,
        dbTimeMs: projected.dbTimeMs,
        claimExpiresAtDbMs: projected.claimExpiresAtDbMs,
      });
    } catch (error) {
      const failure = error as { code?: unknown; message?: unknown };
      // Only the CURRENT attempt owns the connection; an abandoned one must
      // not close its successor's.
      if (inFlightSeq === mySeq) {
        dropClient();
      }
      post({
        type: "failed",
        anchorLocalMs,
        code: typeof failure.code === "string" ? failure.code : null,
        message:
          typeof failure.message === "string" ? failure.message : "manager renew failed",
      });
    } finally {
      if (inFlightSeq === mySeq) {
        inFlightSeq = null;
      }
    }
  };

  const timer = setInterval(() => void attempt(), data.intervalMs);
  // The first attempt runs immediately: a manager that boots into a broken
  // control database must learn it now, not one interval from now.
  void attempt();
  return {
    stop() {
      stopped = true;
      clearInterval(timer);
      dropClient();
    },
  };
}

// Worker entry. Guarded so the module can also be imported by tests on the
// main thread without starting a heartbeat.
if (!isMainThread && parentPort) {
  const port = parentPort;
  const post = (message: ClaimHeartbeatMessage) => port.postMessage(message);
  // The hello frame is posted BEFORE any database work so the main thread can
  // prove — at composition time, not by inference — that the heartbeat runs
  // off the main event loop and that both threads share one monotonic clock.
  post({ type: "hello", threadId, isMainThread, clockMs: performance.now() });
  const handle = runClaimHeartbeatWorker(workerData as ClaimHeartbeatWorkerData, post);
  port.on("message", (message: { type?: unknown }) => {
    if (message?.type === "stop") {
      handle.stop();
      port.close();
    }
  });
}
