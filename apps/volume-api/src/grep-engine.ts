import { Worker } from "node:worker_threads";
import { StringDecoder } from "node:string_decoder";
import { VolumeApiError } from "./errors.js";

const KiB = 1024;
const MiB = 1024 * KiB;

/**
 * Server-owned grep limits. They are deliberately independent of manifest or
 * PFT2 representation so both read paths have identical resource semantics.
 */
export const grepScanLimits = {
  maxFiles: 10_000,
  maxFileBytes: 16 * MiB,
  maxScannedBytes: 64 * MiB,
  maxLineBytes: 256 * KiB,
  maxResultBytes: 8 * MiB,
  batchLines: 128,
  batchBytes: 256 * KiB,
} as const;

export type GrepStoppedReason = "completed" | "max_results" | "deadline";
export interface GrepMatch {
  file: string;
  line: number;
  text: string;
}

// The regex engine lives in a separate V8 isolate. A pattern that enters
// catastrophic backtracking can consume only this worker: the main event loop
// retains the timer and AbortSignal needed to terminate it.
const regexWorkerSource = String.raw`
  const { parentPort, workerData } = require("node:worker_threads");
  let regex;
  try {
    regex = new RegExp(workerData.pattern);
  } catch {
    parentPort.postMessage({ type: "ready", valid: false });
  }
  if (regex) {
    parentPort.postMessage({ type: "ready", valid: true });
    parentPort.on("message", (message) => {
      if (!message || message.type !== "match" || !Array.isArray(message.lines)) {
        return;
      }
      try {
        const matches = message.lines.map((line) => {
          regex.lastIndex = 0;
          return regex.test(line);
        });
        parentPort.postMessage({ type: "result", id: message.id, matches });
      } catch {
        parentPort.postMessage({ type: "failure", id: message.id });
      }
    });
  }
`;

class GrepDeadlineExceededError extends Error {
  constructor() {
    super("The grep deadline elapsed.");
    this.name = "GrepDeadlineExceededError";
  }
}

interface PendingMatch {
  id: number;
  resolve: (matches: boolean[]) => void;
  reject: (error: unknown) => void;
  timer: NodeJS.Timeout;
  signal: AbortSignal;
  onAbort: () => void;
}

/**
 * One worker per grep request. Calls are sequential, so at most one cloned
 * line batch and one pending promise exist at a time.
 */
export class IsolatedRegexMatcher {
  private readonly worker: Worker;
  private ready: Promise<void>;
  private readyResolve: (() => void) | undefined;
  private readyReject: ((error: unknown) => void) | undefined;
  private pending: PendingMatch | undefined;
  private nextId = 1;
  private closed = false;

  private constructor(pattern: string) {
    this.ready = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    this.worker = new Worker(regexWorkerSource, {
      eval: true,
      workerData: { pattern },
      resourceLimits: {
        maxOldGenerationSizeMb: 16,
        maxYoungGenerationSizeMb: 4,
        stackSizeMb: 1,
      },
    });
    this.worker.on("message", (message: unknown) => this.onMessage(message));
    this.worker.once("error", () => {
      this.fail(new VolumeApiError("VOLUME_PATTERN_REJECTED", "The search pattern failed.", 400));
    });
    this.worker.once("exit", (code) => {
      if (!this.closed && code !== 0) {
        this.fail(new GrepDeadlineExceededError());
      }
    });
  }

  static async create(
    pattern: string,
    deadlineAt: number,
    signal: AbortSignal
  ): Promise<IsolatedRegexMatcher> {
    const matcher = new IsolatedRegexMatcher(pattern);
    try {
      await matcher.awaitWithDeadline(matcher.ready, deadlineAt, signal);
      return matcher;
    } catch (error) {
      await matcher.close();
      throw error;
    }
  }

  async match(lines: readonly string[], deadlineAt: number, signal: AbortSignal): Promise<boolean[]> {
    if (this.closed) {
      throw new GrepDeadlineExceededError();
    }
    await this.awaitWithDeadline(this.ready, deadlineAt, signal);
    if (lines.length === 0) {
      return [];
    }
    if (this.pending) {
      throw new Error("The isolated grep matcher accepts one batch at a time.");
    }
    const id = this.nextId;
    this.nextId += 1;
    const remainingMs = deadlineAt - Date.now();
    if (remainingMs <= 0) {
      await this.close();
      throw new GrepDeadlineExceededError();
    }
    return new Promise<boolean[]>((resolve, reject) => {
      const onAbort = () => {
        this.rejectPending(new DOMException("The grep scan was aborted.", "AbortError"));
        void this.close();
      };
      const timer = setTimeout(() => {
        this.rejectPending(new GrepDeadlineExceededError());
        void this.close();
      }, remainingMs);
      this.pending = { id, resolve, reject, timer, signal, onAbort };
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        onAbort();
        return;
      }
      this.worker.postMessage({ type: "match", id, lines });
    });
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.rejectPending(new GrepDeadlineExceededError());
    this.readyReject?.(new GrepDeadlineExceededError());
    this.readyResolve = undefined;
    this.readyReject = undefined;
    await this.worker.terminate().then(() => undefined);
  }

  private onMessage(message: unknown): void {
    if (!message || typeof message !== "object") {
      return;
    }
    const value = message as {
      type?: unknown;
      valid?: unknown;
      id?: unknown;
      matches?: unknown;
    };
    if (value.type === "ready") {
      if (value.valid === true) {
        this.readyResolve?.();
      } else {
        this.readyReject?.(
          new VolumeApiError(
            "VOLUME_PATTERN_REJECTED",
            "The search pattern is not valid JavaScript regular-expression syntax.",
            400
          )
        );
      }
      this.readyResolve = undefined;
      this.readyReject = undefined;
      return;
    }
    const pending = this.pending;
    if (!pending || value.id !== pending.id) {
      return;
    }
    if (
      value.type !== "result" ||
      !Array.isArray(value.matches) ||
      value.matches.some((match) => typeof match !== "boolean")
    ) {
      this.rejectPending(
        new VolumeApiError("VOLUME_PATTERN_REJECTED", "The search pattern failed.", 400)
      );
      return;
    }
    this.pending = undefined;
    clearTimeout(pending.timer);
    pending.signal.removeEventListener("abort", pending.onAbort);
    pending.resolve(value.matches as boolean[]);
  }

  private rejectPending(error: unknown): void {
    const pending = this.pending;
    if (!pending) {
      return;
    }
    this.pending = undefined;
    clearTimeout(pending.timer);
    pending.signal.removeEventListener("abort", pending.onAbort);
    pending.reject(error);
  }

  private fail(error: unknown): void {
    this.readyReject?.(error);
    this.readyResolve = undefined;
    this.readyReject = undefined;
    this.rejectPending(error);
  }

  private async awaitWithDeadline<T>(
    promise: Promise<T>,
    deadlineAt: number,
    signal: AbortSignal
  ): Promise<T> {
    const remainingMs = deadlineAt - Date.now();
    if (remainingMs <= 0) {
      throw new GrepDeadlineExceededError();
    }
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => reject(new GrepDeadlineExceededError()), remainingMs);
      const onAbort = () => reject(new DOMException("The grep scan was aborted.", "AbortError"));
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        reject(new DOMException("The grep scan was aborted.", "AbortError"));
        return;
      }
      promise.then(
        (value) => {
          clearTimeout(timer);
          signal.removeEventListener("abort", onAbort);
          resolve(value);
        },
        (error: unknown) => {
          clearTimeout(timer);
          signal.removeEventListener("abort", onAbort);
          reject(error);
        }
      );
    });
  }
}

interface PendingLine {
  line: number;
  text: string;
  bytes: number;
}

/**
 * Representation-independent, sequential streaming scanner. It never buffers
 * more than one bounded line batch and delegates every regex test to the
 * killable worker.
 */
export class BoundedGrepScanner {
  readonly matches: GrepMatch[] = [];
  stoppedReason: GrepStoppedReason = "completed";
  private files = 0;
  private scannedBytes = 0;
  private resultBytes = 0;

  constructor(
    private readonly matcher: IsolatedRegexMatcher,
    private readonly input: {
      maxResults: number;
      deadlineAt: number;
      signal: AbortSignal;
    }
  ) {}

  checkpoint(): boolean {
    this.throwIfAborted();
    return !this.deadlineElapsed();
  }

  async scanFile(
    filePath: string,
    declaredSize: number | bigint,
    source: AsyncIterable<Uint8Array>
  ): Promise<boolean> {
    this.throwIfAborted();
    if (this.deadlineElapsed()) {
      return false;
    }
    const size = typeof declaredSize === "bigint" ? declaredSize : BigInt(declaredSize);
    if (size < 0n || size > BigInt(grepScanLimits.maxFileBytes)) {
      throw grepLimit(
        `File ${filePath} exceeds the ${grepScanLimits.maxFileBytes}-byte per-file grep limit.`
      );
    }
    this.files += 1;
    if (this.files > grepScanLimits.maxFiles) {
      throw grepLimit(`The scan exceeds the ${grepScanLimits.maxFiles}-file grep limit.`);
    }
    if (BigInt(this.scannedBytes) + size > BigInt(grepScanLimits.maxScannedBytes)) {
      throw grepLimit(
        `The scan exceeds the ${grepScanLimits.maxScannedBytes}-byte aggregate grep limit.`
      );
    }

    const decoder = new StringDecoder("utf8");
    let carry = "";
    let lineNumber = 1;
    let actualBytes = 0;
    const batch: PendingLine[] = [];
    let batchBytes = 0;

    const flush = async (): Promise<boolean> => {
      if (batch.length === 0) {
        return true;
      }
      let flags: boolean[];
      try {
        flags = await this.matcher.match(
          batch.map((line) => line.text),
          this.input.deadlineAt,
          this.input.signal
        );
      } catch (error) {
        if (error instanceof GrepDeadlineExceededError) {
          this.stoppedReason = "deadline";
          return false;
        }
        throw error;
      }
      for (let index = 0; index < batch.length; index += 1) {
        if (flags[index] !== true) {
          continue;
        }
        const line = batch[index] as PendingLine;
        // Charge the actual JSON representation, not raw text bytes: control
        // characters can expand sixfold when escaped by JSON.stringify.
        const match = { file: filePath, line: line.line, text: line.text };
        const resultBytes = Buffer.byteLength(JSON.stringify(match), "utf8") + 1;
        if (this.resultBytes + resultBytes > grepScanLimits.maxResultBytes) {
          throw grepLimit(
            `The matched output exceeds the ${grepScanLimits.maxResultBytes}-byte grep result limit.`
          );
        }
        this.resultBytes += resultBytes;
        this.matches.push(match);
        if (this.matches.length >= this.input.maxResults) {
          this.stoppedReason = "max_results";
          return false;
        }
      }
      batch.length = 0;
      batchBytes = 0;
      return true;
    };

    const queueLine = async (text: string): Promise<boolean> => {
      const lineBytes = Buffer.byteLength(text, "utf8");
      if (lineBytes > grepScanLimits.maxLineBytes) {
        throw grepLimit(
          `File ${filePath} contains a line above the ${grepScanLimits.maxLineBytes}-byte grep limit.`
        );
      }
      batch.push({ line: lineNumber, text, bytes: lineBytes });
      lineNumber += 1;
      batchBytes += lineBytes;
      if (
        batch.length >= grepScanLimits.batchLines ||
        batchBytes >= grepScanLimits.batchBytes
      ) {
        return flush();
      }
      return true;
    };

    for await (const rawChunk of source) {
      this.throwIfAborted();
      if (this.deadlineElapsed()) {
        return false;
      }
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      actualBytes += chunk.byteLength;
      if (actualBytes > Number(size) || actualBytes > grepScanLimits.maxFileBytes) {
        throw grepLimit(`File ${filePath} produced more bytes than its declared size.`);
      }
      const pieces = (carry + decoder.write(chunk)).split("\n");
      carry = pieces.pop() ?? "";
      if (Buffer.byteLength(carry, "utf8") > grepScanLimits.maxLineBytes) {
        throw grepLimit(
          `File ${filePath} contains a line above the ${grepScanLimits.maxLineBytes}-byte grep limit.`
        );
      }
      for (const piece of pieces) {
        const line = piece.endsWith("\r") ? piece.slice(0, -1) : piece;
        if (!(await queueLine(line))) {
          return false;
        }
      }
    }
    carry += decoder.end();
    if (actualBytes !== Number(size)) {
      throw grepLimit(`File ${filePath} produced ${actualBytes} bytes, expected ${size}.`);
    }
    this.scannedBytes += actualBytes;
    if (!(await queueLine(carry))) {
      return false;
    }
    return flush();
  }

  private throwIfAborted(): void {
    if (this.input.signal.aborted) {
      throw new DOMException("The grep scan was aborted.", "AbortError");
    }
  }

  private deadlineElapsed(): boolean {
    if (Date.now() <= this.input.deadlineAt) {
      return false;
    }
    this.stoppedReason = "deadline";
    return true;
  }
}

function grepLimit(message: string): VolumeApiError {
  return new VolumeApiError("VOLUME_GREP_LIMIT_EXCEEDED", message, 413);
}
