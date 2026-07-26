import { describe, expect, test } from "vitest";
import { BoundedGrepScanner, grepScanLimits, IsolatedRegexMatcher } from "./grep-engine.js";

describe("isolated grep engine", () => {
  test("preserves JavaScript regex behavior without running regex bytecode on the caller thread", async () => {
    const abort = new AbortController();
    const deadlineAt = Date.now() + 2_000;
    const matcher = await IsolatedRegexMatcher.create("(?<=prefix-)value-(\\d+)\\1", deadlineAt, abort.signal);
    try {
      const scanner = new BoundedGrepScanner(matcher, {
        maxResults: 10,
        deadlineAt,
        signal: abort.signal,
      });
      const completed = await scanner.scanFile(
        "a.txt",
        Buffer.byteLength("prefix-value-1212\nnope\n"),
        bytes("prefix-value-1212\nnope\n")
      );
      expect(completed).toBe(true);
      expect(scanner.matches).toEqual([
        { file: "a.txt", line: 1, text: "prefix-value-1212" },
      ]);
    } finally {
      await matcher.close();
    }
  });

  test("terminates catastrophic backtracking at the absolute deadline while timers remain responsive", async () => {
    const abort = new AbortController();
    const deadlineAt = Date.now() + 150;
    const matcher = await IsolatedRegexMatcher.create("^(a|aa)+$", deadlineAt, abort.signal);
    try {
      const scanner = new BoundedGrepScanner(matcher, {
        maxResults: 10,
        deadlineAt,
        signal: abort.signal,
      });
      let timerFired = false;
      setTimeout(() => {
        timerFired = true;
      }, 20);
      const completed = await scanner.scanFile(
        "attack.txt",
        49,
        bytes(`${"a".repeat(48)}!`)
      );
      expect(completed).toBe(false);
      expect(scanner.stoppedReason).toBe("deadline");
      expect(timerFired).toBe(true);
    } finally {
      await matcher.close();
    }
  });

  test("rejects invalid syntax and enforces file and line byte ceilings", async () => {
    const abort = new AbortController();
    await expect(
      IsolatedRegexMatcher.create("(", Date.now() + 1_000, abort.signal)
    ).rejects.toMatchObject({ code: "VOLUME_PATTERN_REJECTED", status: 400 });

    const deadlineAt = Date.now() + 2_000;
    const matcher = await IsolatedRegexMatcher.create("x", deadlineAt, abort.signal);
    try {
      const fileScanner = new BoundedGrepScanner(matcher, {
        maxResults: 10,
        deadlineAt,
        signal: abort.signal,
      });
      await expect(
        fileScanner.scanFile(
          "huge.bin",
          grepScanLimits.maxFileBytes + 1,
          bytes("")
        )
      ).rejects.toMatchObject({ code: "VOLUME_GREP_LIMIT_EXCEEDED", status: 413 });

      const line = "a".repeat(grepScanLimits.maxLineBytes + 1);
      const lineScanner = new BoundedGrepScanner(matcher, {
        maxResults: 10,
        deadlineAt,
        signal: abort.signal,
      });
      await expect(
        lineScanner.scanFile("long.txt", Buffer.byteLength(line), bytes(line))
      ).rejects.toMatchObject({ code: "VOLUME_GREP_LIMIT_EXCEEDED", status: 413 });
    } finally {
      await matcher.close();
    }
  });

  test("aborting a stuck match terminates the worker promptly", async () => {
    const abort = new AbortController();
    const deadlineAt = Date.now() + 10_000;
    const matcher = await IsolatedRegexMatcher.create("^(a|aa)+$", deadlineAt, abort.signal);
    const scanner = new BoundedGrepScanner(matcher, {
      maxResults: 10,
      deadlineAt,
      signal: abort.signal,
    });
    const pending = scanner.scanFile("attack.txt", 49, bytes(`${"a".repeat(48)}!`));
    setTimeout(() => abort.abort(), 25);
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    await matcher.close();
  });
});

async function* bytes(value: string): AsyncGenerator<Buffer> {
  yield Buffer.from(value);
}
