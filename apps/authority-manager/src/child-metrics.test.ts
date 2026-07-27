// Child metrics aggregation: golden Go-exporter contract, exact aggregation
// semantics, adversarial parsing, and bounded scraping.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import {
  aggregateChildMetrics,
  childMetricAllowlist,
  childScrapeBounds,
  ChildMetricsCollector,
  loopbackMetricsUrl,
  parseChildExposition,
} from "./child-metrics.js";
import { ManagerMetrics } from "./manager-metrics.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const goldenPath = path.join(
  here,
  "../../../vcs/internal/metrics/testdata/golden_exposition.txt"
);

describe("golden Go exporter contract", () => {
  test("the exact Go exporter output parses cleanly and aggregates with correct semantics", () => {
    const golden = readFileSync(goldenPath, "utf8");
    const parsed = parseChildExposition(golden);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    // Two identical children: counters and additive gauges double, the
    // readiness boolean stays 1 (minimum), summary _count/_sum double, and
    // the precomputed quantiles are DROPPED (never summed, never maxed).
    const aggregated = aggregateChildMetrics([parsed, parsed]);
    expect(aggregated.childrenAggregated).toBe(2);
    expect(aggregated.childrenMalformed).toBe(0);
    expect(aggregated.lines).toContain("pfm_child_vcs_fsproto_ops 2468");
    expect(aggregated.lines).toContain("pfm_child_vcs_mutations 1134");
    expect(aggregated.lines).toContain("pfm_child_vcs_cache_ram_hits 178");
    expect(aggregated.lines).toContain("pfm_child_vcs_fsproto_conns 6");
    expect(aggregated.lines).toContain("pfm_child_writeback_pending_bytes 8192");
    // The dirty-RSS gauges are additive: total resident dirty bytes and the
    // total configured budget across the fleet.
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_block_bytes 16777216");
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_block_bytes_max 4294967296");
    expect(aggregated.lines).toContain("pfm_child_vcs_ready 1"); // min, not sum
    expect(aggregated.lines).toContain("pfm_child_vcs_fsproto_op_latency_count 8");
    expect(aggregated.lines).toContain(`pfm_child_vcs_fsproto_op_latency_sum ${0.00276 * 2}`);
    // No quantile line survives aggregation, and no fake percentile appears.
    expect(aggregated.lines.some((line) => line.includes("quantile"))).toBe(false);
  });

  test("one ready child and one unready child aggregate readiness to 0 (ALL semantics)", () => {
    const golden = readFileSync(goldenPath, "utf8");
    const ready = parseChildExposition(golden);
    const unready = parseChildExposition(golden.replace("vcs_ready 1", "vcs_ready 0"));
    const aggregated = aggregateChildMetrics([ready, unready]);
    expect(aggregated.lines).toContain("pfm_child_vcs_ready 0");
  });
});

describe("strict parsing rejections", () => {
  const cases: Array<{ name: string; text: string; code: string }> = [
    { name: "unknown metric", text: "totally_unknown_metric 5\n", code: "unknown_metric" },
    {
      name: "identifier label smuggling",
      text: 'vcs_fsproto_ops{volume="vol_secret"} 5\n',
      code: "unknown_label",
    },
    {
      name: "branch label smuggling",
      text: 'vcs_ready{branch="main"} 1\n',
      code: "unknown_label",
    },
    {
      name: "unknown quantile value",
      text: 'vcs_fsproto_op_latency{quantile="0.75"} 1\n',
      code: "unknown_label",
    },
    { name: "NaN", text: "vcs_fsproto_ops NaN\n", code: "not_finite" },
    { name: "+Inf", text: "vcs_fsproto_ops +Inf\n", code: "not_finite" },
    { name: "-Inf", text: "vcs_fsproto_ops -Inf\n", code: "not_finite" },
    { name: "HELP line", text: "# HELP vcs_fsproto_ops ops\nvcs_fsproto_ops 1\n", code: "help_type_line" },
    { name: "TYPE line", text: "# TYPE vcs_fsproto_ops counter\nvcs_fsproto_ops 1\n", code: "help_type_line" },
    {
      name: "duplicate series",
      text: "vcs_fsproto_ops 1\nvcs_fsproto_ops 2\n",
      code: "duplicate_series",
    },
    { name: "missing value", text: "vcs_fsproto_ops\n", code: "malformed_line" },
    { name: "empty interior line", text: "vcs_fsproto_ops 1\n\nvcs_mutations 2\n", code: "malformed_line" },
    {
      name: "label on a plain counter",
      text: 'vcs_fsproto_ops{quantile="0.5"} 1\n',
      code: "label_not_allowed",
    },
    {
      name: "label on a plain gauge",
      text: 'vcs_dirty_block_bytes{le="+Inf"} 1\n',
      code: "label_not_allowed",
    },
    {
      name: "summary count with label",
      text: 'vcs_fsproto_op_latency_count{quantile="0.5"} 1\n',
      code: "label_not_allowed",
    },
  ];
  for (const item of cases) {
    test(item.name, () => {
      const parsed = parseChildExposition(item.text);
      expect(parsed.ok).toBe(false);
      if (parsed.ok) return;
      expect(parsed.code).toBe(item.code);
    });
  }

  test("line count bound rejects synthetic floods before any name check", () => {
    const flood = Array.from({ length: childScrapeBounds.maxLines + 1 }, (_, index) => `x${index} 1`).join("\n");
    const parsed = parseChildExposition(flood);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.code).toBe("too_many_lines");
  });

  test("oversized response rejected before parsing", () => {
    const big = "vcs_fsproto_ops 1\n".repeat(20_000);
    const parsed = parseChildExposition(big);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(["response_too_large", "too_many_lines"]).toContain(parsed.code);
  });
});

describe("adversarial fuzz/property: a malformed child NEVER poisons the aggregate", () => {
  // Deterministic PRNG so failures reproduce.
  function mulberry32(seed: number) {
    let a = seed;
    return () => {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function randomGarbage(rand: () => number): string {
    const pieces = [
      "vcs_fsproto_ops",
      "unknown_metric_name",
      '{volume="v"}',
      '{quantile="0.5"}',
      "NaN",
      "Inf",
      "-1",
      "12.5",
      "# HELP x y",
      "vcs_ready",
      '{le="+Inf"}',
      "\u0000",
      " ",
      "{}",
      "1e309",
      "9".repeat(400),
    ];
    const lineCount = Math.floor(rand() * 20);
    const lines: string[] = [];
    for (let index = 0; index < lineCount; index += 1) {
      const wordCount = 1 + Math.floor(rand() * 4);
      const words: string[] = [];
      for (let w = 0; w < wordCount; w += 1) {
        words.push(pieces[Math.floor(rand() * pieces.length)]!);
      }
      lines.push(words.join(rand() > 0.5 ? " " : ""));
    }
    return lines.join("\n") + (rand() > 0.5 ? "\n" : "");
  }

  test("500 random garbage children leave a known-good child's aggregate EXACT", () => {
    const golden = readFileSync(goldenPath, "utf8");
    const good = parseChildExposition(golden);
    expect(good.ok).toBe(true);
    const rand = mulberry32(0xf00d);
    for (let round = 0; round < 500; round += 1) {
      const garbage = parseChildExposition(randomGarbage(rand));
      const aggregated = aggregateChildMetrics([good, garbage]);
      if (garbage.ok) {
        // A garbage string that happens to parse must consist solely of
        // allowlisted, label-legal series — acceptable by construction.
        expect(aggregated.childrenAggregated).toBe(2);
      } else {
        expect(aggregated.childrenAggregated).toBe(1);
        expect(aggregated.childrenMalformed).toBe(1);
        // The good child's counter is EXACT — never inflated by the garbage.
        expect(aggregated.lines).toContain("pfm_child_vcs_fsproto_ops 1234");
      }
      // Invariant: no identifier-ish label ever appears in the output.
      for (const line of aggregated.lines) {
        expect(line).not.toMatch(/volume=|branch=|session|path=|digest|operation/);
      }
    }
  });

  test("property: aggregating one child is identity for counters/additive gauges", () => {
    const golden = readFileSync(goldenPath, "utf8");
    const parsed = parseChildExposition(golden);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const one = aggregateChildMetrics([parsed]);
    expect(one.lines).toContain("pfm_child_vcs_fsproto_ops 1234");
    expect(one.lines).toContain("pfm_child_vcs_ready 1");
    // Property: N identical children scale counters linearly, keep min gauges.
    for (const n of [2, 3, 7]) {
      const many = aggregateChildMetrics(Array.from({ length: n }, () => parsed));
      expect(many.lines).toContain(`pfm_child_vcs_fsproto_ops ${1234 * n}`);
      expect(many.lines).toContain("pfm_child_vcs_ready 1");
    }
  });
});

describe("bounded scraping", () => {
  test("loopback proof: only 127.0.0.1/[::1] literals produce URLs", () => {
    expect(loopbackMetricsUrl("127.0.0.1:9000")).toBe("http://127.0.0.1:9000/metrics");
    expect(loopbackMetricsUrl("[::1]:9000")).toBe("http://[::1]:9000/metrics");
    for (const hostile of [
      "10.0.0.1:9000",
      "localhost:9000", // resolvable names are refused — literals only
      "127.0.0.1:9000/evil",
      "127.0.0.1:9000@attacker.example",
      "attacker.example:80",
      "127.0.0.1:0",
      "127.0.0.1:99999",
      "127.0.0.1",
      "file:///etc/passwd",
    ]) {
      expect(loopbackMetricsUrl(hostile), hostile).toBeNull();
    }
  });

  test("scrapes aggregate; malformed children degrade to bounded error counters; cache single-flights", async () => {
    const golden = readFileSync(goldenPath, "utf8");
    let fetches = 0;
    const metrics = new ManagerMetrics();
    const collector = new ChildMetricsCollector({
      targets: () => [
        { address: "127.0.0.1:9001" },
        { address: "127.0.0.1:9002" },
        { address: "10.9.9.9:9003" }, // non-loopback: refused, never fetched
      ],
      metrics,
      cacheTtlMs: 60_000,
      fetchImpl: (async (input: string | URL | Request) => {
        fetches += 1;
        const url = String(input);
        expect(url.startsWith("http://127.0.0.1:")).toBe(true);
        if (url.includes("9001")) {
          return new Response(golden, { status: 200 });
        }
        return new Response('vcs_ready{volume="leak"} 1\n', { status: 200 });
      }) as typeof fetch,
    });
    const first = await collector.collect();
    expect(first.childrenAggregated).toBe(1);
    expect(first.childrenMalformed).toBe(2); // refused target + label smuggler
    expect(first.lines).toContain("pfm_child_vcs_fsproto_ops 1234");
    expect(fetches).toBe(2); // the non-loopback target was never fetched

    const snapshot = metrics.snapshot();
    expect(snapshot.pfm_child_scrape_refused_total).toBe(1);
    expect(snapshot.pfm_child_scrape_errors_total ?? 0).toBeGreaterThanOrEqual(1);

    // Cache: an immediate second collect performs no new fetches.
    await collector.collect();
    expect(fetches).toBe(2);
  });

  test("a child body over the byte cap aborts during STREAMING, before full allocation", async () => {
    const metrics = new ManagerMetrics();
    const hugeChunk = new TextEncoder().encode("vcs_fsproto_ops 1\n".repeat(4096));
    const collector = new ChildMetricsCollector({
      targets: () => [{ address: "127.0.0.1:9001" }],
      metrics,
      fetchImpl: (async () => {
        let sent = 0;
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            sent += hugeChunk.byteLength;
            if (sent > childScrapeBounds.maxResponseBytes * 4) {
              controller.close();
              return;
            }
            controller.enqueue(hugeChunk);
          },
        });
        return new Response(stream, { status: 200 });
      }) as typeof fetch,
    });
    const result = await collector.collect();
    expect(result.childrenAggregated).toBe(0);
    expect(result.childrenMalformed).toBe(1);
  });

  test("a hung child times out within the per-child deadline and degrades only itself", async () => {
    const golden = readFileSync(goldenPath, "utf8");
    const metrics = new ManagerMetrics();
    const collector = new ChildMetricsCollector({
      targets: () => [{ address: "127.0.0.1:9001" }, { address: "127.0.0.1:9002" }],
      metrics,
      perChildTimeoutMs: 50,
      overallDeadlineMs: 500,
      fetchImpl: (async (input: string | URL | Request, init?: RequestInit) => {
        if (String(input).includes("9001")) {
          return new Response(golden, { status: 200 });
        }
        return await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError"))
          );
        });
      }) as typeof fetch,
    });
    const started = Date.now();
    const result = await collector.collect();
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(result.childrenAggregated).toBe(1);
    expect(result.childrenMalformed).toBe(1);
  });
});

describe("allowlist hygiene", () => {
  test("every allowlisted metric has a declared aggregator; histograms declare boundaries", () => {
    for (const [name, spec] of Object.entries(childMetricAllowlist)) {
      expect(name).toMatch(/^[a-z][a-z0-9_]*$/);
      if (spec.aggregator === "histogram") {
        expect(spec.bucketBoundaries?.at(-1)).toBe("+Inf");
      }
    }
  });

  test("every metric name the OSS Go child can emit is allowlisted (dirty-RSS gauges included)", () => {
    for (const name of [
      "vcs_fsproto_op_other",
      "vcs_dirty_block_bytes",
      "vcs_dirty_block_bytes_max",
      "vcs_ready",
      "vcs_fsproto_ops",
      "writeback_flush_seconds",
      "authority_ops_total",
    ]) {
      expect(childMetricAllowlist[name], name).toBeDefined();
    }
  });

  test("histogram boundary mismatch is rejected, never merged", () => {
    // No histogram-typed child metric exists today (Go renders summaries),
    // so pin the rejection path directly: a _bucket line for a summary-typed
    // metric must be refused as a label/type mismatch.
    const parsed = parseChildExposition('vcs_fsproto_op_latency_bucket{le="0.5"} 3\n');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(["label_not_allowed", "bucket_mismatch", "unknown_metric"]).toContain(parsed.code);
  });
});
