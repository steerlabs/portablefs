// Child metrics aggregation: golden Go-exporter contract, exact aggregation
// semantics, adversarial parsing, and bounded scraping.
import { readdirSync, readFileSync } from "node:fs";
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
const fsprotoServerPath = path.join(
  here,
  "../../../vcs/internal/fsproto/server.go"
);
const vcsRoot = path.join(here, "../../../vcs");

const goModulePath = "github.com/steerlabs/portablefs/vcs";
// The managed child binary. Only the packages IT links can put a metric in a
// child's exposition — the history worker (internal/histworker, pfh_worker_*)
// is a different process the manager never scrapes.
const childMainPackage = "cmd/vcs";

/** In-repo packages the child binary transitively imports (no Go toolchain). */
function childBinaryPackages(): Set<string> {
  const seen = new Set<string>();
  const queue = [childMainPackage];
  while (queue.length > 0) {
    const pkg = queue.pop()!;
    if (seen.has(pkg)) continue;
    seen.add(pkg);
    for (const file of goFilesIn(path.join(vcsRoot, pkg))) {
      const source = readFileSync(file, "utf8");
      for (const match of source.matchAll(
        new RegExp(`"${goModulePath}/([a-zA-Z0-9_/]+)"`, "g")
      )) {
        queue.push(match[1]!);
      }
    }
  }
  return seen;
}

/** Non-test .go files directly in one package directory. */
function goFilesIn(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true })
    .filter(
      (entry) =>
        entry.isFile() && entry.name.endsWith(".go") && !entry.name.endsWith("_test.go")
    )
    .map((entry) => path.join(dir, entry.name));
}

/**
 * Every LITERAL metric name the CHILD BINARY can register, scanned out of the
 * Go tree itself. This is the cross-language contract that keeps the manager's
 * closed allowlist from silently drifting behind the children: adding a metric
 * in Go without allowlisting it here fails CI instead of blinding production.
 * Dynamically composed names (vcs_fsproto_op_ + name) are covered by the
 * per-op test above.
 */
function goMetricRegistrations(): Set<string> {
  return new Set(goMetricRegistrationKinds().keys());
}

/** name -> the registry kinds it is registered as (Counter/Gauge/Histogram). */
function goMetricRegistrationKinds(): Map<string, Set<string>> {
  const kinds = new Map<string, Set<string>>();
  const pattern = /\.(Counter|Gauge|Histogram|Summary)\("([a-z][a-z0-9_]*)"\)/g;
  for (const pkg of childBinaryPackages()) {
    for (const file of goFilesIn(path.join(vcsRoot, pkg))) {
      for (const match of readFileSync(file, "utf8").matchAll(pattern)) {
        const name = match[2]!;
        kinds.set(name, (kinds.get(name) ?? new Set()).add(match[1]!));
      }
    }
  }
  return kinds;
}

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

// ---------------------------------------------------------------------------
// The aad03e9 regression and its CLASS.
//
// aad03e9 registered four vcs_dirty_fold_* metrics at package init in
// vcs/internal/workfs/dirtyfold.go, so EVERY child exposed them. They were not
// allowlisted, and the parser answered unknown_metric for the WHOLE BODY — so
// pfm_child_* vanished from production entirely, including
// pfm_child_vcs_dirty_block_bytes, the one curve that judges the fold.
//
// The instance is fixed by allowlisting the four names. The CLASS is fixed by
// making an unrecognized line skippable-and-counted: no future child metric
// can ever again cost the fleet every OTHER child metric.
// ---------------------------------------------------------------------------
describe("an unrecognized metric never discards the exposition body", () => {
  const foldMetrics = [
    "vcs_dirty_fold_released_bytes",
    "vcs_dirty_fold_blocks",
    "vcs_dirty_fold_passes",
    "vcs_dirty_fold_watermark",
  ] as const;

  test("REGRESSION: a body carrying an unknown name still yields every KNOWN metric", () => {
    const golden = readFileSync(goldenPath, "utf8");
    // Exactly the production shape: a real child body plus names this
    // manager has never heard of.
    const withUnknown =
      golden + "some_metric_a_future_child_adds 7\nanother_unknown_thing 0\n";
    const parsed = parseChildExposition(withUnknown);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.skips.unknownMetrics).toBe(2);

    const aggregated = aggregateChildMetrics([parsed]);
    expect(aggregated.childrenAggregated).toBe(1);
    expect(aggregated.childrenMalformed).toBe(0);
    expect(aggregated.unknownMetricLines).toBe(2);
    // The headline dirty-block residency gauge SURVIVES.
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_block_bytes 8388608");
    expect(aggregated.lines).toContain("pfm_child_vcs_fsproto_ops 1234");
    expect(aggregated.lines).toContain("pfm_child_vcs_ready 1");
    // The unknown names are dropped, never minted into the pfm_child_*
    // namespace: the allowlist's cardinality/namespace guarantee is intact.
    expect(aggregated.lines.some((line) => line.includes("a_future_child_adds"))).toBe(false);
    expect(aggregated.lines.some((line) => line.includes("another_unknown_thing"))).toBe(false);
  });

  test("an unknown metric is dropped WHOLE and unexamined, labels and all", () => {
    // A future metric carrying labels this parser has no rule for must not be
    // fatal either — the labels are never inspected, so they can never leak.
    const parsed = parseChildExposition(
      'vcs_ready 1\nsome_future_metric{volume="vol_secret",branch="main"} 5\nvcs_fsproto_ops 3\n'
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.skips.unknownMetrics).toBe(1);
    const aggregated = aggregateChildMetrics([parsed]);
    expect(aggregated.lines).toContain("pfm_child_vcs_ready 1");
    expect(aggregated.lines).toContain("pfm_child_vcs_fsproto_ops 3");
    for (const line of aggregated.lines) {
      expect(line).not.toMatch(/vol_secret|branch=|some_future_metric/);
    }
  });

  test("a label smuggled onto a KNOWN metric stays fatal for the whole body", () => {
    // The allowlist's real job is preserved: a child rewriting a metric this
    // manager DOES aggregate is a broken/hostile exporter, not a newer one.
    const parsed = parseChildExposition('vcs_ready 1\nvcs_fsproto_ops{volume="v"} 9\n');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.code).toBe("unknown_label");
  });

  test("HELP/TYPE/comment lines are skipped and counted, not fatal", () => {
    const parsed = parseChildExposition(
      "# HELP vcs_fsproto_ops ops\n# TYPE vcs_fsproto_ops counter\nvcs_fsproto_ops 4\n"
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.skips.ignoredLines).toBe(2);
    expect(parsed.skips.unknownMetrics).toBe(0);
    const aggregated = aggregateChildMetrics([parsed]);
    expect(aggregated.ignoredLines).toBe(2);
    expect(aggregated.lines).toContain("pfm_child_vcs_fsproto_ops 4");
  });

  test("the four vcs_dirty_fold_* metrics the child registers aggregate through", () => {
    const body =
      "vcs_dirty_fold_released_bytes 100\n" +
      "vcs_dirty_fold_blocks 4\n" +
      "vcs_dirty_fold_passes 2\n" +
      "vcs_dirty_fold_watermark 900\n" +
      "vcs_dirty_block_bytes 4096\n";
    const a = parseChildExposition(body);
    const b = parseChildExposition(body.replace("vcs_dirty_fold_watermark 900", "vcs_dirty_fold_watermark 700"));
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.skips.unknownMetrics).toBe(0);

    const aggregated = aggregateChildMetrics([a, b]);
    expect(aggregated.childrenMalformed).toBe(0);
    // Monotonic totals sum across the fleet.
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_fold_released_bytes 200");
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_fold_blocks 8");
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_fold_passes 4");
    // Watermarks are per-journal LSNs: the MINIMUM (worst case), never a sum.
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_fold_watermark 700");
    // And the curve the fold is judged by.
    expect(aggregated.lines).toContain("pfm_child_vcs_dirty_block_bytes 8192");
  });

  test("end to end: a child on the real aad03e9 exposition still reports pfm_child_*", async () => {
    // The exact production shape before the fix: the golden body plus the four
    // fold metrics the child registers at init. Every pfm_child_* line was
    // absent; pfm_child_scrape_malformed_total climbed once per scrape.
    const golden = readFileSync(goldenPath, "utf8");
    const childBody = golden + foldMetrics.map((name) => `${name} 0`).join("\n") + "\n";
    const metrics = new ManagerMetrics();
    const collector = new ChildMetricsCollector({
      targets: () => [{ address: "127.0.0.1:9101" }, { address: "127.0.0.1:9102" }],
      metrics,
      fetchImpl: (async () => new Response(childBody, { status: 200 })) as typeof fetch,
    });
    const result = await collector.collect();
    expect(result.childrenAggregated).toBe(2);
    expect(result.childrenMalformed).toBe(0);
    expect(result.unknownMetricLines).toBe(0); // all four are allowlisted now
    expect(result.lines).toContain("pfm_child_vcs_dirty_block_bytes 16777216");
    expect(result.lines).toContain("pfm_child_vcs_dirty_fold_passes 0");

    const snapshot = metrics.snapshot();
    expect(snapshot.pfm_child_scrape_targets).toBe(2);
    expect(snapshot.pfm_child_scrape_aggregated).toBe(2);
    expect(snapshot.pfm_child_scrape_malformed_total ?? 0).toBe(0);
    // The drop counters are ALWAYS rendered, so 0 is distinguishable from
    // "never scraped" on a dashboard.
    expect(snapshot.pfm_child_scrape_unknown_metrics_total).toBe(0);
    expect(snapshot.pfm_child_scrape_ignored_lines_total).toBe(0);
  });

  test("a child ahead of the manager keeps reporting, and the gap is COUNTED", async () => {
    const golden = readFileSync(goldenPath, "utf8");
    const metrics = new ManagerMetrics();
    const collector = new ChildMetricsCollector({
      targets: () => [{ address: "127.0.0.1:9101" }],
      metrics,
      fetchImpl: (async () =>
        new Response(golden + "vcs_some_round_22_metric 3\n", { status: 200 })) as typeof fetch,
    });
    const result = await collector.collect();
    expect(result.childrenAggregated).toBe(1);
    expect(result.lines).toContain("pfm_child_vcs_dirty_block_bytes 8388608");
    expect(metrics.snapshot().pfm_child_scrape_unknown_metrics_total).toBe(1);
    expect(metrics.snapshot().pfm_child_scrape_errors_total ?? 0).toBe(0);
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

  test("every fixed fsproto per-op counter is explicitly allowlisted", () => {
    const server = readFileSync(fsprotoServerPath, "utf8");
    const opNamesBlock = server.match(
      /var opNames = map\[Op\]string\{(?<body>[\s\S]*?)\n\}/
    )?.groups?.body;
    expect(opNamesBlock).toBeDefined();
    const opNames = [
      ...(opNamesBlock ?? "").matchAll(/Op[A-Za-z0-9]+:\s+"(?<name>[a-z0-9_]+)"/g),
    ].map((match) => match.groups?.name);
    expect(opNames.length).toBeGreaterThan(0);
    for (const name of opNames) {
      expect(name).toBeDefined();
      expect(childMetricAllowlist[`vcs_fsproto_op_${name}`], name).toEqual({
        aggregator: "counter",
      });
    }
    const producerMetrics = opNames.map((name) => `vcs_fsproto_op_${name}`).sort();
    const allowlistedFixedMetrics = Object.keys(childMetricAllowlist)
      .filter(
        (name) =>
          name.startsWith("vcs_fsproto_op_") &&
          name !== "vcs_fsproto_op_other" &&
          name !== "vcs_fsproto_op_latency"
      )
      .sort();
    expect(allowlistedFixedMetrics).toEqual(producerMetrics);

    const parsed = parseChildExposition(
      producerMetrics.map((name, index) => `${name} ${index + 1}`).join("\n") + "\n"
    );
    expect(parsed.ok).toBe(true);
    const aggregate = aggregateChildMetrics([parsed, parsed]);
    expect(aggregate.childrenAggregated).toBe(2);
    expect(aggregate.childrenMalformed).toBe(0);
    expect(aggregate.lines).toContain(
      `pfm_child_${producerMetrics.at(-1)} ${producerMetrics.length * 2}`
    );
  });

  // THE GUARD THAT WAS MISSING. The old version of this test listed seven
  // names by hand, so aad03e9 could add four child metrics without a single
  // test noticing. It is now DERIVED from the Go tree: every literal metric
  // name any non-test Go file registers must be allowlisted, or this fails.
  test("every metric name the Go child registers is allowlisted (derived from source)", () => {
    const registrations = goMetricRegistrations();
    // Sanity: the scan actually found the producer surface.
    expect(registrations.size).toBeGreaterThan(20);
    expect(registrations.has("vcs_ready")).toBe(true);
    expect(registrations.has("vcs_dirty_block_bytes")).toBe(true);
    // The four aad03e9 fold metrics are registered at package init, so they
    // appear in EVERY child's exposition.
    for (const name of [
      "vcs_dirty_fold_released_bytes",
      "vcs_dirty_fold_blocks",
      "vcs_dirty_fold_passes",
      "vcs_dirty_fold_watermark",
    ]) {
      expect(registrations.has(name), `${name} must be registered by the child`).toBe(true);
    }
    const missing = [...registrations].filter((name) => !childMetricAllowlist[name]).sort();
    expect(
      missing,
      `Go registers these child metrics but apps/authority-manager/src/child-metrics.ts ` +
        `does not allowlist them, so they are dropped from every pfm_child_* body: ${missing.join(", ")}`
    ).toEqual([]);
  });

  test("the whole Go-registered surface parses and aggregates in one body", () => {
    // Belt and braces: the derived name set, rendered as one exposition,
    // must produce a pfm_child_* line for every one of them.
    const names = [...goMetricRegistrations()]
      .filter((name) => childMetricAllowlist[name]?.aggregator !== "summary")
      .sort();
    const parsed = parseChildExposition(names.map((name, i) => `${name} ${i + 1}`).join("\n") + "\n");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.skips.unknownMetrics).toBe(0);
    const aggregated = aggregateChildMetrics([parsed]);
    for (const name of names) {
      expect(
        aggregated.lines.some((line) => line.startsWith(`pfm_child_${name} `)),
        name
      ).toBe(true);
    }
  });

  // The OTHER way a Go-side registration can blind a whole body: the child's
  // registry renders counters, gauges and histograms from three separate
  // maps, so one name registered as two kinds (or a counter colliding with a
  // histogram's rendered _count/_sum) emits the SAME series twice, and a
  // duplicate series is a whole-body rejection. Nothing collides today; this
  // keeps it that way rather than discovering it in production.
  test("no child metric name renders twice (duplicate_series is whole-body fatal)", () => {
    const kinds = goMetricRegistrationKinds();
    const multiKind = [...kinds].filter(([, k]) => k.size > 1).map(([name]) => name);
    expect(multiKind, "registered as more than one metric kind").toEqual([]);

    const histograms = [...kinds].filter(([, k]) => k.has("Histogram")).map(([name]) => name);
    const shadowed = histograms.flatMap((base) =>
      ["_count", "_sum"].filter((suffix) => kinds.has(`${base}${suffix}`)).map((s) => `${base}${s}`)
    );
    expect(shadowed, "collides with a histogram's rendered _count/_sum line").toEqual([]);
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
