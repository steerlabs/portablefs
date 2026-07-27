#!/usr/bin/env node
import { performance } from "node:perf_hooks";
import {
  applyManifestDiffIndexed,
  canonicalizeManifestDiff,
  computeTreeHash,
  createManifestIndex,
  diffManifestIndexes,
} from "../packages/core/dist/tree.js";

const fileCount = Number(process.env.PORTABLEFS_BENCH_MANIFEST_FILES || 50_000);
const iterations = Number(process.env.PORTABLEFS_BENCH_MANIFEST_ITERS || 100);
const mutationCount = Number(process.env.PORTABLEFS_BENCH_MANIFEST_MUTATIONS || 1);

const baseEntries = Array.from({ length: fileCount }, (_, index) => {
  const name = String(index).padStart(8, "0");
  return {
    path: `data/${name}.txt`,
    kind: "file",
    mode: 0o644,
    size: 512,
    mtimeMs: 1,
    executable: false,
    blob: {
      digest: fakeDigest(index),
      size: 512,
      compression: "none",
      packed: false,
    },
  };
});
const baseManifest = {
  version: 1,
  treeHash: computeTreeHash(baseEntries),
  entries: baseEntries,
};
const baseIndexStarted = performance.now();
const baseIndex = createManifestIndex(baseManifest);
const baseIndexMs = performance.now() - baseIndexStarted;
const safeMutationCount = Math.max(1, Math.min(mutationCount, fileCount));
const firstMutationIndex = Math.max(0, Math.min(fileCount - safeMutationCount, Math.floor(fileCount / 2)));
const changed = Array.from({ length: safeMutationCount }, (_, offset) => {
  const source = baseEntries[firstMutationIndex + offset];
  if (!source) {
    throw new Error("Benchmark mutation source is outside the manifest.");
  }
  return {
    ...source,
    size: source.size + 1,
    mtimeMs: source.mtimeMs + 1,
    blob: {
      ...source.blob,
      digest: fakeDigest(fileCount + offset),
      size: source.blob.size + 1,
    },
  };
});
const diff = {
  added: [],
  changed,
  removed: [],
  mutationCount: changed.length,
  byteCount: changed.reduce((total, entry) => total + entry.blob.size, 0),
};

const applyAndDiffSamples = await measure(iterations, () => {
  const applied = applyManifestDiffIndexed(baseIndex, diff);
  const canonical = diffManifestIndexes(baseIndex, applied.index);
  if (canonical.mutationCount !== safeMutationCount) {
    throw new Error(`Expected ${safeMutationCount} mutation(s), received ${canonical.mutationCount}.`);
  }
});
const canonicalDeltaSamples = await measure(iterations, () => {
  const canonical = canonicalizeManifestDiff(baseIndex, diff);
  if (canonical.mutationCount !== safeMutationCount) {
    throw new Error(`Expected ${safeMutationCount} mutation(s), received ${canonical.mutationCount}.`);
  }
});
const cleanDiffSamples = await measure(iterations, () => {
  const canonical = diffManifestIndexes(baseIndex, baseIndex);
  if (canonical.mutationCount !== 0) {
    throw new Error(`Expected clean diff, received ${canonical.mutationCount}.`);
  }
});

console.log(
  JSON.stringify(
    {
      ok: true,
      fileCount,
      mutationCount: safeMutationCount,
      iterations,
      baseIndexMs,
      indexedApplyAndCanonicalDiff: summarize(applyAndDiffSamples),
      touchedPathCanonicalDelta: summarize(canonicalDeltaSamples),
      indexedCleanDiff: summarize(cleanDiffSamples),
    },
    null,
    2
  )
);

async function measure(count, fn) {
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    const started = performance.now();
    await fn(index);
    samples.push(performance.now() - started);
  }
  return samples;
}

function summarize(samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  const sum = samples.reduce((total, value) => total + value, 0);
  return {
    minMs: sorted[0] ?? 0,
    meanMs: sum / Math.max(1, samples.length),
    p50Ms: percentile(sorted, 0.5),
    p95Ms: percentile(sorted, 0.95),
    maxMs: sorted.at(-1) ?? 0,
  };
}

function percentile(sorted, ratio) {
  if (!sorted.length) {
    return 0;
  }
  const index = Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * ratio));
  return sorted[index] ?? 0;
}

function fakeDigest(index) {
  return `sha256:${index.toString(16).padStart(64, "0").slice(-64)}`;
}
