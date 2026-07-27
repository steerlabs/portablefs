import { describe, expect, test } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { S3ExactKeyReader, historyStoreRegistryFromEnv } from "./history-stores.js";

// ---------------------------------------------------------------------------
// Recorded storage keys are the store's FULLY PREFIXED exact keys (the Go
// worker records Store.ExactKey = prefix + relative key). Readers must
// present them verbatim: the declared prefix is physical-target identity,
// never something to re-apply. Re-applying it double-prefixes every read and
// turns a healthy store into HISTORY_OBJECT_UNAVAILABLE — exactly what took
// down the first Railway deployment.
// ---------------------------------------------------------------------------

function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

describe("S3ExactKeyReader", () => {
  test("presents the recorded key verbatim: declared prefix is never re-applied", async () => {
    const body = Buffer.from("history object bytes");
    const recordedKey = `history/t/org_founder/pft2/sha256/ab/${sha256Hex(body)}/i1`;
    const requested: string[] = [];
    const reader = new S3ExactKeyReader({
      endpoint: "https://t3.storageapi.dev",
      region: "auto",
      bucket: "pfs-history-a",
      accessKeyId: "key",
      secretAccessKey: "secret",
      fetchImpl: async (input) => {
        requested.push(String(input));
        return new Response(new Uint8Array(body), { status: 200 });
      },
    });

    const bytes = await reader.readExactKey(recordedKey, {
      expectedSize: body.byteLength,
      maxBytes: 1024,
    });

    expect(bytes.equals(body)).toBe(true);
    expect(requested).toEqual([`https://pfs-history-a.t3.storageapi.dev/${recordedKey}`]);
  });

  test("path-style URLs place the bucket on the path with the verbatim key", async () => {
    const body = Buffer.from("x");
    const recordedKey = "history/t/local/pft2/sha256/aa/a1/i1";
    const requested: string[] = [];
    const reader = new S3ExactKeyReader({
      endpoint: "http://127.0.0.1:9000",
      region: "auto",
      bucket: "bkt",
      accessKeyId: "key",
      secretAccessKey: "secret",
      pathStyle: true,
      fetchImpl: async (input) => {
        requested.push(String(input));
        return new Response(new Uint8Array(body), { status: 200 });
      },
    });

    await reader.readExactKey(recordedKey, { expectedSize: 1, maxBytes: 8 });
    expect(requested).toEqual([`http://127.0.0.1:9000/bkt/${recordedKey}`]);
  });
});

describe("historyStoreRegistryFromEnv", () => {
  test("fs domains confine to the PLAIN rootDir so prefixed recorded keys resolve once", async () => {
    const rootDir = await mkdtemp(path.join(tmpdir(), "pfs-hist-"));
    const body = Buffer.from("fs history object");
    const recordedKey = `history/t/local/pft2/sha256/cd/${sha256Hex(body)}/i1`;
    await mkdir(path.dirname(path.join(rootDir, recordedKey)), { recursive: true });
    await writeFile(path.join(rootDir, recordedKey), body);

    const registry = historyStoreRegistryFromEnv({
      PFH_WORKER_STORES_JSON: JSON.stringify([
        { failureDomain: "local", kind: "fs", rootDir, prefix: "history" },
      ]),
    } as NodeJS.ProcessEnv);

    const domain = registry?.get("local");
    expect(domain).toBeDefined();
    const bytes = await domain!.reader.readExactKey(recordedKey, {
      expectedSize: body.byteLength,
      maxBytes: 1024,
    });
    expect(bytes.equals(body)).toBe(true);
  });
});
