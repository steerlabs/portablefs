import { describe, expect, test } from "vitest";
import { BlobRangeNotSatisfiableError, sha256Buffer } from "@portablefs/core";
import { S3BlobStore, s3ConfigFromEnv, signS3RequestHeaders } from "./index.js";

async function collect(stream: AsyncIterable<Buffer>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

// An in-memory bucket that behaves like the metadata-writing PUT path of this
// store: object bodies plus the x-amz-meta-* headers real uploads carry.
function streamingBucket(options: { honorRange?: boolean } = {}) {
  const honorRange = options.honorRange ?? true;
  const objects = new Map<string, { body: Buffer; headers: Record<string, string> }>();
  const requests: Array<{ method: string; headers: Headers }> = [];
  const store = new S3BlobStore({
    endpoint: "https://t3.storageapi.dev",
    bucket: "bucket-test",
    region: "auto",
    urlStyle: "virtual-host",
    accessKeyId: "access",
    secretAccessKey: "secret",
    fetchImpl: async (input, init) => {
      const method = init?.method ?? "GET";
      const headers = new Headers(init?.headers);
      requests.push({ method, headers });
      const key = new URL(String(input)).pathname;
      if (method === "PUT") {
        objects.set(key, {
          body: Buffer.from((init?.body ?? Buffer.alloc(0)) as ArrayBuffer),
          headers: {
            "x-amz-meta-size": headers.get("x-amz-meta-size") ?? "0",
            "x-amz-meta-compression": headers.get("x-amz-meta-compression") ?? "none",
          },
        });
        return new Response(null, { status: 200 });
      }
      const object = objects.get(key);
      if (method === "HEAD") {
        if (!object) {
          return new Response(null, { status: 404 });
        }
        return new Response(null, {
          status: 200,
          headers: { ...object.headers, "content-length": String(object.body.byteLength) },
        });
      }
      if (method === "GET") {
        if (!object) {
          return new Response("missing", { status: 404 });
        }
        const range = headers.get("range");
        if (range && honorRange) {
          const match = /^bytes=(\d+)-(\d+)$/.exec(range);
          if (!match) {
            return new Response("bad range", { status: 416 });
          }
          const start = Number(match[1]);
          const end = Math.min(Number(match[2]), object.body.byteLength - 1);
          return new Response(new Uint8Array(object.body.subarray(start, end + 1)), {
            status: 206,
            headers: object.headers,
          });
        }
        return new Response(new Uint8Array(object.body), { status: 200, headers: object.headers });
      }
      if (method === "DELETE") {
        objects.delete(key);
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 405 });
    },
  });
  return { store, objects, requests };
}

describe("S3BlobStore", () => {
  test("signs virtual-host requests and stores content-addressed blobs", async () => {
    const objects = new Map<string, Buffer>();
    const requests: Array<{ method: string; url: string; authorization: string | null }> = [];
    const store = new S3BlobStore({
      endpoint: "https://t3.storageapi.dev",
      bucket: "bucket-test",
      region: "auto",
      urlStyle: "virtual-host",
      accessKeyId: "access",
      secretAccessKey: "secret",
      prefix: "prefix",
      now: () => new Date("2026-06-16T12:00:00.000Z"),
      fetchImpl: async (input, init) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        const authorization = new Headers(init?.headers).get("authorization");
        requests.push({ method, url, authorization });
        const key = new URL(url).pathname;
        if (!authorization?.startsWith("AWS4-HMAC-SHA256 ")) {
          return new Response("missing signature", { status: 403 });
        }
        if (method === "HEAD") {
          return new Response(null, { status: objects.has(key) ? 200 : 404 });
        }
        if (method === "PUT") {
          objects.set(key, Buffer.from((init?.body ?? Buffer.alloc(0)) as ArrayBuffer));
          return new Response(null, { status: 200 });
        }
        if (method === "GET") {
          const body = objects.get(key);
          return body ? new Response(body) : new Response("missing", { status: 404 });
        }
        if (method === "DELETE") {
          objects.delete(key);
          return new Response(null, { status: 204 });
        }
        return new Response("bad method", { status: 405 });
      },
    });

    const bytes = Buffer.from("railway bucket bytes\n");
    const digest = sha256Buffer(bytes);
    const uploaded = await store.put(bytes, { digest });

    expect(uploaded.blob.storageKey).toMatch(/^prefix\/blobs\/sha256\//);
    expect(requests[0]?.method).toBe("HEAD");
    expect(requests[0]?.url).toContain("https://bucket-test.t3.storageapi.dev/");
    expect(await store.has(digest)).toBe(true);
    await expect(store.get(digest)).resolves.toEqual(bytes);
    await store.delete(digest);
    await expect(store.has(digest)).resolves.toBe(false);
  });

  test("supports path-style bucket URLs", async () => {
    const urls: string[] = [];
    const store = new S3BlobStore({
      endpoint: "https://storage.example.test/root",
      bucket: "bucket-test",
      region: "auto",
      urlStyle: "path",
      accessKeyId: "access",
      secretAccessKey: "secret",
      fetchImpl: async (input) => {
        urls.push(String(input));
        return new Response(null, { status: 404 });
      },
    });

    await expect(store.has("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).resolves.toBe(false);
    expect(urls[0]).toContain("https://storage.example.test/root/bucket-test/blobs/sha256/aa/");
  });

  test("can skip existence checks for idempotent API upload paths", async () => {
    const requests: string[] = [];
    const store = new S3BlobStore({
      endpoint: "https://t3.storageapi.dev",
      bucket: "bucket-test",
      region: "auto",
      urlStyle: "virtual-host",
      accessKeyId: "access",
      secretAccessKey: "secret",
      fetchImpl: async (_input, init) => {
        requests.push(init?.method ?? "GET");
        return new Response(null, { status: 200 });
      },
    });

    const bytes = Buffer.from("skip preflight\n");
    await store.put(bytes, { digest: sha256Buffer(bytes), checkExisting: false });

    expect(requests).toEqual(["PUT"]);
  });

  test("stores compressible blobs compressed while reading original bytes", async () => {
    const objects = new Map<string, { body: Buffer; headers: Headers }>();
    const store = new S3BlobStore({
      endpoint: "https://t3.storageapi.dev",
      bucket: "bucket-test",
      region: "auto",
      urlStyle: "virtual-host",
      accessKeyId: "access",
      secretAccessKey: "secret",
      fetchImpl: async (input, init) => {
        const key = new URL(String(input)).pathname;
        const method = init?.method ?? "GET";
        if (method === "HEAD") {
          return new Response(null, { status: objects.has(key) ? 200 : 404 });
        }
        if (method === "PUT") {
          objects.set(key, {
            body: Buffer.from((init?.body ?? Buffer.alloc(0)) as ArrayBuffer),
            headers: new Headers(init?.headers),
          });
          return new Response(null, { status: 200 });
        }
        if (method === "GET") {
          const object = objects.get(key);
          if (!object) {
            return new Response("missing", { status: 404 });
          }
          return new Response(object.body, {
            headers: {
              "x-amz-meta-compression": object.headers.get("x-amz-meta-compression") ?? "none",
            },
          });
        }
        return new Response(null, { status: 204 });
      },
    });

    const bytes = Buffer.from("const prospect = 'qualified';\n".repeat(2000));
    const digest = sha256Buffer(bytes);
    const uploaded = await store.put(bytes, { digest });
    const stored = [...objects.values()][0];

    expect(uploaded.blob.compression).toBe("gzip");
    expect(stored?.body.byteLength).toBeLessThan(bytes.byteLength / 4);
    await expect(store.get(digest)).resolves.toEqual(bytes);
  });

  test("requests server-side encryption on upload when configured, omits it otherwise", async () => {
    const sse: Array<string | null> = [];
    const make = (serverSideEncryption?: string) =>
      new S3BlobStore({
        endpoint: "https://t3.storageapi.dev",
        bucket: "bucket-test",
        region: "auto",
        urlStyle: "virtual-host",
        accessKeyId: "access",
        secretAccessKey: "secret",
        ...(serverSideEncryption ? { serverSideEncryption } : {}),
        fetchImpl: async (_input, init) => {
          if ((init?.method ?? "GET") === "PUT") {
            sse.push(new Headers(init?.headers).get("x-amz-server-side-encryption"));
          }
          return new Response(null, { status: 200 });
        },
      });

    const bytes = Buffer.from("encrypt at rest\n");
    const digest = sha256Buffer(bytes);
    await make("AES256").put(bytes, { digest, checkExisting: false });
    await make().put(bytes, { digest, checkExisting: false });
    expect(sse).toEqual(["AES256", null]); // header present when configured, absent otherwise
  });

  test("streams verified full reads and serves uncompressed ranges with a signed Range request", async () => {
    const bucket = streamingBucket();
    const bytes = Buffer.from("0123456789abcdefghij"); // < 1024: stored uncompressed
    const digest = sha256Buffer(bytes);
    await bucket.store.put(bytes, { digest, checkExisting: false });

    const full = await bucket.store.openBlobStream(digest);
    expect(full.totalLength).toBe(bytes.byteLength);
    expect(full.start).toBe(0);
    expect(full.end).toBe(bytes.byteLength - 1);
    expect(full.buffered).toBe(false);
    expect(await collect(full.stream)).toEqual(bytes);

    const ranged = await bucket.store.openBlobStream(digest, {
      range: { kind: "bounded", start: 2, end: 5 },
    });
    expect(ranged.totalLength).toBe(bytes.byteLength);
    expect(ranged.start).toBe(2);
    expect(ranged.end).toBe(5);
    expect((await collect(ranged.stream)).toString()).toBe("2345");

    const suffix = await bucket.store.openBlobStream(digest, {
      range: { kind: "suffix", length: 4 },
    });
    expect((await collect(suffix.stream)).toString()).toBe("ghij");

    // The ranged fetch asked S3 for exactly the window, with a signed request.
    const rangedGet = bucket.requests.find((request) => request.headers.get("range"));
    expect(rangedGet?.headers.get("range")).toBe("bytes=2-5");
    expect(rangedGet?.headers.get("authorization")).toMatch(/^AWS4-HMAC-SHA256 /);
  });

  test("slices the requested window when a backend ignores Range", async () => {
    const bucket = streamingBucket({ honorRange: false });
    const bytes = Buffer.from("0123456789abcdefghij");
    const digest = sha256Buffer(bytes);
    await bucket.store.put(bytes, { digest, checkExisting: false });

    const ranged = await bucket.store.openBlobStream(digest, {
      range: { kind: "bounded", start: 10, end: 13 },
    });
    expect((await collect(ranged.stream)).toString()).toBe("abcd");
  });

  test("streams gzip-stored blobs decompressed, verified, and plaintext-ranged", async () => {
    const bucket = streamingBucket();
    const bytes = Buffer.from("const prospect = 'qualified';\n".repeat(2000));
    const digest = sha256Buffer(bytes);
    await bucket.store.put(bytes, { digest, checkExisting: false });
    const stored = [...bucket.objects.values()][0];
    expect(stored?.headers["x-amz-meta-compression"]).toBe("gzip");
    expect(stored?.body.byteLength).toBeLessThan(bytes.byteLength / 4);

    const full = await bucket.store.openBlobStream(digest);
    expect(full.totalLength).toBe(bytes.byteLength);
    expect(await collect(full.stream)).toEqual(bytes);

    const ranged = await bucket.store.openBlobStream(digest, {
      range: { kind: "bounded", start: 6, end: 13 },
    });
    expect(ranged.totalLength).toBe(bytes.byteLength);
    expect((await collect(ranged.stream)).toString()).toBe("prospect");
  });

  test("refuses unsatisfiable ranges typed with the plaintext length", async () => {
    const bucket = streamingBucket();
    const bytes = Buffer.from("short body");
    const digest = sha256Buffer(bytes);
    await bucket.store.put(bytes, { digest, checkExisting: false });

    const error = await bucket.store
      .openBlobStream(digest, { range: { kind: "open", start: bytes.byteLength } })
      .then(
        () => undefined,
        (thrown: unknown) => thrown
      );
    expect(error).toBeInstanceOf(BlobRangeNotSatisfiableError);
    expect((error as BlobRangeNotSatisfiableError).totalLength).toBe(bytes.byteLength);
  });

  test("corrupted bucket bytes error the full stream before the body can complete", async () => {
    const bucket = streamingBucket();
    const bytes = Buffer.from("original uncorrupted body");
    const digest = sha256Buffer(bytes);
    await bucket.store.put(bytes, { digest, checkExisting: false });
    const key = [...bucket.objects.keys()][0];
    const object = bucket.objects.get(key ?? "");
    if (!key || !object) {
      throw new Error("fixture object missing");
    }
    bucket.objects.set(key, { ...object, body: Buffer.from("tampered corrupted body!!") });

    const opened = await bucket.store.openBlobStream(digest);
    const received: Buffer[] = [];
    await expect(
      (async () => {
        for await (const chunk of opened.stream) {
          received.push(chunk);
        }
      })()
    ).rejects.toThrow(/checksum mismatch/);
    expect(Buffer.concat(received).byteLength).toBeLessThan(bytes.byteLength);
  });

  test("reads the canonical AWS_* environment shape", () => {
    expect(
      s3ConfigFromEnv({
        AWS_ENDPOINT_URL: "https://t3.storageapi.dev",
        AWS_S3_BUCKET_NAME: "bucket-test",
        AWS_DEFAULT_REGION: "auto",
        AWS_S3_URL_STYLE: "virtual-host",
        AWS_ACCESS_KEY_ID: "access",
        AWS_SECRET_ACCESS_KEY: "secret",
      })
    ).toMatchObject({
      endpoint: "https://t3.storageapi.dev",
      bucket: "bucket-test",
      region: "auto",
      urlStyle: "virtual-host",
    });
  });

  test("maps the retired VOLUME_RAILWAY_BUCKET_* spellings onto the canonical names, whole-family", () => {
    expect(
      s3ConfigFromEnv({
        VOLUME_RAILWAY_BUCKET_ENDPOINT: "https://buckets.example.test",
        VOLUME_RAILWAY_BUCKET_NAME: "explicit-bucket",
        VOLUME_RAILWAY_BUCKET_ACCESS_KEY_ID: "explicit-access",
        VOLUME_RAILWAY_BUCKET_SECRET_ACCESS_KEY: "explicit-secret",
        AWS_ENDPOINT_URL: "https://t3.storageapi.dev",
        AWS_S3_BUCKET_NAME: "cli-bucket",
        AWS_ACCESS_KEY_ID: "cli-access",
        AWS_SECRET_ACCESS_KEY: "cli-secret",
      })
    ).toMatchObject({
      endpoint: "https://buckets.example.test",
      bucket: "explicit-bucket",
      accessKeyId: "explicit-access",
      prefix: "portablefs",
    });
  });

  test("aliases the retired prefix/SSE spellings independently of the credential family", () => {
    expect(
      s3ConfigFromEnv({
        AWS_ENDPOINT_URL: "https://t3.storageapi.dev",
        AWS_S3_BUCKET_NAME: "bucket-test",
        AWS_ACCESS_KEY_ID: "access",
        AWS_SECRET_ACCESS_KEY: "secret",
        VOLUME_RAILWAY_BUCKET_PREFIX: "legacy-prefix",
        VOLUME_RAILWAY_BUCKET_SSE: "AES256",
      })
    ).toMatchObject({
      prefix: "legacy-prefix",
      serverSideEncryption: "AES256",
    });
  });

  test("signs a fixed request deterministically (the one shared SigV4 signer)", () => {
    const headers = signS3RequestHeaders({
      method: "GET",
      url: new URL("https://bkt.t3.storageapi.dev/history/t/local/pft2/sha256/ab/cd/i1"),
      region: "auto",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      now: new Date("2026-01-02T03:04:05.000Z"),
    });
    expect(headers["x-amz-date"]).toBe("20260102T030405Z");
    expect(headers["x-amz-content-sha256"]).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    expect(headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/auto/s3/aws4_request, " +
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
        "Signature=a32fcfd0b969c426664d10dabcd86fd6f4b5eac7bd7286fb8cff665e890ad913"
    );
  });

  test("canonicalizes query parameters per SigV4 (sorted, %20 spaces, extras escaped)", () => {
    const base = {
      method: "GET" as const,
      region: "auto",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      now: new Date("2026-01-02T03:04:05.000Z"),
    };
    // Same logical query, two insertion orders and one '+'-space spelling:
    // canonical signing must produce the identical signature for all three.
    const a = signS3RequestHeaders({
      ...base,
      url: new URL("https://bkt.example.com/k?prefix=a b&list-type=2&marker=x*(1)"),
    });
    const b = signS3RequestHeaders({
      ...base,
      url: new URL("https://bkt.example.com/k?marker=x*(1)&prefix=a+b&list-type=2"),
    });
    expect(a.authorization).toBe(b.authorization);
  });
});
