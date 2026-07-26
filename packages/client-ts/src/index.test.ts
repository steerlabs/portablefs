import { describe, expect, test } from "vitest";
import { sha256Buffer } from "@portablefs/core";
import { VolumeClient } from "./index.js";

describe("VolumeClient", () => {
  test("uploads blob batches with compact binary wire format", async () => {
    const first = Buffer.from("first\n");
    const second = Buffer.from("second\n");
    const firstDigest = sha256Buffer(first);
    const secondDigest = sha256Buffer(second);
    const requests: Array<{ path: string; contentType: string; bytes: Buffer }> = [];
    const client = new VolumeClient({
      baseUrl: "http://volume.test",
      fetchImpl: async (input, init) => {
        const url = new URL(String(input));
        requests.push({
          path: url.pathname,
          contentType: String((init?.headers as Record<string, string>)?.["content-type"] ?? ""),
          bytes: Buffer.from((init?.body as Uint8Array) ?? new Uint8Array()),
        });
        return new Response(
          JSON.stringify({
            blobs: [
              { digest: firstDigest, size: first.byteLength, compression: "none", packed: false },
              { digest: secondDigest, size: second.byteLength, compression: "none", packed: false },
            ],
          }),
          { status: 201, headers: { "content-type": "application/json" } }
        );
      },
    });

    await expect(
      client.uploadBlobs([
        { digest: firstDigest, buffer: first },
        { digest: secondDigest, buffer: second },
      ])
    ).resolves.toMatchObject({
      blobs: [
        { digest: firstDigest, size: first.byteLength },
        { digest: secondDigest, size: second.byteLength },
      ],
    });

    expect(requests).toHaveLength(1);
    expect(requests[0]?.path).toBe("/v1/blobs/batch-binary");
    expect(requests[0]?.contentType).toBe("application/vnd.portablefs.blob-batch.v1");
    expect(requests[0]?.bytes.toString("ascii", 0, 4)).toBe("OSVB");
    const legacyJsonBytes = Buffer.byteLength(
      JSON.stringify({
        blobs: [
          { digest: firstDigest, bytesBase64: first.toString("base64") },
          { digest: secondDigest, bytesBase64: second.toString("base64") },
        ],
      })
    );
    expect(requests[0]?.bytes.byteLength).toBeLessThan(legacyJsonBytes);
  });

  test("falls back to JSON blob batches for older servers", async () => {
    const bytes = Buffer.from("fallback\n");
    const digest = sha256Buffer(bytes);
    const requests: Array<{ path: string; body: string }> = [];
    const client = new VolumeClient({
      baseUrl: "http://volume.test",
      fetchImpl: async (input, init) => {
        const url = new URL(String(input));
        requests.push({
          path: url.pathname,
          body: Buffer.from((init?.body as Uint8Array) ?? new Uint8Array()).toString("utf8"),
        });
        if (url.pathname === "/v1/blobs/batch-binary") {
          return new Response(JSON.stringify({ error: { code: "VOLUME_NOT_FOUND", message: "not found" } }), {
            status: 404,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(
          JSON.stringify({
            blobs: [{ digest, size: bytes.byteLength, compression: "none", packed: false }],
          }),
          { status: 201, headers: { "content-type": "application/json" } }
        );
      },
    });

    await expect(client.uploadBlobs([{ digest, buffer: bytes }])).resolves.toMatchObject({
      blobs: [{ digest, size: bytes.byteLength }],
    });

    expect(requests.map((request) => request.path)).toEqual([
      "/v1/blobs/batch-binary",
      "/v1/blobs/batch",
    ]);
    expect(JSON.parse(requests[1]?.body ?? "{}")).toEqual({
      blobs: [{ digest, bytesBase64: bytes.toString("base64") }],
    });
  });

  test("requests compact blob batch acknowledgements and synthesizes local refs", async () => {
    const first = Buffer.from("ack first\n");
    const second = Buffer.from("ack second\n");
    const firstDigest = sha256Buffer(first);
    const secondDigest = sha256Buffer(second);
    const requests: Array<{ path: string; search: string }> = [];
    const client = new VolumeClient({
      baseUrl: "http://volume.test",
      fetchImpl: async (input) => {
        const url = new URL(String(input));
        requests.push({ path: url.pathname, search: url.search });
        return new Response(
          JSON.stringify({
            count: 2,
            bytes: first.byteLength + second.byteLength,
          }),
          { status: 201, headers: { "content-type": "application/json" } }
        );
      },
    });

    await expect(
      client.uploadBlobs(
        [
          { digest: firstDigest, buffer: first },
          { digest: secondDigest, buffer: second },
        ],
        { response: "ack" }
      )
    ).resolves.toEqual({
      blobs: [
        { digest: firstDigest, size: first.byteLength, compression: "none", packed: false },
        { digest: secondDigest, size: second.byteLength, compression: "none", packed: false },
      ],
    });

    expect(requests).toEqual([{ path: "/v1/blobs/batch-binary", search: "?response=ack" }]);
  });

  test("accepts full blob batch responses from mixed-version servers when ack is requested", async () => {
    const bytes = Buffer.from("mixed-version ack\n");
    const digest = sha256Buffer(bytes);
    const client = new VolumeClient({
      baseUrl: "http://volume.test",
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            blobs: [{ digest, size: bytes.byteLength, compression: "none", packed: false }],
          }),
          { status: 201, headers: { "content-type": "application/json" } }
        ),
    });

    await expect(
      client.uploadBlobs([{ digest, buffer: bytes }], { response: "ack" })
    ).resolves.toMatchObject({
      blobs: [{ digest, size: bytes.byteLength }],
    });
  });
});
