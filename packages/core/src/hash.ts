import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { BlobDigest } from "@portablefs/protocol";

export function sha256Buffer(buffer: Buffer | Uint8Array | string): BlobDigest {
  return `sha256:${createHash("sha256").update(buffer).digest("hex")}`;
}

export async function sha256File(path: string): Promise<BlobDigest> {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return `sha256:${hash.digest("hex")}`;
}

export function stableJson(value: unknown): string {
  return JSON.stringify(sortForStableJson(value));
}

function sortForStableJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortForStableJson);
  }
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(object).sort()) {
      const child = object[key];
      if (child !== undefined) {
        sorted[key] = sortForStableJson(child);
      }
    }
    return sorted;
  }
  return value;
}

