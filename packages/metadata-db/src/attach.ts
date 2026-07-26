import { createHash } from "node:crypto";
import { normalizeVolumePath, stableJson } from "@portablefs/core";
import type { AttachMode } from "@portablefs/protocol";

/**
 * Canonical semantic binding for a receipted attach. Authentication material
 * is deliberately excluded; the verified tenant identity is included. Paths
 * are normalized and prefetch hints are a set, so semantically identical
 * retries do not conflict because of spelling or order.
 */
export function attachRequestFingerprint(args: {
  tenantId: string;
  volumeId: string;
  branchName: string;
  mode: AttachMode;
  shared: boolean;
  rootPath: string;
  holderId: string;
  leaseTtlMs: number;
  prefetchPaths?: readonly string[] | undefined;
  clientInfo?: Readonly<Record<string, unknown>> | undefined;
}): string {
  const canonical = stableJson({
    version: "portablefs-attach-receipt-v1",
    tenantId: args.tenantId,
    volumeId: args.volumeId,
    branchName: args.branchName,
    mode: args.mode,
    shared: args.shared,
    rootPath: normalizeVolumePath(args.rootPath),
    holderId: args.holderId,
    leaseTtlMs: args.leaseTtlMs,
    prefetchPaths: [
      ...new Set((args.prefetchPaths ?? []).map((path) => normalizeVolumePath(path))),
    ].sort(),
    clientInfo: args.clientInfo ?? {},
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}
