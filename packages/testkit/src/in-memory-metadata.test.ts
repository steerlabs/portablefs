import { describe, expect, test } from "vitest";
import { computeTreeHash } from "@portablefs/core";
import { protocolVersion, type TreeEntry, type TreeManifest } from "@portablefs/protocol";
import { InMemoryMetadataRepository } from "./in-memory-metadata.js";

describe("InMemoryMetadataRepository listing", () => {
  test("lists a tenant's volumes with branch heads and honors the limit", async () => {
    const metadata = new InMemoryMetadataRepository();
    const first = await metadata.createVolume({ tenantId: "t1", volumeId: "vol_1", branchName: "main" });
    await metadata.createVolume({ tenantId: "t1", volumeId: "vol_2", branchName: "main" });
    await metadata.createVolume({ tenantId: "t2", volumeId: "vol_other", branchName: "main" });

    const listed = await metadata.listVolumes({ tenantId: "t1", limit: 100 });
    expect(listed.map((entry) => entry.volume.id)).toEqual(["vol_1", "vol_2"]);
    expect(listed[0]?.branches).toEqual([
      { name: "main", headCommitId: first.branch.headCommitId },
    ]);

    const limited = await metadata.listVolumes({ tenantId: "t1", limit: 1 });
    expect(limited.map((entry) => entry.volume.id)).toEqual(["vol_1"]);

    await expect(metadata.listVolumes({ tenantId: "t3", limit: 10 })).resolves.toEqual([]);
  });

  test("permits the same public volume id in different tenants without aliasing", async () => {
    const metadata = new InMemoryMetadataRepository();
    await metadata.createVolume({ tenantId: "t1", volumeId: "shared", branchName: "main" });
    await metadata.createVolume({ tenantId: "t2", volumeId: "shared", branchName: "main" });

    await expect(
      metadata.createVolume({ tenantId: "t1", volumeId: "shared", branchName: "other" })
    ).rejects.toMatchObject({ code: "VOLUME_ALREADY_EXISTS", status: 409 });
    await expect(
      metadata.tenantOwnsVolume({ tenantId: "t1", volumeId: "shared" })
    ).resolves.toBe(true);
    await expect(
      metadata.tenantOwnsVolume({ tenantId: "t2", volumeId: "shared" })
    ).resolves.toBe(true);
    expect(
      (await metadata.getStatus({
        tenantId: "t1",
        volumeId: "shared",
        branchName: "main",
      }))?.volume.tenantId
    ).toBe("t1");
    expect(
      (await metadata.getStatus({
        tenantId: "t2",
        volumeId: "shared",
        branchName: "main",
      }))?.volume.tenantId
    ).toBe("t2");
  });

  test("walks branch history newest-first through parent links", async () => {
    const metadata = new InMemoryMetadataRepository();
    const created = await metadata.createVolume({ tenantId: "t1", volumeId: "vol_h", branchName: "main" });
    const attached = await metadata.attachVolume({
      tenantId: "t1",
      volumeId: "vol_h",
      branchName: "main",
      mode: "write",
      shared: false,
      rootPath: "",
      holderId: "history-tester",
      leaseTtlMs: 600_000,
    });
    const lease = attached.session.lease;
    if (!lease) {
      throw new Error("Expected write lease.");
    }
    const attachedManifest = attached.manifest;
    if (!attachedManifest) {
      throw new Error("Expected a manifest on a legacy attach.");
    }

    const firstManifest = withFile(attachedManifest, "a.txt", "one\n");
    const firstCommit = await metadata.commitSummary({
      attachSessionId: attached.session.id,
      leaseId: lease.id,
      fencingToken: lease.fencingToken,
      expectedHeadCommitId: attached.branch.headCommitId,
      manifest: firstManifest,
      mutationCount: 1,
      byteCount: 4,
    });
    const secondManifest = withFile(firstManifest, "b.txt", "two\n");
    const secondCommit = await metadata.commitSummary({
      attachSessionId: attached.session.id,
      leaseId: lease.id,
      fencingToken: lease.fencingToken,
      expectedHeadCommitId: firstCommit.commit.id,
      manifest: secondManifest,
      mutationCount: 1,
      byteCount: 4,
    });

    const history = await metadata.listCommitHistory({
      tenantId: "t1",
      volumeId: "vol_h",
      branchName: "main",
      limit: 50,
    });
    expect(history?.map((commit) => commit.id)).toEqual([
      secondCommit.commit.id,
      firstCommit.commit.id,
      created.head.id,
    ]);
    expect(history?.[0]?.parentCommitId).toBe(firstCommit.commit.id);
    expect(history?.every((commit) => !("manifest" in commit))).toBe(true);

    const capped = await metadata.listCommitHistory({
      tenantId: "t1",
      volumeId: "vol_h",
      branchName: "main",
      limit: 2,
    });
    expect(capped?.map((commit) => commit.id)).toEqual([
      secondCommit.commit.id,
      firstCommit.commit.id,
    ]);

    await expect(
      metadata.listCommitHistory({
        tenantId: "t1",
        volumeId: "vol_h",
        branchName: "missing",
        limit: 10,
      })
    ).resolves.toBeNull();
    await expect(
      metadata.listCommitHistory({
        tenantId: "t1",
        volumeId: "vol_missing",
        branchName: "main",
        limit: 10,
      })
    ).resolves.toBeNull();

    // A branch fork's history crosses the branch point into pre-fork ancestry.
    await metadata.snapshot({
      tenantId: "t1",
      volumeId: "vol_h",
      branchName: "main",
      name: "before-fork",
    });
    const fork = await metadata.createBranch({
      tenantId: "t1",
      volumeId: "vol_h",
      branchName: "fork",
      fromBranch: "main",
      fromSnapshotName: "before-fork",
    });
    const forkHistory = await metadata.listCommitHistory({
      tenantId: "t1",
      volumeId: "vol_h",
      branchName: "fork",
      limit: 10,
    });
    expect(forkHistory?.map((commit) => commit.id)).toEqual([
      fork.head.id,
      secondCommit.commit.id,
      firstCommit.commit.id,
      created.head.id,
    ]);
  });
});

describe("InMemoryMetadataRepository retirement", () => {
  test("retireVolume flips once, hides the volume from listings, and fences every resolver", async () => {
    const metadata = new InMemoryMetadataRepository();
    await metadata.createVolume({ tenantId: "t1", volumeId: "vol_r", branchName: "main" });
    const attached = await metadata.attachVolume({
      tenantId: "t1",
      volumeId: "vol_r",
      branchName: "main",
      mode: "write",
      shared: false,
      rootPath: "",
      holderId: "retire-tester",
      leaseTtlMs: 600_000,
    });
    const lease = attached.session.lease;
    if (!lease) {
      throw new Error("Expected write lease.");
    }
    const snapshot = await metadata.snapshot({
      tenantId: "t1",
      volumeId: "vol_r",
      branchName: "main",
    });

    // Foreign tenant and unknown ids never flip anything.
    await expect(metadata.retireVolume({ volumeId: "vol_r", tenantId: "t2" })).resolves.toBeNull();
    await expect(metadata.retireVolume({ volumeId: "vol_x", tenantId: "t1" })).resolves.toBeNull();

    const receipt = await metadata.retireVolume({ volumeId: "vol_r", tenantId: "t1", now: 1234 });
    expect(receipt).toEqual({ volumeId: "vol_r", retiredAtMs: 1234 });
    // Already retired = null (the route's non-enumerating 404); the first
    // receipt is never overwritten.
    await expect(metadata.retireVolume({ volumeId: "vol_r", tenantId: "t1" })).resolves.toBeNull();
    expect(metadata.retired.get("t1\0vol_r")).toBe(1234);

    await expect(metadata.listVolumes({ tenantId: "t1", limit: 10 })).resolves.toEqual([]);
    await expect(
      metadata.tenantOwnsVolume({ tenantId: "t1", volumeId: "vol_r" })
    ).resolves.toBe(false);
    await expect(metadata.sessionTenant(attached.session.id)).resolves.toBeNull();
    await expect(metadata.leaseTenant(lease.id)).resolves.toBeNull();
    await expect(metadata.snapshotTenant(snapshot.id)).resolves.toBeNull();
    const head = await metadata.getHead({
      tenantId: "t1",
      volumeId: "vol_r",
      branchName: "main",
    });
    if (!head) {
      throw new Error("Expected the branch head to survive retirement (nothing is deleted).");
    }
    await expect(metadata.commitTenant(head.head.id)).resolves.toBeNull();
  });
});

describe("InMemoryMetadataRepository blob probe filter", () => {
  test("reports unreferenced digests missing even when they exist globally", async () => {
    const metadata = new InMemoryMetadataRepository();
    const mine = `sha256:${"a".repeat(64)}`;
    const theirs = `sha256:${"b".repeat(64)}`;
    const unknown = `sha256:${"c".repeat(64)}`;
    await metadata.addBlobRefs("t1", [mine]);
    await metadata.addBlobRefs("t2", [theirs]);
    // `theirs` is stored globally, but t1 holds no reference: it must still be
    // reported missing, or probing would leak t2's content and skip the
    // proof-of-possession upload.
    await metadata.recordBlobs([
      { digest: mine, size: 1 },
      { digest: theirs, size: 2 },
    ]);

    await expect(
      metadata.filterUnreferencedBlobs("t1", [mine, theirs, unknown, theirs])
    ).resolves.toEqual([theirs, unknown]);
    await expect(metadata.filterUnreferencedBlobs("t2", [theirs])).resolves.toEqual([]);
    await expect(metadata.filterUnreferencedBlobs("t3", [mine])).resolves.toEqual([mine]);
  });
});

function withFile(previous: TreeManifest, filePath: string, contents: string): TreeManifest {
  const bytes = Buffer.from(contents, "utf8");
  const digest = `sha256:${Buffer.from(filePath).toString("hex").padEnd(64, "0").slice(0, 64)}`;
  const entry: TreeEntry = {
    path: filePath,
    kind: "file",
    mode: 0o644,
    size: bytes.byteLength,
    mtimeMs: 0,
    executable: false,
    blob: {
      digest,
      size: bytes.byteLength,
      compression: "none",
      packed: false,
    },
  };
  const entries = [...previous.entries, entry].sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0
  );
  return {
    version: protocolVersion,
    entries,
    treeHash: computeTreeHash(entries),
  };
}
