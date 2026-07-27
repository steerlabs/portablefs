import { randomUUID } from "node:crypto";
import {
  applyManifestDiffIndexed,
  canonicalizeManifestDiff,
  collectMutationPaths,
  computeTreeHash,
  createManifestIndex,
  diffHasPathConflict,
  diffManifestIndexes,
  diffManifests,
  isEqualOrDescendantPath,
  joinVolumePath,
  normalizeVolumePath,
  pathDelegationsOverlap,
  projectManifest,
  type ManifestIndex,
} from "@portablefs/core";
import {
  protocolVersion,
  treeManifestDiffSchema,
  treeManifestSchema,
  type AttachSession,
  type PathDelegation,
  type TreeManifestDiff,
  type TreeManifest,
  type Volume,
  type VolumeBranch,
  type VolumeCommit,
  type VolumeCommitSummary,
  type VolumeLease,
  type VolumeSnapshot,
} from "@portablefs/protocol";
import {
  MetadataConflictError,
  type AttachVolumeInput,
  type AttachVolumeResult,
  type CheckinInput,
  type CheckinResult,
  type CheckoutInput,
  type CheckoutResult,
  type CreateBranchInput,
  type CommitVolumeDeltaInput,
  type CommitVolumeInput,
  type CommitVolumeResult,
  type CommitVolumeSummaryResult,
  type CreateVolumeInput,
  type CreateVolumeResult,
  type DetachVolumeInput,
  type ForkSnapshotInput,
  type ListBranchesInput,
  type ListCommitHistoryInput,
  type ListDelegationsInput,
  type ListSnapshotsInput,
  type ListVolumesInput,
  type MetadataRepository,
  type RenewLeaseInput,
  type SnapshotInput,
  type WaitForHeadInput,
  type VolumeListEntry,
  type VolumeManifestDiffInput,
  type VolumeManifestDiffResult,
  type VolumeHeadResult,
  type VolumeStatusInput,
} from "@portablefs/metadata-db";

interface BranchState extends VolumeBranch {
  tenantId: string;
  leaseCounter: number;
}

const manifestIndexCacheLimit = 128;

export class InMemoryMetadataRepository implements MetadataRepository {
  readonly volumes = new Map<string, Volume>();
  readonly branches = new Map<string, BranchState>();
  readonly commits = new Map<string, VolumeCommit>();
  readonly sessions = new Map<string, AttachSession>();
  readonly leases = new Map<string, VolumeLease>();
  readonly delegations = new Map<string, PathDelegation & { leaseId: string }>();
  readonly snapshots = new Map<string, VolumeSnapshot>();
  readonly blobs = new Map<
    string,
    { digest: string; size: number; storageKey?: string; createdAt: number }
  >();
  // tenantId\0volumeId -> retirement instant (epoch ms). Mirror of
  // volumes.retired_at
  // (migration 021): a retired volume stays in `volumes` (nothing is deleted)
  // but resolves as absent through the ownership resolvers and the listing.
  readonly retired = new Map<string, number>();
  readonly tenants = new Set<string>();
  readonly tenantTokens = new Map<string, string>(); // tokenHash -> tenantId
  // credentialHash -> pinned scope. There is no mint path on MetadataRepository
  // (minting lives on the manager control store), so tests populate this directly.
  readonly runtimeReadCredentials = new Map<
    string,
    { tenantId: string; volumeId: string; branchName: string }
  >();
  readonly blobRefs = new Set<string>(); // `${tenantId}\0${digest}`
  private readonly manifestIndexCache = new Map<string, ManifestIndex>();
  private readonly headWaiters = new Map<
    string,
    Set<{ afterCommitId: string; resolve: () => void; timer: NodeJS.Timeout }>
  >();

  private manifestIndexForCommit(commit: VolumeCommit): ManifestIndex {
    const cached = this.manifestIndexCache.get(commit.id);
    if (cached) {
      this.manifestIndexCache.delete(commit.id);
      this.manifestIndexCache.set(commit.id, cached);
      return cached;
    }
    const index = createManifestIndex(commit.manifest);
    this.rememberManifestIndex(commit.id, index);
    return index;
  }

  private rememberManifestIndex(commitId: string, index: ManifestIndex): void {
    if (this.manifestIndexCache.has(commitId)) {
      this.manifestIndexCache.delete(commitId);
    }
    this.manifestIndexCache.set(commitId, index);
    while (this.manifestIndexCache.size > manifestIndexCacheLimit) {
      const oldest = this.manifestIndexCache.keys().next().value;
      if (!oldest) {
        break;
      }
      this.manifestIndexCache.delete(oldest);
    }
  }

  async createVolume(input: CreateVolumeInput): Promise<CreateVolumeResult> {
    const now = Date.now();
    const volumeId = input.volumeId ?? `vol_${randomUUID()}`;
    const volumeKey = tenantVolumeKey(input.tenantId, volumeId);
    if (this.volumes.has(volumeKey)) {
      throw new MetadataConflictError("VOLUME_ALREADY_EXISTS", "Volume already exists.", 409);
    }
    const branchId = `br_${randomUUID()}`;
    const commitId = `cmt_${randomUUID()}`;
    const manifest = emptyManifest();
    const volume: Volume = {
      id: volumeId,
      tenantId: input.tenantId,
      defaultBranchId: branchId,
      createdAt: now,
    };
    const branch: BranchState = {
      id: branchId,
      tenantId: input.tenantId,
      volumeId,
      name: input.branchName,
      headCommitId: commitId,
      leaseCounter: 0,
      createdAt: now,
      updatedAt: now,
    };
    const head: VolumeCommit = {
      id: commitId,
      volumeId,
      branchId,
      treeHash: manifest.treeHash,
      manifest,
      mutationCount: 0,
      byteCount: 0,
      createdAt: now,
    };
    this.volumes.set(volumeKey, volume);
    this.branches.set(branchId, branch);
    this.commits.set(commitId, head);
    this.rememberManifestIndex(commitId, createManifestIndex(manifest));
    return { volume, branch, head };
  }

  async getStatus(input: VolumeStatusInput): Promise<CreateVolumeResult | null> {
    const volume = this.volumes.get(tenantVolumeKey(input.tenantId, input.volumeId));
    if (!volume) {
      return null;
    }
    const branch = this.getBranchByName(input.tenantId, input.volumeId, input.branchName);
    if (!branch) {
      return null;
    }
    const head = this.requireCommit(branch.headCommitId);
    const now = Date.now();
    return {
      volume,
      branch,
      head,
      activeLeases: [...this.leases.values()].filter(
        (lease) => lease.branchId === branch.id && !lease.releasedAt && lease.expiresAt > now
      ).length,
      activeDelegations: [...this.delegations.values()].filter(
        (delegation) =>
          delegation.branchId === branch.id &&
          !delegation.releasedAt &&
          !delegation.revokedAt &&
          delegation.expiresAt > now
      ).length,
    };
  }

  async getHead(input: VolumeStatusInput): Promise<VolumeHeadResult | null> {
    const volume = this.volumes.get(tenantVolumeKey(input.tenantId, input.volumeId));
    if (!volume) {
      return null;
    }
    const branch = this.getBranchByName(input.tenantId, input.volumeId, input.branchName);
    if (!branch) {
      return null;
    }
    const now = Date.now();
    return {
      volume,
      branch,
      head: toCommitSummary(this.requireCommit(branch.headCommitId)),
      activeLeases: [...this.leases.values()].filter(
        (lease) => lease.branchId === branch.id && !lease.releasedAt && lease.expiresAt > now
      ).length,
      activeDelegations: [...this.delegations.values()].filter(
        (delegation) =>
          delegation.branchId === branch.id &&
          !delegation.releasedAt &&
          !delegation.revokedAt &&
          delegation.expiresAt > now
      ).length,
    };
  }

  async waitForHead(input: WaitForHeadInput): Promise<VolumeHeadResult | null> {
    const immediate = await this.getHead(input);
    if (!immediate || immediate.branch.headCommitId !== input.afterCommitId) {
      return immediate;
    }
    const key = branchWaitKey(input.tenantId, input.volumeId, input.branchName);
    await new Promise<void>((resolve) => {
      const waiters =
        this.headWaiters.get(key) ??
        new Set<{ afterCommitId: string; resolve: () => void; timer: NodeJS.Timeout }>();
      let waiter: { afterCommitId: string; resolve: () => void; timer: NodeJS.Timeout };
      const timer = setTimeout(() => waiter.resolve(), Math.max(1, input.timeoutMs));
      waiter = {
        afterCommitId: input.afterCommitId,
        resolve: () => undefined,
        timer,
      };
      waiter.resolve = () => {
        clearTimeout(waiter.timer);
        waiters.delete(waiter);
        if (waiters.size === 0) {
          this.headWaiters.delete(key);
        }
        resolve();
      };
      waiters.add(waiter);
      this.headWaiters.set(key, waiters);
    });
    return this.getHead(input);
  }

  async getManifestDiff(input: VolumeManifestDiffInput): Promise<VolumeManifestDiffResult | null> {
    const volume = this.volumes.get(tenantVolumeKey(input.tenantId, input.volumeId));
    if (!volume) {
      return null;
    }
    const branch = this.getBranchByName(input.tenantId, input.volumeId, input.branchName);
    if (!branch) {
      return null;
    }
    const base = this.commits.get(input.baseCommitId);
    if (!base || base.branchId !== branch.id) {
      throw new MetadataConflictError("VOLUME_BASE_COMMIT_NOT_FOUND", "Base commit was not found on this branch.", 404);
    }
    const head = this.requireCommit(branch.headCommitId);
    const rootPath = normalizeVolumePath(input.rootPath);
    const baseManifest = projectManifest(base.manifest, rootPath);
    const targetManifest = projectManifest(head.manifest, rootPath);
    return {
      volume,
      branch,
      head: toCommitSummary(head),
      baseCommitId: base.id,
      rootPath,
      targetTreeHash: targetManifest.treeHash,
      targetEntryCount: targetManifest.entries.length,
      diff: diffManifests(baseManifest, targetManifest),
    };
  }

  async getCommit(commitId: string): Promise<VolumeCommit | null> {
    return this.commits.get(commitId) ?? null;
  }

  async getManifest(commitId: string): Promise<TreeManifest | null> {
    return this.commits.get(commitId)?.manifest ?? null;
  }

  async attachVolume(input: AttachVolumeInput): Promise<AttachVolumeResult> {
    const now = input.now ?? Date.now();
    const rootPath = normalizeVolumePath(input.rootPath);
    const branch = this.getBranchByName(input.tenantId, input.volumeId, input.branchName);
    if (!branch) {
      throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
    }
    if (input.mode === "write") {
      for (const lease of this.leases.values()) {
        const conflicts =
          lease.branchId === branch.id &&
          !lease.releasedAt &&
          lease.expiresAt > now &&
          (!input.shared || lease.exclusive);
        if (conflicts) {
          throw new MetadataConflictError(
            "VOLUME_WRITE_LEASE_BUSY",
            input.shared
              ? "Volume branch has an active exclusive writer."
              : "Volume branch already has an active writer.",
            423
          );
        }
      }
    }
    const head = this.requireCommit(branch.headCommitId);
    if (rootPath) {
      const rootEntry = head.manifest.entries.find((entry) => entry.path === rootPath);
      if (!rootEntry || rootEntry.kind !== "directory") {
        throw new MetadataConflictError(
          "VOLUME_ROOT_PATH_NOT_FOUND",
          "Attach rootPath must point to an existing directory.",
          404
        );
      }
    }
    const sessionId = `att_${randomUUID()}`;
    const session: AttachSession = {
      id: sessionId,
      volumeId: input.volumeId,
      branchId: branch.id,
      mode: input.mode,
      shared: input.shared,
      rootPath,
      baseCommitId: branch.headCommitId,
      attachedAt: now,
    };
    this.sessions.set(sessionId, session);
    let lease: VolumeLease | undefined;
    const delegations: PathDelegation[] = [];
    if (input.mode === "write") {
      branch.leaseCounter += 1;
      lease = {
        id: `lse_${randomUUID()}`,
        volumeId: input.volumeId,
        branchId: branch.id,
        attachSessionId: sessionId,
        holderId: input.holderId,
        fencingToken: branch.leaseCounter,
        exclusive: !input.shared,
        expiresAt: now + input.leaseTtlMs,
      };
      this.leases.set(lease.id, lease);
      if (!input.shared) {
        delegations.push(
          this.createDelegation({
            volumeId: input.volumeId,
            branchId: branch.id,
            attachSessionId: sessionId,
            leaseId: lease.id,
            holderId: input.holderId,
            path: rootPath,
            recursive: true,
            fencingToken: branch.leaseCounter,
            expiresAt: now + input.leaseTtlMs,
            createdAt: now,
          })
        );
      }
    }
    return {
      session: lease ? { ...session, lease } : session,
      branch,
      manifest: projectManifest(head.manifest, rootPath),
      delegations,
    };
  }

  async renewLease(input: RenewLeaseInput): Promise<VolumeLease> {
    const now = input.now ?? Date.now();
    const lease = this.leases.get(input.leaseId);
    if (!lease || lease.fencingToken !== input.fencingToken || lease.releasedAt || lease.expiresAt <= now) {
      throw new MetadataConflictError("VOLUME_LEASE_STALE", "Volume write lease is stale.", 409);
    }
    const next = { ...lease, expiresAt: now + input.leaseTtlMs };
    this.leases.set(input.leaseId, next);
    for (const [delegationId, delegation] of this.delegations) {
      if (delegation.leaseId === input.leaseId && !delegation.releasedAt && !delegation.revokedAt) {
        this.delegations.set(delegationId, {
          ...delegation,
          expiresAt: next.expiresAt,
        });
      }
    }
    return next;
  }

  async checkout(input: CheckoutInput): Promise<CheckoutResult> {
    const now = input.now ?? Date.now();
    const session = this.sessions.get(input.attachSessionId);
    if (!session || session.mode !== "write" || session.detachedAt) {
      throw new MetadataConflictError("VOLUME_ATTACH_SESSION_CLOSED", "Attach session is not writable.", 409);
    }
    const lease = this.assertWritableLease({
      leaseId: input.leaseId,
      attachSessionId: input.attachSessionId,
      fencingToken: input.fencingToken,
      now,
    });
    const requestedPath = input.path ?? "";
    const requestedRecursive = input.recursive ?? true;
    const pathValue = joinVolumePath(session.rootPath, requestedPath);
    if (session.shared && !pathValue && requestedRecursive) {
      throw new MetadataConflictError(
        "VOLUME_ROOT_DELEGATION_DENIED",
        "Shared sessions cannot claim ownership of the volume root.",
        409
      );
    }
    const active = this.activeDelegations(session.branchId, now);
    const conflicts = active.filter(
      (delegation) =>
        delegation.attachSessionId !== input.attachSessionId &&
        pathDelegationsOverlap(delegation, { path: pathValue, recursive: requestedRecursive })
    );
    if (conflicts.length && !input.force) {
      throw new MetadataConflictError(
        "VOLUME_DELEGATION_BUSY",
        `Path is already checked out: ${pathValue || "/"}.`,
        423
      );
    }
    const revoked: PathDelegation[] = [];
    for (const conflict of conflicts) {
      const next = { ...conflict, revokedAt: conflict.revokedAt ?? now };
      this.delegations.set(conflict.id, next);
      revoked.push(stripLeaseId(next));
    }
    const existingOwned = active.find(
      (delegation) =>
        delegation.attachSessionId === input.attachSessionId &&
        delegation.path === pathValue &&
        delegation.recursive === requestedRecursive
    );
    if (existingOwned) {
      return { delegation: stripLeaseId(existingOwned), revoked };
    }
    const delegation = this.createDelegation({
      volumeId: session.volumeId,
      branchId: session.branchId,
      attachSessionId: input.attachSessionId,
      leaseId: lease.id,
      holderId: lease.holderId,
      path: pathValue,
      recursive: requestedRecursive,
      fencingToken: lease.fencingToken,
      expiresAt: lease.expiresAt,
      createdAt: now,
    });
    return { delegation, revoked };
  }

  async checkin(input: CheckinInput): Promise<CheckinResult> {
    const now = input.now ?? Date.now();
    const session = this.sessions.get(input.attachSessionId);
    if (!session) {
      throw new MetadataConflictError("VOLUME_ATTACH_SESSION_NOT_FOUND", "Attach session not found.", 404);
    }
    const pathValue =
      input.path === undefined ? undefined : joinVolumePath(session.rootPath, input.path);
    const released: PathDelegation[] = [];
    for (const [delegationId, delegation] of this.delegations) {
      if (
        delegation.attachSessionId === input.attachSessionId &&
        !delegation.releasedAt &&
        !delegation.revokedAt &&
        (!input.delegationId || delegation.id === input.delegationId) &&
        (pathValue === undefined || delegation.path === pathValue)
      ) {
        const next = { ...delegation, releasedAt: now };
        this.delegations.set(delegationId, next);
        released.push(stripLeaseId(next));
      }
    }
    return { released };
  }

  async listDelegations(input: ListDelegationsInput): Promise<PathDelegation[]> {
    const now = input.now ?? Date.now();
    let branchId = input.branchId;
    if (!branchId && input.volumeId && input.branchName) {
      branchId = this.getBranchByName(
        input.tenantId,
        input.volumeId,
        input.branchName
      )?.id;
    }
    return [...this.delegations.values()]
      .filter(
        (delegation) =>
          this.branches.get(delegation.branchId)?.tenantId === input.tenantId &&
          (!branchId || delegation.branchId === branchId) &&
          (!input.attachSessionId || delegation.attachSessionId === input.attachSessionId) &&
          (input.includeReleased ||
            (!delegation.releasedAt && !delegation.revokedAt && delegation.expiresAt > now))
      )
      .map((delegation) => stripLeaseId(delegation))
      .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0) || left.createdAt - right.createdAt);
  }

  async commit(input: CommitVolumeInput): Promise<CommitVolumeResult> {
    const now = input.now ?? Date.now();
    const session = this.sessions.get(input.attachSessionId);
    if (!session || session.mode !== "write" || session.detachedAt) {
      throw new MetadataConflictError("VOLUME_ATTACH_SESSION_CLOSED", "Attach session is not writable.", 409);
    }
    this.assertWritableLease({
      leaseId: input.leaseId,
      attachSessionId: input.attachSessionId,
      fencingToken: input.fencingToken,
      now,
    });
    const branch = this.branches.get(session.branchId);
    if (!branch) {
      throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
    }
    const manifest = treeManifestSchema.parse(input.manifest);
    if (manifest.treeHash !== computeTreeHash(manifest.entries)) {
      throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Commit manifest tree hash is invalid.", 400);
    }
    const rootPath = normalizeVolumePath(session.rootPath);
    const baseCommit = this.commits.get(input.expectedHeadCommitId);
    if (!baseCommit || baseCommit.branchId !== session.branchId) {
      throw new MetadataConflictError("VOLUME_BASE_COMMIT_NOT_FOUND", "Commit base was not found on this branch.", 409);
    }
    const baseCommitIndex = this.manifestIndexForCommit(baseCommit);
    const baseProjected = rootPath ? projectManifest(baseCommit.manifest, rootPath) : baseCommitIndex.manifest;
    const baseProjectedIndex = rootPath ? createManifestIndex(baseProjected) : baseCommitIndex;
    const manifestIndex = createManifestIndex(manifest);
    const requestedDiff = diffManifestIndexes(baseProjectedIndex, manifestIndex);
    if (session.shared) {
      this.assertDelegationsCoverMutation({
        branchId: session.branchId,
        attachSessionId: input.attachSessionId,
        mutationPaths: collectMutationPaths(requestedDiff, rootPath),
        now,
      });
    }
    let parentCommitId = branch.headCommitId;
    let manifestToCommit: TreeManifest;
    let manifestToCommitIndex = manifestIndex;
    let mergedFromHeadCommitId: string | undefined;
    let parentManifestIndex = baseCommitIndex;
    if (branch.headCommitId === input.expectedHeadCommitId) {
      if (rootPath) {
        const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
        manifestToCommit = applied.manifest;
        manifestToCommitIndex = applied.index;
      } else {
        manifestToCommit = manifest;
      }
    } else {
      if (!session.shared) {
        throw new MetadataConflictError("VOLUME_HEAD_CHANGED", "Volume branch head changed.", 409);
      }
      const currentHead = this.requireCommit(branch.headCommitId);
      const currentHeadIndex = this.manifestIndexForCommit(currentHead);
      const currentDiff = diffManifestIndexes(
        baseProjectedIndex,
        rootPath
          ? createManifestIndex(projectManifest(currentHead.manifest, rootPath))
          : currentHeadIndex
      );
      if (diffHasPathConflict(requestedDiff, currentDiff)) {
        throw new MetadataConflictError(
          "VOLUME_MERGE_CONFLICT",
          "Shared writer changes conflict with a newer committed head.",
          409
        );
      }
      parentManifestIndex = currentHeadIndex;
      const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
      manifestToCommit = applied.manifest;
      manifestToCommitIndex = applied.index;
      parentCommitId = currentHead.id;
      mergedFromHeadCommitId = currentHead.id;
    }
    if (manifestToCommit.treeHash !== manifestToCommitIndex.manifest.treeHash) {
      throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Merged manifest tree hash is invalid.", 500);
    }
    const commit: VolumeCommit = {
      id: `cmt_${randomUUID()}`,
      volumeId: session.volumeId,
      branchId: session.branchId,
      parentCommitId,
      treeHash: manifestToCommit.treeHash,
      manifest: manifestToCommit,
      mutationCount: requestedDiff.mutationCount,
      byteCount: requestedDiff.byteCount,
      createdByAttachSessionId: input.attachSessionId,
      createdAt: now,
    };
    this.commits.set(commit.id, commit);
    this.recordBlobRefs(branch.tenantId, commit.manifest);
    this.rememberManifestIndex(commit.id, manifestToCommitIndex);
    branch.headCommitId = commit.id;
    branch.updatedAt = now;
    this.notifyHeadWaiters(branch, commit.id);
    return Object.assign(
      { commit, branch },
      mergedFromHeadCommitId ? { mergedFromHeadCommitId } : {}
    );
  }

  async commitSummary(input: CommitVolumeInput): Promise<CommitVolumeSummaryResult> {
    const result = await this.commit(input);
    return Object.assign(
      { commit: toCommitSummary(result.commit), branch: result.branch },
      result.mergedFromHeadCommitId ? { mergedFromHeadCommitId: result.mergedFromHeadCommitId } : {}
    );
  }

  async commitDeltaSummary(input: CommitVolumeDeltaInput): Promise<CommitVolumeSummaryResult> {
    const now = input.now ?? Date.now();
    const session = this.sessions.get(input.attachSessionId);
    if (!session || session.mode !== "write" || session.detachedAt) {
      throw new MetadataConflictError("VOLUME_ATTACH_SESSION_CLOSED", "Attach session is not writable.", 409);
    }
    this.assertWritableLease({
      leaseId: input.leaseId,
      attachSessionId: input.attachSessionId,
      fencingToken: input.fencingToken,
      now,
    });
    const branch = this.branches.get(session.branchId);
    if (!branch) {
      throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
    }
    const parsedDiff = treeManifestDiffSchema.parse(input.diff);
    assertManifestDiffShape(parsedDiff);
    const rootPath = normalizeVolumePath(session.rootPath);
    const baseCommit = this.commits.get(input.expectedHeadCommitId);
    if (!baseCommit || baseCommit.branchId !== session.branchId) {
      throw new MetadataConflictError("VOLUME_BASE_COMMIT_NOT_FOUND", "Commit base was not found on this branch.", 409);
    }
    const baseCommitIndex = this.manifestIndexForCommit(baseCommit);
    const baseProjected = rootPath ? projectManifest(baseCommit.manifest, rootPath) : baseCommitIndex.manifest;
    const baseProjectedIndex = rootPath ? createManifestIndex(baseProjected) : baseCommitIndex;
    const requestedProjected = applyManifestDiffIndexed(baseProjectedIndex, parsedDiff);
    const requestedProjectedManifest = requestedProjected.manifest;
    if (requestedProjectedManifest.treeHash !== input.targetTreeHash) {
      throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Commit delta target tree hash is invalid.", 400);
    }
    const requestedDiff = canonicalizeManifestDiff(baseProjectedIndex, parsedDiff);
    assertManifestDiffShape(requestedDiff);
    if (
      requestedDiff.mutationCount !== parsedDiff.mutationCount ||
      requestedDiff.byteCount !== parsedDiff.byteCount
    ) {
      throw new MetadataConflictError("VOLUME_COMMIT_DELTA_MISMATCH", "Commit delta does not match its base.", 400);
    }
    if (session.shared) {
      this.assertDelegationsCoverMutation({
        branchId: session.branchId,
        attachSessionId: input.attachSessionId,
        mutationPaths: collectMutationPaths(requestedDiff, rootPath),
        now,
      });
    }
    let parentCommitId = branch.headCommitId;
    let manifestToCommit: TreeManifest;
    let manifestToCommitIndex = requestedProjected.index;
    let mergedFromHeadCommitId: string | undefined;
    let parentManifestIndex = baseCommitIndex;
    if (branch.headCommitId === input.expectedHeadCommitId) {
      if (rootPath) {
        const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
        manifestToCommit = applied.manifest;
        manifestToCommitIndex = applied.index;
      } else {
        manifestToCommit = requestedProjectedManifest;
      }
    } else {
      if (!session.shared) {
        throw new MetadataConflictError("VOLUME_HEAD_CHANGED", "Volume branch head changed.", 409);
      }
      const currentHead = this.requireCommit(branch.headCommitId);
      const currentHeadIndex = this.manifestIndexForCommit(currentHead);
      const currentDiff = diffManifestIndexes(
        baseProjectedIndex,
        rootPath
          ? createManifestIndex(projectManifest(currentHead.manifest, rootPath))
          : currentHeadIndex
      );
      if (diffHasPathConflict(requestedDiff, currentDiff)) {
        throw new MetadataConflictError(
          "VOLUME_MERGE_CONFLICT",
          "Shared writer changes conflict with a newer committed head.",
          409
        );
      }
      parentManifestIndex = currentHeadIndex;
      const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
      manifestToCommit = applied.manifest;
      manifestToCommitIndex = applied.index;
      parentCommitId = currentHead.id;
      mergedFromHeadCommitId = currentHead.id;
    }
    if (manifestToCommit.treeHash !== manifestToCommitIndex.manifest.treeHash) {
      throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Merged manifest tree hash is invalid.", 500);
    }
    const commit: VolumeCommitSummary = {
      id: `cmt_${randomUUID()}`,
      volumeId: session.volumeId,
      branchId: session.branchId,
      parentCommitId,
      treeHash: manifestToCommit.treeHash,
      mutationCount: requestedDiff.mutationCount,
      byteCount: requestedDiff.byteCount,
      createdByAttachSessionId: input.attachSessionId,
      createdAt: now,
    };
    this.commits.set(commit.id, { ...commit, manifest: manifestToCommit });
    this.recordBlobRefs(branch.tenantId, manifestToCommit);
    this.rememberManifestIndex(commit.id, manifestToCommitIndex);
    branch.headCommitId = commit.id;
    branch.updatedAt = now;
    this.notifyHeadWaiters(branch, commit.id);
    return Object.assign(
      { commit, branch },
      mergedFromHeadCommitId ? { mergedFromHeadCommitId } : {}
    );
  }

  async detach(input: DetachVolumeInput): Promise<AttachSession> {
    const now = input.now ?? Date.now();
    const session = this.sessions.get(input.attachSessionId);
    if (!session) {
      throw new MetadataConflictError("VOLUME_ATTACH_SESSION_NOT_FOUND", "Attach session not found.", 404);
    }
    if (input.releaseLease) {
      for (const [leaseId, lease] of this.leases) {
        if (lease.attachSessionId === input.attachSessionId && !lease.releasedAt) {
          this.leases.set(leaseId, { ...lease, releasedAt: now });
        }
      }
      for (const [delegationId, delegation] of this.delegations) {
        if (
          delegation.attachSessionId === input.attachSessionId &&
          !delegation.releasedAt &&
          !delegation.revokedAt
        ) {
          this.delegations.set(delegationId, { ...delegation, releasedAt: now });
        }
      }
    }
    const next = { ...session, detachedAt: session.detachedAt ?? now };
    this.sessions.set(input.attachSessionId, next);
    return next;
  }

  async snapshot(input: SnapshotInput): Promise<VolumeSnapshot> {
    const now = input.now ?? Date.now();
    const branch = this.getBranchByName(input.tenantId, input.volumeId, input.branchName);
    if (!branch) {
      throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
    }
    const snapshot: VolumeSnapshot = {
      id: input.snapshotId ?? `snp_${randomUUID()}`,
      volumeId: input.volumeId,
      branchId: branch.id,
      commitId: branch.headCommitId,
      name: input.name,
      createdAt: now,
    };
    this.snapshots.set(snapshot.id, snapshot);
    return snapshot;
  }

  async listSnapshots(input: ListSnapshotsInput): Promise<VolumeSnapshot[]> {
    const branch = input.branchName
      ? this.getBranchByName(input.tenantId, input.volumeId, input.branchName)
      : null;
    if (input.branchName && !branch) {
      throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
    }
    return [...this.snapshots.values()]
      .filter(
        (snapshot) =>
          snapshot.volumeId === input.volumeId &&
          this.branches.get(snapshot.branchId)?.tenantId === input.tenantId &&
          (!branch || snapshot.branchId === branch.id)
      )
      .sort((left, right) => left.createdAt - right.createdAt || (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  }

  /**
   * Mirror of the Postgres branch-point commit: a new branch/fork starts with its
   * own commit ON the new branch (parent = the fork-point commit, same tree), so the
   * branch's head_commit_id always carries that branch's branch_id.
   */
  private createBranchPointCommit(
    volumeId: string,
    branchId: string,
    fromCommitId: string,
    now: number
  ): VolumeCommit {
    const source = this.requireCommit(fromCommitId);
    const commit: VolumeCommit = {
      id: `cmt_${randomUUID()}`,
      volumeId,
      branchId,
      parentCommitId: fromCommitId,
      treeHash: source.treeHash,
      manifest: source.manifest,
      mutationCount: 0,
      byteCount: 0,
      createdAt: now,
    };
    this.commits.set(commit.id, commit);
    this.rememberManifestIndex(commit.id, createManifestIndex(commit.manifest));
    return commit;
  }

  async createBranch(input: CreateBranchInput): Promise<{ branch: VolumeBranch; head: VolumeCommit }> {
    const now = input.now ?? Date.now();
    const sourceBranch = this.getBranchByName(
      input.tenantId,
      input.volumeId,
      input.fromBranch ?? "main"
    );
    if (!sourceBranch) {
      throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Source branch not found.", 404);
    }
    const snapshot = [...this.snapshots.values()].find(
      (candidate) =>
        candidate.volumeId === input.volumeId &&
        candidate.branchId === sourceBranch.id &&
        ((input.fromSnapshotId && candidate.id === input.fromSnapshotId) ||
          (input.fromSnapshotName && candidate.name === input.fromSnapshotName))
    );
    if (!snapshot) {
      throw new MetadataConflictError("VOLUME_SNAPSHOT_NOT_FOUND", "Snapshot not found.", 404);
    }
    const branchId = `br_${randomUUID()}`;
    const branchPoint = this.createBranchPointCommit(input.volumeId, branchId, snapshot.commitId, now);
    const branch: BranchState = {
      id: branchId,
      tenantId: input.tenantId,
      volumeId: input.volumeId,
      name: input.branchName,
      parentBranchId: sourceBranch.id,
      forkedFromSnapshotId: snapshot.id,
      headCommitId: branchPoint.id,
      leaseCounter: 0,
      createdAt: now,
      updatedAt: now,
    };
    this.branches.set(branchId, branch);
    return { branch, head: branchPoint };
  }

  async listBranches(input: ListBranchesInput): Promise<VolumeBranch[]> {
    return [...this.branches.values()]
      .filter(
        (branch) =>
          branch.tenantId === input.tenantId && branch.volumeId === input.volumeId
      )
      .sort((left, right) => left.createdAt - right.createdAt || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  }

  async listVolumes(input: ListVolumesInput): Promise<VolumeListEntry[]> {
    const limit = Math.max(1, Math.trunc(input.limit));
    const volumes = [...this.volumes.values()]
      .filter(
        (volume) =>
          volume.tenantId === input.tenantId &&
          !this.retired.has(tenantVolumeKey(input.tenantId, volume.id))
      )
      .sort((left, right) => left.createdAt - right.createdAt || (left.id < right.id ? -1 : left.id > right.id ? 1 : 0))
      .slice(0, limit);
    return Promise.all(
      volumes.map(async (volume) => ({
        volume,
        branches: (
          await this.listBranches({ tenantId: input.tenantId, volumeId: volume.id })
        ).map((branch) => ({
          name: branch.name,
          headCommitId: branch.headCommitId,
        })),
      }))
    );
  }

  async listCommitHistory(input: ListCommitHistoryInput): Promise<VolumeCommitSummary[] | null> {
    if (!this.volumes.has(tenantVolumeKey(input.tenantId, input.volumeId))) {
      return null;
    }
    const branch = this.getBranchByName(input.tenantId, input.volumeId, input.branchName);
    if (!branch) {
      return null;
    }
    const limit = Math.max(1, Math.trunc(input.limit));
    const history: VolumeCommitSummary[] = [];
    let commitId: string | undefined = branch.headCommitId;
    while (commitId && history.length < limit) {
      const commit = this.commits.get(commitId);
      if (!commit) {
        break;
      }
      history.push(toCommitSummary(commit));
      commitId = commit.parentCommitId;
    }
    return history;
  }

  async forkSnapshot(input: ForkSnapshotInput): Promise<CreateVolumeResult> {
    const now = input.now ?? Date.now();
    const snapshot = this.snapshots.get(input.snapshotId);
    if (!snapshot) {
      throw new MetadataConflictError("VOLUME_SNAPSHOT_NOT_FOUND", "Snapshot not found.", 404);
    }
    const volumeId = input.volumeId ?? `vol_${randomUUID()}`;
    const volumeKey = tenantVolumeKey(input.tenantId, volumeId);
    if (this.volumes.has(volumeKey)) {
      throw new MetadataConflictError("VOLUME_ALREADY_EXISTS", "Volume already exists.", 409);
    }
    const branchId = `br_${randomUUID()}`;
    const volume: Volume = {
      id: volumeId,
      tenantId: input.tenantId,
      defaultBranchId: branchId,
      createdAt: now,
    };
    const branchPoint = this.createBranchPointCommit(volumeId, branchId, snapshot.commitId, now);
    const branch: BranchState = {
      id: branchId,
      tenantId: input.tenantId,
      volumeId,
      name: input.branchName,
      headCommitId: branchPoint.id,
      leaseCounter: 0,
      createdAt: now,
      updatedAt: now,
    };
    this.volumes.set(volumeKey, volume);
    this.branches.set(branchId, branch);
    this.recordBlobRefs(input.tenantId, branchPoint.manifest);
    return { volume, branch, head: branchPoint };
  }

  async recordBlobs(blobs: Array<{ digest: string; size: number; storageKey?: string }>): Promise<void> {
    for (const blob of blobs) {
      const existing = this.blobs.get(blob.digest);
      // created_at is the first-seen time (kept on re-record, like Postgres ON CONFLICT).
      this.blobs.set(blob.digest, { ...blob, createdAt: existing?.createdAt ?? Date.now() });
    }
  }

  async hasBlobs(digests: string[]): Promise<Set<string>> {
    return new Set([...new Set(digests)].filter((digest) => this.blobs.has(digest)));
  }

  async listCommits(): Promise<VolumeCommit[]> {
    return [...this.commits.values()].sort((left, right) => left.createdAt - right.createdAt || (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  }

  async listBlobRecords(): Promise<Array<{ digest: string; size: number; storageKey?: string }>> {
    return [...this.blobs.values()]
      .map(({ digest, size, storageKey }) => ({ digest, size, ...(storageKey ? { storageKey } : {}) }))
      .sort((left, right) => (left.digest < right.digest ? -1 : left.digest > right.digest ? 1 : 0));
  }

  async deleteBlobRecord(digest: string): Promise<void> {
    this.blobs.delete(digest);
  }

  async referencedDigests(): Promise<Set<string>> {
    const digests = new Set<string>();
    for (const commit of this.commits.values()) {
      for (const digest of manifestDigests(commit.manifest)) {
        digests.add(digest);
      }
    }
    return digests;
  }

  // --- Multi-tenant isolation ---

  private recordBlobRefs(tenantId: string, manifest: TreeManifest): void {
    for (const digest of manifestDigests(manifest)) {
      this.blobRefs.add(`${tenantId}\0${digest}`);
    }
  }

  async createTenant(tenantId: string): Promise<void> {
    this.tenants.add(tenantId);
  }

  async createTenantToken(input: { tenantId: string; tokenHash: string; label?: string }): Promise<void> {
    this.tenants.add(input.tenantId);
    this.tenantTokens.set(input.tokenHash, input.tenantId);
  }

  async resolveTenantToken(tokenHash: string): Promise<{ tenantId: string } | null> {
    const tenantId = this.tenantTokens.get(tokenHash);
    return tenantId ? { tenantId } : null;
  }

  async resolveRuntimeReadCredential(credentialHash: string): Promise<{
    tenantId: string;
    volumeId: string;
    branchName: string;
    readOnly: true;
  } | null> {
    const pinned = this.runtimeReadCredentials.get(credentialHash);
    return pinned ? { ...pinned, readOnly: true } : null;
  }

  // retireVolume mirrors the Postgres atomic conditional flip: null answers
  // mean unknown, foreign, or already retired (the route's non-enumerating
  // 404). Nothing is deleted; the resolvers below simply stop seeing the
  // volume and everything that belongs to it.
  async retireVolume(input: {
    volumeId: string;
    tenantId: string;
    now?: number;
  }): Promise<{ volumeId: string; retiredAtMs: number } | null> {
    const volumeKey = tenantVolumeKey(input.tenantId, input.volumeId);
    const volume = this.volumes.get(volumeKey);
    if (!volume || this.retired.has(volumeKey)) {
      return null;
    }
    const retiredAtMs = input.now ?? Date.now();
    this.retired.set(volumeKey, retiredAtMs);
    return { volumeId: input.volumeId, retiredAtMs };
  }

  // The ownership resolvers treat a retired volume — and its sessions,
  // leases, snapshots, and commits — as absent, exactly like Postgres'
  // retired_at IS NULL predicates. This is the fencing point every
  // per-volume route relies on after retirement.
  private liveBranchTenant(branchId: string): string | null {
    const branch = this.branches.get(branchId);
    if (!branch) {
      return null;
    }
    const key = tenantVolumeKey(branch.tenantId, branch.volumeId);
    return this.retired.has(key) ? null : branch.tenantId;
  }

  async tenantOwnsVolume(input: {
    tenantId: string;
    volumeId: string;
    includeRetired?: boolean;
  }): Promise<boolean> {
    const key = tenantVolumeKey(input.tenantId, input.volumeId);
    return this.volumes.has(key) && (Boolean(input.includeRetired) || !this.retired.has(key));
  }

  async sessionTenant(sessionId: string): Promise<string | null> {
    const session = this.sessions.get(sessionId);
    return session ? this.liveBranchTenant(session.branchId) : null;
  }

  async leaseTenant(leaseId: string): Promise<string | null> {
    const lease = this.leases.get(leaseId);
    return lease ? this.liveBranchTenant(lease.branchId) : null;
  }

  async sessionVolume(sessionId: string): Promise<string | null> {
    return this.sessions.get(sessionId)?.volumeId ?? null;
  }

  async leaseVolume(leaseId: string): Promise<string | null> {
    return this.leases.get(leaseId)?.volumeId ?? null;
  }

  async snapshotTenant(snapshotId: string): Promise<string | null> {
    const snapshot = this.snapshots.get(snapshotId);
    return snapshot ? this.liveBranchTenant(snapshot.branchId) : null;
  }

  async commitTenant(commitId: string): Promise<string | null> {
    const commit = this.commits.get(commitId);
    return commit ? this.liveBranchTenant(commit.branchId) : null;
  }

  async tenantReferencesBlob(tenantId: string, digest: string): Promise<boolean> {
    return this.blobRefs.has(`${tenantId}\0${digest}`);
  }

  async tenantReferencesBlobs(tenantId: string, digests: string[]): Promise<Set<string>> {
    const referenced = new Set<string>();
    for (const digest of digests) {
      if (this.blobRefs.has(`${tenantId}\0${digest}`)) {
        referenced.add(digest);
      }
    }
    return referenced;
  }

  async addBlobRefs(tenantId: string, digests: string[]): Promise<void> {
    for (const digest of digests) {
      if (digest) {
        this.blobRefs.add(`${tenantId}\0${digest}`);
      }
    }
  }

  // Mirror of the Postgres batch probe filter: only this tenant's refs are
  // consulted (never this.blobs), so globally-stored-but-unreferenced digests are
  // still reported missing (proof-of-possession preserved).
  async filterUnreferencedBlobs(tenantId: string, digests: string[]): Promise<string[]> {
    const unique = [...new Set(digests)].filter((digest) => digest);
    return unique.filter((digest) => !this.blobRefs.has(`${tenantId}\0${digest}`));
  }

  async listBlobsCreatedBefore(
    cutoffMs: number
  ): Promise<Array<{ digest: string; size: number; storageKey?: string; createdAt: number }>> {
    return [...this.blobs.values()]
      .filter((blob) => blob.createdAt < cutoffMs)
      .map(({ digest, size, storageKey, createdAt }) => ({
        digest,
        size,
        createdAt,
        ...(storageKey ? { storageKey } : {}),
      }))
      .sort((left, right) => (left.digest < right.digest ? -1 : left.digest > right.digest ? 1 : 0));
  }

  private assertWritableLease(input: {
    leaseId: string;
    attachSessionId: string;
    fencingToken: number;
    now: number;
  }): VolumeLease {
    const lease = this.leases.get(input.leaseId);
    if (
      !lease ||
      lease.attachSessionId !== input.attachSessionId ||
      lease.fencingToken !== input.fencingToken ||
      lease.releasedAt ||
      lease.expiresAt <= input.now
    ) {
      throw new MetadataConflictError("VOLUME_LEASE_STALE", "Volume write lease is stale.", 409);
    }
    return lease;
  }

  private assertDelegationsCoverMutation(input: {
    branchId: string;
    attachSessionId: string;
    mutationPaths: Array<{ path: string; recursive: boolean }>;
    now: number;
  }): void {
    const active = this.activeDelegations(input.branchId, input.now).filter(
      (delegation) => delegation.attachSessionId === input.attachSessionId
    );
    const uncovered = input.mutationPaths.find((mutation) => {
      const pathValue = normalizeVolumePath(mutation.path);
      return !active.some((delegation) => {
        if (mutation.recursive && !delegation.recursive) {
          return false;
        }
        return (
          delegation.path === pathValue ||
          (delegation.recursive && isEqualOrDescendantPath(pathValue, delegation.path))
        );
      });
    });
    if (uncovered) {
      throw new MetadataConflictError(
        "VOLUME_DELEGATION_REQUIRED",
        `No active checkout covers ${uncovered.path || "/"}.`,
        409
      );
    }
  }

  private activeDelegations(
    branchId: string,
    now: number
  ): Array<PathDelegation & { leaseId: string }> {
    return [...this.delegations.values()].filter(
      (delegation) =>
        delegation.branchId === branchId &&
        !delegation.releasedAt &&
        !delegation.revokedAt &&
        delegation.expiresAt > now
    );
  }

  private createDelegation(input: {
    volumeId: string;
    branchId: string;
    attachSessionId: string;
    leaseId: string;
    holderId: string;
    path: string;
    recursive: boolean;
    fencingToken: number;
    expiresAt: number;
    createdAt: number;
  }): PathDelegation {
    const delegation: PathDelegation & { leaseId: string } = {
      id: `dlg_${randomUUID()}`,
      volumeId: input.volumeId,
      branchId: input.branchId,
      attachSessionId: input.attachSessionId,
      leaseId: input.leaseId,
      holderId: input.holderId,
      path: normalizeVolumePath(input.path),
      recursive: input.recursive,
      fencingToken: input.fencingToken,
      expiresAt: input.expiresAt,
      createdAt: input.createdAt,
    };
    this.delegations.set(delegation.id, delegation);
    return stripLeaseId(delegation);
  }

  private getBranchByName(
    tenantId: string,
    volumeId: string,
    branchName: string
  ): BranchState | null {
    for (const branch of this.branches.values()) {
      if (
        branch.tenantId === tenantId &&
        branch.volumeId === volumeId &&
        branch.name === branchName
      ) {
        return branch;
      }
    }
    return null;
  }

  private notifyHeadWaiters(branch: VolumeBranch, headCommitId: string): void {
    const branchState = this.branches.get(branch.id);
    if (!branchState) {
      return;
    }
    const waiters = this.headWaiters.get(
      branchWaitKey(branchState.tenantId, branch.volumeId, branch.name)
    );
    if (!waiters) {
      return;
    }
    for (const waiter of [...waiters]) {
      if (waiter.afterCommitId !== headCommitId) {
        waiter.resolve();
      }
    }
  }

  private requireCommit(commitId: string): VolumeCommit {
    const commit = this.commits.get(commitId);
    if (!commit) {
      throw new Error(`Commit not found: ${commitId}`);
    }
    return commit;
  }
}

function stripLeaseId(delegation: PathDelegation & { leaseId: string }): PathDelegation {
  const { leaseId: _leaseId, ...rest } = delegation;
  return rest;
}

function tenantVolumeKey(tenantId: string, volumeId: string): string {
  return `${tenantId}\0${volumeId}`;
}

function branchWaitKey(tenantId: string, volumeId: string, branchName: string): string {
  return `${tenantId}\0${volumeId}\0${branchName}`;
}

function assertManifestDiffShape(diff: TreeManifestDiff): void {
  const actualMutationCount = diff.added.length + diff.changed.length + diff.removed.length;
  if (diff.mutationCount !== actualMutationCount) {
    throw new MetadataConflictError(
      "VOLUME_COMMIT_DELTA_MISMATCH",
      "Commit delta mutation count does not match changed entries.",
      400
    );
  }
}

export class FaultInjectingMetadataRepository implements MetadataRepository {
  failNextCommit = false;

  constructor(private readonly inner: MetadataRepository) {}

  createVolume(input: CreateVolumeInput): Promise<CreateVolumeResult> {
    return this.inner.createVolume(input);
  }
  getStatus(input: VolumeStatusInput): Promise<CreateVolumeResult | null> {
    return this.inner.getStatus(input);
  }
  getHead(input: VolumeStatusInput): Promise<VolumeHeadResult | null> {
    return this.inner.getHead(input);
  }
  waitForHead(input: WaitForHeadInput): Promise<VolumeHeadResult | null> {
    return this.inner.waitForHead?.(input) ?? this.inner.getHead(input);
  }
  getManifestDiff(input: VolumeManifestDiffInput): Promise<VolumeManifestDiffResult | null> {
    return this.inner.getManifestDiff(input);
  }
  getCommit(commitId: string): Promise<VolumeCommit | null> {
    return this.inner.getCommit(commitId);
  }
  getManifest(commitId: string): Promise<TreeManifest | null> {
    return this.inner.getManifest(commitId);
  }
  attachVolume(input: AttachVolumeInput): Promise<AttachVolumeResult> {
    return this.inner.attachVolume(input);
  }
  renewLease(input: RenewLeaseInput): Promise<VolumeLease> {
    return this.inner.renewLease(input);
  }
  checkout(input: CheckoutInput): Promise<CheckoutResult> {
    return this.inner.checkout(input);
  }
  checkin(input: CheckinInput): Promise<CheckinResult> {
    return this.inner.checkin(input);
  }
  listDelegations(input: ListDelegationsInput): Promise<PathDelegation[]> {
    return this.inner.listDelegations(input);
  }
  async commit(input: CommitVolumeInput): Promise<CommitVolumeResult> {
    if (this.failNextCommit) {
      this.failNextCommit = false;
      throw new Error("Injected metadata commit failure.");
    }
    return this.inner.commit(input);
  }
  async commitSummary(input: CommitVolumeInput): Promise<CommitVolumeSummaryResult> {
    if (this.failNextCommit) {
      this.failNextCommit = false;
      throw new Error("Injected metadata commit failure.");
    }
    return this.inner.commitSummary(input);
  }
  async commitDeltaSummary(input: CommitVolumeDeltaInput): Promise<CommitVolumeSummaryResult> {
    if (this.failNextCommit) {
      this.failNextCommit = false;
      throw new Error("Injected metadata commit failure.");
    }
    return this.inner.commitDeltaSummary(input);
  }
  detach(input: DetachVolumeInput): Promise<AttachSession> {
    return this.inner.detach(input);
  }
  snapshot(input: SnapshotInput): Promise<VolumeSnapshot> {
    return this.inner.snapshot(input);
  }
  listSnapshots(input: ListSnapshotsInput): Promise<VolumeSnapshot[]> {
    return this.inner.listSnapshots(input);
  }
  createBranch(input: CreateBranchInput): Promise<{ branch: VolumeBranch; head: VolumeCommit }> {
    return this.inner.createBranch(input);
  }
  listBranches(input: ListBranchesInput): Promise<VolumeBranch[]> {
    return this.inner.listBranches(input);
  }
  listVolumes(input: ListVolumesInput): Promise<VolumeListEntry[]> {
    return this.inner.listVolumes(input);
  }
  retireVolume(input: {
    volumeId: string;
    tenantId: string;
    now?: number;
  }): Promise<{ volumeId: string; retiredAtMs: number } | null> {
    return this.inner.retireVolume?.(input) ?? Promise.resolve(null);
  }
  listCommitHistory(input: ListCommitHistoryInput): Promise<VolumeCommitSummary[] | null> {
    return this.inner.listCommitHistory(input);
  }
  forkSnapshot(input: ForkSnapshotInput): Promise<CreateVolumeResult> {
    return this.inner.forkSnapshot(input);
  }
  recordBlobs(blobs: Array<{ digest: string; size: number; storageKey?: string }>): Promise<void> {
    return this.inner.recordBlobs(blobs);
  }
  hasBlobs(digests: string[]): Promise<Set<string>> {
    return this.inner.hasBlobs?.(digests) ?? Promise.resolve(new Set());
  }
  listCommits(): Promise<VolumeCommit[]> {
    return this.inner.listCommits?.() ?? Promise.resolve([]);
  }
  listBlobRecords(): Promise<Array<{ digest: string; size: number; storageKey?: string }>> {
    return this.inner.listBlobRecords?.() ?? Promise.resolve([]);
  }
  deleteBlobRecord(digest: string): Promise<void> {
    return this.inner.deleteBlobRecord?.(digest) ?? Promise.resolve();
  }
  createTenant(tenantId: string): Promise<void> {
    return this.inner.createTenant(tenantId);
  }
  createTenantToken(input: { tenantId: string; tokenHash: string; label?: string }): Promise<void> {
    return this.inner.createTenantToken(input);
  }
  resolveTenantToken(tokenHash: string): Promise<{ tenantId: string } | null> {
    return this.inner.resolveTenantToken(tokenHash);
  }
  resolveRuntimeReadCredential(credentialHash: string): Promise<{
    tenantId: string;
    volumeId: string;
    branchName: string;
    readOnly: true;
  } | null> {
    return this.inner.resolveRuntimeReadCredential(credentialHash);
  }
  tenantOwnsVolume(input: {
    tenantId: string;
    volumeId: string;
    includeRetired?: boolean;
  }): Promise<boolean> {
    return this.inner.tenantOwnsVolume(input);
  }
  sessionTenant(sessionId: string): Promise<string | null> {
    return this.inner.sessionTenant(sessionId);
  }
  leaseTenant(leaseId: string): Promise<string | null> {
    return this.inner.leaseTenant(leaseId);
  }
  sessionVolume(sessionId: string): Promise<string | null> {
    return this.inner.sessionVolume(sessionId);
  }
  leaseVolume(leaseId: string): Promise<string | null> {
    return this.inner.leaseVolume(leaseId);
  }
  snapshotTenant(snapshotId: string): Promise<string | null> {
    return this.inner.snapshotTenant(snapshotId);
  }
  commitTenant(commitId: string): Promise<string | null> {
    return this.inner.commitTenant(commitId);
  }
  tenantReferencesBlob(tenantId: string, digest: string): Promise<boolean> {
    return this.inner.tenantReferencesBlob(tenantId, digest);
  }
  tenantReferencesBlobs(tenantId: string, digests: string[]): Promise<Set<string>> {
    return this.inner.tenantReferencesBlobs(tenantId, digests);
  }
  addBlobRefs(tenantId: string, digests: string[]): Promise<void> {
    return this.inner.addBlobRefs(tenantId, digests);
  }
  filterUnreferencedBlobs(tenantId: string, digests: string[]): Promise<string[]> {
    return this.inner.filterUnreferencedBlobs(tenantId, digests);
  }
}

function emptyManifest(): TreeManifest {
  const entries: TreeManifest["entries"] = [];
  return {
    version: protocolVersion,
    treeHash: computeTreeHash(entries),
    entries,
  };
}

function toCommitSummary(commit: VolumeCommit): VolumeCommitSummary {
  const { manifest: _manifest, ...summary } = commit;
  return summary;
}

function manifestDigests(manifest: TreeManifest): string[] {
  const out: string[] = [];
  for (const entry of manifest.entries) {
    if (entry.kind !== "file") {
      continue;
    }
    if (entry.chunks?.length) {
      for (const chunk of entry.chunks) {
        out.push(chunk.digest);
      }
    } else if (entry.blob) {
      out.push(entry.blob.digest);
    }
  }
  return out;
}
