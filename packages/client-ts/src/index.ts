import { sha256Buffer } from "@portablefs/core";
import {
  attachVolumeResponseSchema,
  checkinResponseSchema,
  checkoutResponseSchema,
  commitDeltaRequestSchema,
  commitResponseSchema,
  commitSummaryResponseSchema,
  createBranchResponseSchema,
  createVolumeResponseSchema,
  delegationsResponseSchema,
  detachResponseSchema,
  forkResponseSchema,
  grepResponseSchema,
  listBranchesResponseSchema,
  listSnapshotsResponseSchema,
  renewLeaseResponseSchema,
  snapshotResponseSchema,
  uploadBlobBatchAckResponseSchema,
  uploadBlobBatchResponseSchema,
  uploadBlobResponseSchema,
  volumeHeadResponseSchema,
  volumeManifestDiffResponseSchema,
  volumeWaitHeadResponseSchema,
  volumeStatusResponseSchema,
  type AttachVolumeRequest,
  type AttachVolumeResponse,
  type BlobDigest,
  type CheckinRequest,
  type CheckinResponse,
  type CheckoutRequest,
  type CheckoutResponse,
  type CommitDeltaRequest,
  type CommitRequest,
  type CommitResponse,
  type CommitSummaryResponse,
  type CreateBranchRequest,
  type CreateBranchResponse,
  type CreateVolumeRequest,
  type CreateVolumeResponse,
  type DelegationsResponse,
  type DetachResponse,
  type ForkRequest,
  type ForkResponse,
  type GrepRequest,
  type GrepResponse,
  type ListBranchesResponse,
  type ListSnapshotsResponse,
  type RenewLeaseResponse,
  type SnapshotRequest,
  type SnapshotResponse,
  type TreeManifest,
  type UploadBlobBatchAckResponse,
  type UploadBlobBatchResponse,
  type UploadBlobResponse,
  type VolumeHeadResponse,
  type VolumeManifestDiffResponse,
  type VolumeWaitHeadResponse,
  type VolumeStatusResponse,
} from "@portablefs/protocol";

export interface VolumeClientOptions {
  baseUrl: string;
  token?: string;
  fetchImpl?: typeof fetch;
}

/**
 * The named-snapshot release facts (`DELETE .../snapshots/:name`): the READY
 * cut ids whose label was cleared and how many snapshot consumers were
 * released with them. No protocol schema exists for this journal-era route;
 * the shape is validated structurally like `getManifest`.
 */
export interface DeleteSnapshotResponse {
  cutIds: string[];
  snapshotConsumersReleased: string;
}

export class VolumeClientError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "VolumeClientError";
    this.status = status;
    this.code = code;
  }
}

export class VolumeClient {
  private readonly baseUrl: string;
  private readonly token: string | undefined;
  private readonly fetchImpl: typeof fetch;

  constructor(options: VolumeClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async createVolume(input: CreateVolumeRequest): Promise<CreateVolumeResponse> {
    return createVolumeResponseSchema.parse(
      await this.requestJson("POST", "/v1/volumes", input)
    );
  }

  async status(volumeId: string, branch = "main"): Promise<VolumeStatusResponse> {
    return volumeStatusResponseSchema.parse(
      await this.requestJson(
        "GET",
        `/v1/volumes/${encodeURIComponent(volumeId)}/status?branch=${encodeURIComponent(branch)}`
      )
    );
  }

  async head(volumeId: string, branch = "main"): Promise<VolumeHeadResponse> {
    return volumeHeadResponseSchema.parse(
      await this.requestJson(
        "GET",
        `/v1/volumes/${encodeURIComponent(volumeId)}/head?branch=${encodeURIComponent(branch)}`
      )
    );
  }

  async waitHead(
    volumeId: string,
    input: {
      branch?: string;
      afterCommitId: string;
      timeoutMs?: number | undefined;
      signal?: AbortSignal | undefined;
    }
  ): Promise<VolumeWaitHeadResponse> {
    const params = new URLSearchParams({
      branch: input.branch ?? "main",
      afterCommitId: input.afterCommitId,
    });
    if (input.timeoutMs !== undefined) {
      params.set("timeoutMs", String(input.timeoutMs));
    }
    const init: RequestInit = {
      method: "GET",
      headers: this.headers(),
    };
    if (input.signal) {
      init.signal = input.signal;
    }
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/volumes/${encodeURIComponent(volumeId)}/wait-head?${params.toString()}`,
      init
    );
    return volumeWaitHeadResponseSchema.parse(await readResponse(response));
  }

  async manifestDiff(
    volumeId: string,
    input: { branch?: string; baseCommitId: string; rootPath?: string }
  ): Promise<VolumeManifestDiffResponse> {
    const params = new URLSearchParams({
      branch: input.branch ?? "main",
      baseCommitId: input.baseCommitId,
      rootPath: input.rootPath ?? "",
    });
    return volumeManifestDiffResponseSchema.parse(
      await this.requestJson(
        "GET",
        `/v1/volumes/${encodeURIComponent(volumeId)}/manifest-diff?${params.toString()}`
      )
    );
  }

  async attach(
    volumeId: string,
    input: AttachVolumeRequest
  ): Promise<AttachVolumeResponse> {
    return attachVolumeResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/volumes/${encodeURIComponent(volumeId)}/attach`,
        input
      )
    );
  }

  async uploadBlob(
    buffer: Buffer,
    options?: { digest?: BlobDigest }
  ): Promise<UploadBlobResponse> {
    const actualDigest = sha256Buffer(buffer);
    const digest = options?.digest ?? actualDigest;
    if (digest !== actualDigest) {
      throw new VolumeClientError(
        400,
        "VOLUME_BLOB_DIGEST_MISMATCH",
        `Prepared ${actualDigest}; expected ${digest}.`
      );
    }
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/blobs/${encodeURIComponent(digest)}`,
      {
        method: "PUT",
        headers: this.headers("application/octet-stream"),
        body: new Uint8Array(buffer),
      }
    );
    return uploadBlobResponseSchema.parse(await readResponse(response));
  }

  async uploadBlobs(
    blobs: Array<{ buffer: Buffer; digest?: BlobDigest }>,
    options?: { response?: "full" | "ack" }
  ): Promise<UploadBlobBatchResponse> {
    if (blobs.length === 0) {
      return { blobs: [] };
    }
    const prepared = blobs.map((blob) => {
      const actualDigest = sha256Buffer(blob.buffer);
      const digest = blob.digest ?? actualDigest;
      if (digest !== actualDigest) {
        throw new VolumeClientError(
          400,
          "VOLUME_BLOB_DIGEST_MISMATCH",
          `Prepared ${actualDigest}; expected ${digest}.`
        );
      }
      return { digest, buffer: blob.buffer };
    });
    const wantsAck = options?.response === "ack";
    const response = await this.fetchImpl(`${this.baseUrl}/v1/blobs/batch-binary${wantsAck ? "?response=ack" : ""}`, {
      method: "POST",
      headers: this.headers("application/vnd.portablefs.blob-batch.v1"),
      body: new Uint8Array(encodeBlobBatchBinary(prepared)),
    });
    if (response.status !== 404 && response.status !== 415) {
      const body = await readResponse(response);
      if (wantsAck) {
        return uploadBlobBatchResponseFromAckOrFull(body, prepared);
      }
      return uploadBlobBatchResponseSchema.parse(body);
    }
    const fallback = await this.requestJson("POST", `/v1/blobs/batch${wantsAck ? "?response=ack" : ""}`, {
        blobs: prepared.map((blob) => ({
          digest: blob.digest,
          bytesBase64: blob.buffer.toString("base64"),
        })),
    });
    if (wantsAck) {
      return uploadBlobBatchResponseFromAckOrFull(fallback, prepared);
    }
    return uploadBlobBatchResponseSchema.parse(fallback);
  }

  async downloadBlob(digest: BlobDigest): Promise<Buffer> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/blobs/${encodeURIComponent(digest)}`,
      {
        method: "GET",
        headers: this.headers(),
      }
    );
    if (!response.ok) {
      await throwClientError(response);
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    const actual = sha256Buffer(buffer);
    if (actual !== digest) {
      throw new VolumeClientError(502, "VOLUME_BLOB_DIGEST_MISMATCH", `Downloaded ${actual}; expected ${digest}.`);
    }
    return buffer;
  }

  async commit(
    attachSessionId: string,
    input: CommitRequest
  ): Promise<CommitResponse> {
    return commitResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/attach-sessions/${encodeURIComponent(attachSessionId)}/commit`,
        input
      )
    );
  }

  async commitSummary(
    attachSessionId: string,
    input: CommitRequest
  ): Promise<CommitSummaryResponse> {
    return commitSummaryResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/attach-sessions/${encodeURIComponent(attachSessionId)}/commit-summary`,
        input
      )
    );
  }

  async commitDeltaSummary(
    attachSessionId: string,
    input: CommitDeltaRequest
  ): Promise<CommitSummaryResponse> {
    return commitSummaryResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/attach-sessions/${encodeURIComponent(attachSessionId)}/commit-delta-summary`,
        commitDeltaRequestSchema.parse(input)
      )
    );
  }

  async checkout(
    attachSessionId: string,
    input: CheckoutRequest
  ): Promise<CheckoutResponse> {
    return checkoutResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/attach-sessions/${encodeURIComponent(attachSessionId)}/checkout`,
        input
      )
    );
  }

  async checkin(
    attachSessionId: string,
    input: CheckinRequest
  ): Promise<CheckinResponse> {
    return checkinResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/attach-sessions/${encodeURIComponent(attachSessionId)}/checkin`,
        input
      )
    );
  }

  async delegations(attachSessionId: string, includeReleased = false): Promise<DelegationsResponse> {
    return delegationsResponseSchema.parse(
      await this.requestJson(
        "GET",
        `/v1/attach-sessions/${encodeURIComponent(attachSessionId)}/delegations?includeReleased=${includeReleased ? "true" : "false"}`
      )
    );
  }

  async detach(attachSessionId: string, releaseLease = true): Promise<DetachResponse> {
    return detachResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/attach-sessions/${encodeURIComponent(attachSessionId)}/detach`,
        { releaseLease }
      )
    );
  }

  async renewLease(args: {
    leaseId: string;
    fencingToken: number;
    leaseTtlMs: number;
  }): Promise<RenewLeaseResponse> {
    return renewLeaseResponseSchema.parse(
      await this.requestJson("POST", `/v1/leases/${encodeURIComponent(args.leaseId)}/renew`, {
        fencingToken: args.fencingToken,
        leaseTtlMs: args.leaseTtlMs,
      })
    );
  }

  async snapshot(
    volumeId: string,
    input: SnapshotRequest
  ): Promise<SnapshotResponse> {
    return snapshotResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/volumes/${encodeURIComponent(volumeId)}/snapshots`,
        input
      )
    );
  }

  async listSnapshots(volumeId: string, branch?: string): Promise<ListSnapshotsResponse> {
    const query = branch ? `?branch=${encodeURIComponent(branch)}` : "";
    return listSnapshotsResponseSchema.parse(
      await this.requestJson(
        "GET",
        `/v1/volumes/${encodeURIComponent(volumeId)}/snapshots${query}`
      )
    );
  }

  async deleteSnapshot(volumeId: string, name: string): Promise<DeleteSnapshotResponse> {
    const response = (await this.requestJson(
      "DELETE",
      `/v1/volumes/${encodeURIComponent(volumeId)}/snapshots/${encodeURIComponent(name)}`
    )) as { released?: DeleteSnapshotResponse };
    if (!response?.released || !Array.isArray(response.released.cutIds)) {
      throw new VolumeClientError(502, "VOLUME_PROTOCOL_ERROR", "Snapshot release response was empty.");
    }
    return response.released;
  }

  async createBranch(
    volumeId: string,
    input: CreateBranchRequest
  ): Promise<CreateBranchResponse> {
    return createBranchResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/volumes/${encodeURIComponent(volumeId)}/branches`,
        input
      )
    );
  }

  async listBranches(volumeId: string): Promise<ListBranchesResponse> {
    return listBranchesResponseSchema.parse(
      await this.requestJson(
        "GET",
        `/v1/volumes/${encodeURIComponent(volumeId)}/branches`
      )
    );
  }

  async listVolumeDelegations(volumeId: string, branch = "main", includeReleased = false): Promise<DelegationsResponse> {
    return delegationsResponseSchema.parse(
      await this.requestJson(
        "GET",
        `/v1/volumes/${encodeURIComponent(volumeId)}/delegations?branch=${encodeURIComponent(branch)}&includeReleased=${includeReleased ? "true" : "false"}`
      )
    );
  }

  async grep(volumeId: string, input: GrepRequest): Promise<GrepResponse> {
    return grepResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/volumes/${encodeURIComponent(volumeId)}/grep`,
        input
      )
    );
  }

  async fork(snapshotId: string, input: ForkRequest): Promise<ForkResponse> {
    return forkResponseSchema.parse(
      await this.requestJson(
        "POST",
        `/v1/snapshots/${encodeURIComponent(snapshotId)}/fork`,
        input
      )
    );
  }

  async getManifest(commitId: string): Promise<TreeManifest> {
    const response = (await this.requestJson(
      "GET",
      `/v1/commits/${encodeURIComponent(commitId)}/manifest`
    )) as { manifest?: unknown };
    if (!response.manifest) {
      throw new VolumeClientError(502, "VOLUME_PROTOCOL_ERROR", "Manifest response was empty.");
    }
    return response.manifest as TreeManifest;
  }

  private async requestJson(
    method: string,
    path: string,
    body?: unknown
  ): Promise<unknown> {
    const init: RequestInit = {
      method,
      headers: this.headers(body === undefined ? undefined : "application/json"),
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    return readResponse(response);
  }

  private headers(contentType?: string): Record<string, string> {
    const headers: Record<string, string> = {};
    if (contentType) {
      headers["content-type"] = contentType;
    }
    if (this.token) {
      headers.authorization = `Bearer ${this.token}`;
    }
    return headers;
  }
}

function encodeBlobBatchBinary(blobs: Array<{ digest: BlobDigest; buffer: Buffer }>): Buffer {
  if (blobs.length > 1024) {
    throw new VolumeClientError(
      400,
      "VOLUME_BLOB_BATCH_TOO_LARGE",
      "Blob batch cannot contain more than 1024 blobs."
    );
  }
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(8);
  header.write("OSVB", 0, "ascii");
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(blobs.length, 6);
  parts.push(header);
  let totalBytes = header.byteLength;
  for (const blob of blobs) {
    const digestBytes = Buffer.from(blob.digest, "utf8");
    if (digestBytes.byteLength > 0xffff) {
      throw new VolumeClientError(400, "VOLUME_BLOB_DIGEST_INVALID", "Blob digest is too long.");
    }
    if (blob.buffer.byteLength > 0xffffffff) {
      throw new VolumeClientError(400, "VOLUME_BLOB_TOO_LARGE", "Blob is too large for binary batch upload.");
    }
    const entryHeader = Buffer.allocUnsafe(6);
    entryHeader.writeUInt16BE(digestBytes.byteLength, 0);
    entryHeader.writeUInt32BE(blob.buffer.byteLength, 2);
    parts.push(entryHeader, digestBytes, blob.buffer);
    totalBytes += entryHeader.byteLength + digestBytes.byteLength + blob.buffer.byteLength;
  }
  return Buffer.concat(parts, totalBytes);
}

function uploadBlobBatchResponseFromAck(
  ack: UploadBlobBatchAckResponse,
  blobs: Array<{ digest: BlobDigest; buffer: Buffer }>
): UploadBlobBatchResponse {
  const bytes = blobs.reduce((total, blob) => total + blob.buffer.byteLength, 0);
  if (ack.count !== blobs.length || ack.bytes !== bytes) {
    throw new VolumeClientError(
      502,
      "VOLUME_PROTOCOL_ERROR",
      `Blob batch ack mismatch: server accepted ${ack.count}/${ack.bytes}, client sent ${blobs.length}/${bytes}.`
    );
  }
  return {
    blobs: blobs.map((blob) => ({
      digest: blob.digest,
      size: blob.buffer.byteLength,
      compression: "none" as const,
      packed: false,
    })),
  };
}

function uploadBlobBatchResponseFromAckOrFull(
  body: unknown,
  blobs: Array<{ digest: BlobDigest; buffer: Buffer }>
): UploadBlobBatchResponse {
  const ack = uploadBlobBatchAckResponseSchema.safeParse(body);
  if (ack.success) {
    return uploadBlobBatchResponseFromAck(ack.data, blobs);
  }
  return uploadBlobBatchResponseSchema.parse(body);
}

async function readResponse(response: Response): Promise<unknown> {
  if (!response.ok) {
    await throwClientError(response);
  }
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

async function throwClientError(response: Response): Promise<never> {
  const payload = (await response.json().catch(() => null)) as
    | { error?: { code?: string; message?: string } }
    | null;
  throw new VolumeClientError(
    response.status,
    payload?.error?.code ?? "VOLUME_HTTP_ERROR",
    payload?.error?.message ?? `Volume API request failed with ${response.status}.`
  );
}
