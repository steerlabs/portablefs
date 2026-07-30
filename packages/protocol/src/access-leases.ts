import { z } from "zod";

// ---------------------------------------------------------------------------
// Canonical access leases (portablefs-v1).
//
// An ACCESS LEASE is the canonical name for the external lease a consumer
// (hosted control plane worker, sandbox, device) holds against the authority
// manager's data plane. It is EXPLICITLY NOT the internal exact filesystem
// session (fsproto attach session): losing the lease token never loses the
// filesystem session — the caller reacquires a fresh lease and resumes.
//
// Identity and fencing:
//   - accessLeaseId: server-assigned stable id (prefix `pfal_`).
//   - managerEpoch: the epoch id of the manager state that minted the lease's
//     tokens. Tokens are deterministic HMACs bound to the epoch inside the
//     MAC key derivation, so a ledger reset (fresh epoch) invalidates every
//     old token automatically.
//   - controlSeq: advances by exactly one for each ACCEPTED control mutation
//     (create, renew, rotate, release, revoke) on the lease. Replays return
//     the recorded controlSeq unchanged.
//   - tokenGeneration: increments ONLY on explicit rotation; renewal without
//     rotation never changes it.
//
// Routes: POST /v1/access-leases/create | inspect | renew | release | revoke |
// revoke-owner. Inspect authenticates the exact current token and returns the
// canonical active binding without changing the lease.
//
// This contract is wire-compatible with the hosted PortableFS stack: the same
// route names, shapes, and error codes, so a consumer built against one stack
// works against the other. `teamId` is the optional tenant-scope field hosted
// control planes use; plain deployments omit it.
// ---------------------------------------------------------------------------

export const accessLeaseProtocolVersion = 1 as const;

// All 64-bit counters cross the wire as canonical positive decimal STRINGS
// (each its own branded domain) — never JS numbers, which round above 2^53.
export const maxSignedInt64Decimal = "9223372036854775807" as const;
const positiveDecimalPattern = /^[1-9][0-9]{0,18}$/u;

function isSignedInt64Decimal(value: string): boolean {
  return (
    value.length < maxSignedInt64Decimal.length ||
    (value.length === maxSignedInt64Decimal.length && value <= maxSignedInt64Decimal)
  );
}

const idSchema = z.string().min(1).max(256);

export const authorityBranchSchema = z.string().min(1).max(128);

export const accessLeaseIdSchema = z.string().regex(/^pfal_[A-Za-z0-9_-]{1,120}$/u);
export type AccessLeaseId = z.infer<typeof accessLeaseIdSchema>;

export const accessLeaseOperationIdSchema = z.string().min(1).max(256);
export const accessConsumerIdSchema = z.string().min(1).max(256);
export const accessLeaseTtlMsSchema = z
  .number()
  .int()
  .positive()
  .max(24 * 60 * 60 * 1000);

export const accessLeaseControlSeqSchema = z
  .string()
  .regex(positiveDecimalPattern, "controlSeq must be a canonical positive decimal string")
  .refine(isSignedInt64Decimal, "controlSeq exceeds signed int64")
  .brand<"AccessLeaseControlSeq">();
export type AccessLeaseControlSeq = z.infer<typeof accessLeaseControlSeqSchema>;
export function parseAccessLeaseControlSeq(value: string): AccessLeaseControlSeq {
  return accessLeaseControlSeqSchema.parse(value);
}

export const accessLeaseTokenGenerationSchema = z
  .string()
  .regex(positiveDecimalPattern, "tokenGeneration must be a canonical positive decimal string")
  .refine(isSignedInt64Decimal, "tokenGeneration exceeds signed int64")
  .brand<"AccessLeaseTokenGeneration">();
export type AccessLeaseTokenGeneration = z.infer<typeof accessLeaseTokenGenerationSchema>;
export function parseAccessLeaseTokenGeneration(value: string): AccessLeaseTokenGeneration {
  return accessLeaseTokenGenerationSchema.parse(value);
}

// managerEpoch identifies one lifetime of the manager's durable lease state.
// It is minted randomly when the lease ledger is first created and lives
// inside every token's MAC key derivation, so a reset ledger (new epoch)
// invalidates all previously issued tokens automatically.
export const managerEpochSchema = z
  .string()
  .regex(positiveDecimalPattern, "managerEpoch must be a canonical positive decimal string")
  .refine(isSignedInt64Decimal, "managerEpoch exceeds signed int64")
  .brand<"ManagerEpoch">();
export type ManagerEpoch = z.infer<typeof managerEpochSchema>;
export function parseManagerEpoch(value: string): ManagerEpoch {
  return managerEpochSchema.parse(value);
}

export const accessLeaseStateSchema = z.enum(["active", "released", "expired", "revoked"]);
export type AccessLeaseState = z.infer<typeof accessLeaseStateSchema>;

export const accessLeaseEndReasonSchema = z.enum([
  "released",
  "expired",
  "revoked",
  "owner-revoked",
  "authority-retired",
  // The manager epoch that minted the lease's tokens ended. Kept for wire
  // parity with hosted stacks; this deployment model reports it only when
  // lease state outlives an epoch change, which a ledger reset does not.
  "manager-epoch-superseded",
]);
export type AccessLeaseEndReason = z.infer<typeof accessLeaseEndReasonSchema>;

// The exact receipt of one create/renew/release request against a lease.
// Bounded retention with an explicit retained floor: an operation id older
// than the floor is rejected (ACCESS_LEASE_RECEIPT_EVICTED), never silently
// re-executed.
export const accessLeaseReceiptSchema = z.object({
  operationId: accessLeaseOperationIdSchema,
  kind: z.enum(["create", "renew", "release"]),
  // Store-computed canonical request fingerprint; callers never supply it.
  // Reusing an operationId with different semantic content conflicts.
  fingerprint: z.string().min(1),
  accessLeaseId: accessLeaseIdSchema,
  controlSeq: accessLeaseControlSeqSchema,
  tokenGeneration: accessLeaseTokenGenerationSchema,
  expiresAt: z.number().int().nonnegative().optional(),
  completedAtMs: z.number().int().nonnegative(),
});
export type AccessLeaseReceipt = z.infer<typeof accessLeaseReceiptSchema>;

// The public view of an access lease. Token material never leaves the server
// outside the create/rotate response; expiry, id, controlSeq, and generations
// are always server-assigned.
export const accessLeaseSchema = z.object({
  version: z.literal(accessLeaseProtocolVersion),
  accessLeaseId: accessLeaseIdSchema,
  teamId: idSchema.optional(),
  volumeId: idSchema,
  branch: authorityBranchSchema,
  authorityInstanceId: idSchema,
  managerEpoch: managerEpochSchema.optional(),
  consumerId: accessConsumerIdSchema,
  tokenGeneration: accessLeaseTokenGenerationSchema,
  controlSeq: accessLeaseControlSeqSchema,
  state: accessLeaseStateSchema,
  expiresAt: z.number().int().nonnegative(),
  createdAtMs: z.number().int().nonnegative(),
  endedAtMs: z.number().int().nonnegative().optional(),
  endReason: accessLeaseEndReasonSchema.optional(),
});
export type AccessLease = z.infer<typeof accessLeaseSchema>;

// The exact transport a lease holder MUST use for the data-plane endpoint.
// This is deliberately discriminated instead of treating an empty CA as
// plaintext: every successful production lease names one unambiguous mode.
//
// Optional at the outer endpoint boundary for additive wire compatibility
// with managers released before this field existed. Current PortableFS mount
// clients require it and report explicit upgrade guidance when it is absent.
function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every(
      (part) =>
        /^(0|[1-9][0-9]{0,2})$/u.test(part) && Number(part) >= 0 && Number(part) <= 255
    )
  );
}

function isIPv6(value: string): boolean {
  if (!value.includes(":") || value.includes(":::") || value.indexOf("::") !== value.lastIndexOf("::")) {
    return false;
  }
  const compressed = value.includes("::");
  const halves = compressed ? value.split("::") : [value, ""];
  const leftText = halves[0] ?? "";
  const rightText = halves[1] ?? "";
  const left = leftText === "" ? [] : leftText.split(":");
  const right = rightText === "" ? [] : rightText.split(":");
  const all = [...left, ...right];
  let groups = 0;
  for (let index = 0; index < all.length; index += 1) {
    const part = all[index]!;
    if (part.includes(".")) {
      if (index !== all.length - 1 || !isIPv4(part)) {
        return false;
      }
      groups += 2;
    } else {
      if (!/^[A-Fa-f0-9]{1,4}$/u.test(part)) {
        return false;
      }
      groups += 1;
    }
  }
  return compressed ? groups < 8 : groups === 8;
}

function isDataPlaneServerName(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > 253 ||
    value !== value.trim() ||
    /[\u0000-\u0020/\\]/u.test(value) ||
    value.startsWith("[") ||
    value.endsWith("]")
  ) {
    return false;
  }
  if (isIPv4(value) || isIPv6(value)) {
    return true;
  }
  return value.split(".").every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-") &&
      /^[A-Za-z0-9-]+$/u.test(label)
  );
}

const dataPlaneServerNameSchema = z
  .string()
  .min(1)
  .max(253)
  .refine(isDataPlaneServerName, "serverName must be a valid DNS name or unbracketed IP address");
const dataPlaneCAPEMSchema = z.string().min(1).max(256 * 1024);
const sha256HexSchema = z.string().regex(/^[a-f0-9]{64}$/u, "caSha256 must be lowercase SHA-256 hex");

export const dataPlaneTransportSchema = z.discriminatedUnion("mode", [
  z
    .object({
      mode: z.literal("tls-private-ca"),
      serverName: dataPlaneServerNameSchema,
      caPem: dataPlaneCAPEMSchema,
      caSha256: sha256HexSchema,
    })
    .strict(),
  z
    .object({
      mode: z.literal("tls-system-pki"),
      serverName: dataPlaneServerNameSchema,
    })
    .strict(),
  z.object({ mode: z.literal("plaintext") }).strict(),
]);
export type DataPlaneTransport = z.infer<typeof dataPlaneTransportSchema>;

// The endpoint payload the caller mounts against: dial this address and
// present the accessToken as the data-plane router handshake token.
export const authorityEndpointPayloadSchema = z.object({
  provider: z.string().min(1).max(128).optional(),
  authorityUrl: z.string().min(1).max(512),
  host: z.string().min(1).max(255).optional(),
  port: z.number().int().positive().max(65535).optional(),
  // Retired with the NFSv3 data plane: kept optional for wire compatibility
  // with older payloads; no producer emits it.
  nfsPort: z.number().int().positive().max(65535).optional(),
  authorityInstanceId: idSchema.optional(),
  authorityAuthToken: z.string().min(1).optional(),
  authorityExpiresAt: z.number().int().nonnegative().optional(),
  dataPlaneTransport: dataPlaneTransportSchema.optional(),
});
export type AuthorityEndpointPayload = z.infer<typeof authorityEndpointPayloadSchema>;

export const accessLeaseCreateRequestSchema = z
  .object({
    operationId: accessLeaseOperationIdSchema,
    teamId: idSchema.optional(),
    volumeId: idSchema,
    branch: authorityBranchSchema,
    consumerId: accessConsumerIdSchema,
    ttlMs: accessLeaseTtlMsSchema.optional(),
  })
  .strict();
export type AccessLeaseCreateRequest = z.input<typeof accessLeaseCreateRequestSchema>;

// Create replay semantics: retrying the same operationId + fingerprint never
// mints a second lease. Tokens are deterministic HMACs over the recorded
// claims, so a replay returns the IDENTICAL token, expiry, tokenGeneration,
// and controlSeq.
export const accessLeaseCreateResponseSchema = z.object({
  authority: authorityEndpointPayloadSchema,
  lease: accessLeaseSchema,
  accessToken: z.string().min(1),
  serverTimeMs: z.number().int().nonnegative(),
});
export type AccessLeaseCreateResponse = z.infer<typeof accessLeaseCreateResponseSchema>;

// Read-only handshake. The token is bounded before any authentication work,
// never appears in the response, and authenticates only the lease's CURRENT
// token generation. No receipt, no controlSeq change.
export const accessLeaseInspectRequestSchema = z
  .object({
    accessLeaseId: accessLeaseIdSchema,
    accessToken: z.string().min(1).max(4096),
  })
  .strict();
export type AccessLeaseInspectRequest = z.infer<typeof accessLeaseInspectRequestSchema>;

export const accessLeaseInspectResponseSchema = z
  .object({
    lease: accessLeaseSchema.strict(),
    serverTimeMs: z.number().int().nonnegative(),
  })
  .strict();
export type AccessLeaseInspectResponse = z.infer<typeof accessLeaseInspectResponseSchema>;

export const accessLeaseRenewRequestSchema = z
  .object({
    operationId: accessLeaseOperationIdSchema,
    accessLeaseId: accessLeaseIdSchema,
    accessToken: z.string().min(1),
    // Retry-stable CAS precondition. Callers MUST persist and resend the
    // controlSeq from the lease they observed before this operation. It is
    // deliberately not part of semantic request identity: a retained receipt
    // replays first, while a receipt miss uses this original value for the
    // retained-floor and live-CAS checks.
    expectedControlSeq: accessLeaseControlSeqSchema,
    ttlMs: accessLeaseTtlMsSchema.optional(),
    // Rotate the token within the SAME lease: tokenGeneration increments, the
    // previous token stops resolving on the data plane, and live tunnels
    // opened under older generations are closed immediately.
    rotateToken: z.boolean().optional(),
  })
  .strict();
export type AccessLeaseRenewRequest = z.input<typeof accessLeaseRenewRequestSchema>;

export const accessLeaseRenewResponseSchema = z.object({
  lease: accessLeaseSchema,
  // Present only when the renew rotated the token.
  accessToken: z.string().min(1).optional(),
  serverTimeMs: z.number().int().nonnegative(),
});
export type AccessLeaseRenewResponse = z.infer<typeof accessLeaseRenewResponseSchema>;

export const accessLeaseReleaseRequestSchema = z
  .object({
    operationId: accessLeaseOperationIdSchema,
    accessLeaseId: accessLeaseIdSchema,
    accessToken: z.string().min(1),
  })
  .strict();
export type AccessLeaseReleaseRequest = z.input<typeof accessLeaseReleaseRequestSchema>;

export const accessLeaseReleaseResponseSchema = z.object({
  lease: accessLeaseSchema,
  receipt: accessLeaseReceiptSchema,
  serverTimeMs: z.number().int().nonnegative(),
});
export type AccessLeaseReleaseResponse = z.infer<typeof accessLeaseReleaseResponseSchema>;

// Administrative: the manager bearer token already authenticates the route,
// so no access token is required.
export const accessLeaseRevokeRequestSchema = z
  .object({
    accessLeaseId: accessLeaseIdSchema,
  })
  .strict();
export type AccessLeaseRevokeRequest = z.input<typeof accessLeaseRevokeRequestSchema>;

export const accessLeaseRevokeResponseSchema = z.object({
  lease: accessLeaseSchema,
  serverTimeMs: z.number().int().nonnegative(),
});
export type AccessLeaseRevokeResponse = z.infer<typeof accessLeaseRevokeResponseSchema>;

// Owner revocation spans volumes only within one tenant namespace: the server
// requires at least volumeId or teamId to scope the batch.
export const accessLeaseRevokeOwnerRequestSchema = z
  .object({
    teamId: idSchema.optional(),
    consumerId: accessConsumerIdSchema,
    volumeId: idSchema.optional(),
    branch: authorityBranchSchema.optional(),
  })
  .strict();
export type AccessLeaseRevokeOwnerRequest = z.input<typeof accessLeaseRevokeOwnerRequestSchema>;

export const accessLeaseRevokeOwnerResponseSchema = z.object({
  revoked: z.array(accessLeaseIdSchema),
  serverTimeMs: z.number().int().nonnegative(),
});
export type AccessLeaseRevokeOwnerResponse = z.infer<typeof accessLeaseRevokeOwnerResponseSchema>;

// Stable machine-readable error codes for the access-lease routes
// ({ error: { code, message } }).
export const accessLeaseErrorCodes = {
  invalidRequest: "ACCESS_LEASE_INVALID_REQUEST",
  // The registry mode does not manage access leases (environment mode).
  unsupported: "ACCESS_LEASE_UNSUPPORTED",
  notFound: "ACCESS_LEASE_NOT_FOUND",
  // The presented token does not authenticate the lease's current (or, for
  // the exact replay of a rotation, immediately previous) token generation.
  unauthorized: "ACCESS_LEASE_UNAUTHORIZED",
  // An operationId was reused with a different canonical request fingerprint.
  operationConflict: "ACCESS_LEASE_OPERATION_CONFLICT",
  // The operation id is below the lease's retained receipt floor: the exact
  // outcome is forgotten and is NEVER silently re-executed.
  receiptEvicted: "ACCESS_LEASE_RECEIPT_EVICTED",
  // Terminal-state refusals: a renew/release against an ended lease NEVER
  // mints a replacement; the caller must create a fresh lease.
  released: "ACCESS_LEASE_RELEASED",
  expired: "ACCESS_LEASE_EXPIRED",
  revoked: "ACCESS_LEASE_REVOKED",
  // The durable lease ledger refused the mutation (failed validation); the
  // manager fails readiness rather than guessing lease state.
  storeUnavailable: "ACCESS_LEASE_STORE_UNAVAILABLE",
  // The manager epoch that scoped this lease ended; reacquire a fresh lease.
  // Kept for wire parity with hosted stacks.
  epochSuperseded: "ACCESS_LEASE_EPOCH_SUPERSEDED",
  internal: "ACCESS_LEASE_INTERNAL",
} as const;
export type AccessLeaseErrorCode = (typeof accessLeaseErrorCodes)[keyof typeof accessLeaseErrorCodes];
