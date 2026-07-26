import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
  parseAccessLeaseTokenGeneration,
  type AccessLeaseControlSeq,
  type AccessLeaseTokenGeneration,
  type ManagerEpoch,
} from "@portablefs/protocol";

// ---------------------------------------------------------------------------
// Deterministic access tokens.
//
// An access token is an HMAC-SHA256 over the STRICT canonical length-delimited
// claims of the lease state that minted it (create or explicit rotation):
//
//   protocol version, managerEpoch, accessLeaseId, controlSeq (at mint),
//   tokenGeneration, tenant/team, volume, branch, authorityInstanceId,
//   authorityRuntimeGeneration, consumer, expiry (at mint).
//
// KEY DERIVATION (versioned, KMS-style): the MAC key is NOT a stored secret.
// It is derived per (managerEpoch, tokenGeneration) from a REQUIRED stable
// root secret:
//
//   key = HMAC-SHA256(root, "pfat-key-v1" ‖ len(managerEpoch) ‖ managerEpoch
//                            ‖ len(tokenGeneration) ‖ tokenGeneration)
//
// Because the derivation input is exactly (root + recorded claims), a manager
// that restarted — or a lost-response replay answered from the durable
// receipt — recomputes the BYTE-IDENTICAL token with no plaintext token
// storage anywhere. Epoch is inside the key: every token dies with its
// manager epoch (a reset ledger) even before claims validation runs.
//
// Length-delimited canonical form: every claim is rendered as
// `${utf8ByteLength}:${value}` and concatenated, so no claim value can smear
// into a neighbor regardless of content (a strict, injective encoding).
//
// All 64-bit counters cross this module as branded canonical decimal strings
// (@portablefs/protocol); nothing here ever coerces them to JS numbers.
// ---------------------------------------------------------------------------

export interface AccessTokenClaims {
  protocolVersion: number;
  managerEpoch: ManagerEpoch;
  accessLeaseId: string;
  controlSeq: AccessLeaseControlSeq;
  tokenGeneration: AccessLeaseTokenGeneration;
  teamId: string;
  volumeId: string;
  branch: string;
  authorityInstanceId: string;
  // Claim slot kept for cross-stack token-computation parity. This deployment
  // model does not sequence child runtimes, so callers pin it to "1".
  authorityRuntimeGeneration: string;
  consumerId: string;
  expiresAt: number;
}

function lengthDelimited(parts: readonly string[]): Buffer {
  return Buffer.concat(
    parts.map((part) => {
      const bytes = Buffer.from(part, "utf8");
      return Buffer.concat([Buffer.from(`${bytes.byteLength}:`, "ascii"), bytes]);
    })
  );
}

export function canonicalAccessTokenClaims(claims: AccessTokenClaims): Buffer {
  return lengthDelimited([
    "pfat-claims-v2",
    String(claims.protocolVersion),
    claims.managerEpoch,
    claims.accessLeaseId,
    claims.controlSeq,
    claims.tokenGeneration,
    claims.teamId,
    claims.volumeId,
    claims.branch,
    claims.authorityInstanceId,
    claims.authorityRuntimeGeneration,
    claims.consumerId,
    String(claims.expiresAt),
  ]);
}

// deriveTokenKey derives the versioned per-(epoch, generation) MAC key from
// the stable root secret. Deterministic and stateless by design.
export function deriveTokenKey(
  rootSecret: Buffer,
  managerEpoch: ManagerEpoch,
  tokenGeneration: AccessLeaseTokenGeneration
): Buffer {
  return createHmac("sha256", rootSecret)
    .update(lengthDelimited(["pfat-key-v1", managerEpoch, tokenGeneration]))
    .digest();
}

// mintAccessToken derives the deterministic token for the claims under the
// root secret. Format: `<accessLeaseId>.g<tokenGeneration>.<mac>` — the id
// and generation prefix let the data plane resolve the lease and generation
// without a token index; the MAC alone authenticates.
export function mintAccessToken(rootSecret: Buffer, claims: AccessTokenClaims): string {
  const key = deriveTokenKey(rootSecret, claims.managerEpoch, claims.tokenGeneration);
  const mac = createHmac("sha256", key).update(canonicalAccessTokenClaims(claims)).digest();
  return `${claims.accessLeaseId}.g${claims.tokenGeneration}.${mac.toString("base64url")}`;
}

export interface ParsedAccessToken {
  accessLeaseId: string;
  tokenGeneration: AccessLeaseTokenGeneration;
  mac: string;
}

export function parseAccessToken(token: string): ParsedAccessToken | null {
  if (token.length > 512) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const [accessLeaseId, generationPart, mac] = parts as [string, string, string];
  if (!accessLeaseId || !mac || !/^g[1-9][0-9]{0,18}$/u.test(generationPart)) {
    return null;
  }
  try {
    return {
      accessLeaseId,
      tokenGeneration: parseAccessLeaseTokenGeneration(generationPart.slice(1)),
      mac,
    };
  } catch {
    return null;
  }
}

// verifyAccessToken recomputes the deterministic token for the recorded mint
// claims and compares in constant time.
export function verifyAccessToken(
  rootSecret: Buffer,
  claims: AccessTokenClaims,
  presentedToken: string
): boolean {
  const expected = mintAccessToken(rootSecret, claims);
  const expectedBytes = Buffer.from(expected, "utf8");
  const presentedBytes = Buffer.from(presentedToken, "utf8");
  return (
    expectedBytes.byteLength === presentedBytes.byteLength &&
    timingSafeEqual(expectedBytes, presentedBytes)
  );
}

// ---------------------------------------------------------------------------
// Root secret loading.
// ---------------------------------------------------------------------------

// parseAccessTokenRootSecret decodes the stable root secret
// (PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET): 64 hex chars or base64/base64url of
// exactly 32 bytes. The root never appears in child env or logs.
export function parseAccessTokenRootSecret(raw: string): Buffer {
  const trimmed = raw.trim();
  if (/^[0-9a-fA-F]{64}$/u.test(trimmed)) {
    return Buffer.from(trimmed, "hex");
  }
  if (/^[A-Za-z0-9+/_-]{43,44}={0,2}$/u.test(trimmed)) {
    const decoded = Buffer.from(trimmed, "base64");
    if (decoded.byteLength === 32) {
      return decoded;
    }
  }
  throw new Error(
    "PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET must be 32 bytes as 64 hex chars or base64."
  );
}

// ---------------------------------------------------------------------------
// Cryptographic RNG (required — no time-derived fallback exists anywhere).
// ---------------------------------------------------------------------------

// assertCryptographicRng proves node:crypto's CSPRNG is functional at
// composition time; identifier and secret minting has NO fallback path.
export function assertCryptographicRng(): void {
  const sample = randomBytes(16);
  if (sample.byteLength !== 16) {
    throw new Error("Cryptographic RNG is unavailable; refusing to mint identifiers or secrets.");
  }
}

export function mintRootSecret(): Buffer {
  assertCryptographicRng();
  return randomBytes(32);
}

export function mintAccessLeaseId(): string {
  assertCryptographicRng();
  return `pfal_${randomUUID().replaceAll("-", "")}`;
}

// mintManagerEpoch mints a random epoch id in the canonical positive-int64
// decimal domain, so epoch values are wire-compatible with stacks that
// sequence epochs from a database counter.
export function mintManagerEpoch(): string {
  assertCryptographicRng();
  const value = randomBytes(8).readBigUInt64BE(0) & 0x7fffffffffffffffn;
  return String(value === 0n ? 1n : value);
}
