import {
  createHash,
  createPrivateKey,
  randomBytes,
  timingSafeEqual,
  X509Certificate,
} from "node:crypto";
import { closeSync, openSync, readSync } from "node:fs";
import {
  createServer as createNetServer,
  connect,
  isIP,
  type AddressInfo,
  type Server,
  type Socket,
} from "node:net";
import {
  connect as connectTLS,
  createSecureContext,
  createServer as createTlsServer,
  type TLSSocket,
} from "node:tls";
import type { DataPlaneTransport } from "@portablefs/protocol";
import { parseAuthorityAddress } from "./authority-address.js";

// ── THE ACK VOCABULARY ───────────────────────────────────────────────────────
//
// The router answers a client's token frame with ONE byte. Until round 18d that
// byte was 0 (admit) or 1 (refuse), and 1 was written for four unrelated
// conditions: a token that did not resolve, a lease at its tunnel limit, a
// lease that ended or rotated mid-handshake, and a reservation that could not
// be consumed. The client could only read "the credential was rejected" out of
// that, so it latched a terminal credential verdict and told operators to run
// `portablefs login` — measured live against a lease with 4.5 minutes of
// validity left, for which re-login was not the remedy.
//
// One byte can carry the difference, so it does. Zero still means, and only
// ever means, admitted; every refusal now names itself.
//
// Compatibility: an OLD client reads any nonzero byte as a credential refusal,
// which is exactly what it did with ack 1 for these same conditions — no
// regression, and no code it would newly admit. A NEW client reading an OLD
// router only ever sees 0 or 1, whose meanings are unchanged. See
// vcs/internal/fsproto/reconnect.go, which holds the mirrored list.
export const AckCode = {
  Admitted: 0,
  /** The session token did not resolve. TERMINAL: the credential is dead. */
  CredentialRejected: 1,
  /** maxTunnelsPerLease or maxOpenTunnels is reached. RETRYABLE. */
  AtCapacity: 2,
  /** The lease ended or rotated its token generation mid-handshake. RETRYABLE. */
  LeaseTransition: 3,
  /** No backend authority was reachable for a resolved route. RETRYABLE. */
  AuthorityUnavailable: 4,
} as const;

export type AckCodeValue = (typeof AckCode)[keyof typeof AckCode];

const MAX_TOKEN_BYTES = 4096;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5_000;
const DEFAULT_BACKEND_CONNECT_TIMEOUT_MS = 5_000;
const MAX_ROUTER_CA_BYTES = 256 * 1024;
const MAX_ROUTER_TLS_MATERIAL_BYTES = 256 * 1024;
const TLS_PREFLIGHT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_PENDING_CONNECTIONS = 256;
const DEFAULT_MAX_OPEN_TUNNELS = 4096;
const DEFAULT_MAX_TUNNELS_PER_LEASE = 64;

export interface AuthorityDataPlaneRouterLimits {
  maxPendingConnections: number;
  maxOpenTunnels: number;
  maxTunnelsPerLease: number;
  maxConnections: number;
}

export function authorityDataPlaneRouterLimitsFromEnv(
  env: NodeJS.ProcessEnv
): AuthorityDataPlaneRouterLimits {
  const maxPendingConnections = positiveIntegerEnv(
    env,
    "PORTABLEFS_AUTHORITY_ROUTER_MAX_PENDING_CONNECTIONS",
    DEFAULT_MAX_PENDING_CONNECTIONS
  );
  const maxOpenTunnels = positiveIntegerEnv(
    env,
    "PORTABLEFS_AUTHORITY_ROUTER_MAX_OPEN_TUNNELS",
    DEFAULT_MAX_OPEN_TUNNELS
  );
  const maxTunnelsPerLease = positiveIntegerEnv(
    env,
    "PORTABLEFS_AUTHORITY_ROUTER_MAX_TUNNELS_PER_LEASE",
    DEFAULT_MAX_TUNNELS_PER_LEASE
  );
  if (maxTunnelsPerLease > maxOpenTunnels) {
    throw new Error(
      "PORTABLEFS_AUTHORITY_ROUTER_MAX_TUNNELS_PER_LEASE must not exceed PORTABLEFS_AUTHORITY_ROUTER_MAX_OPEN_TUNNELS."
    );
  }
  const maxConnections = maxPendingConnections + maxOpenTunnels;
  if (!Number.isSafeInteger(maxConnections)) {
    throw new Error("PortableFS authority router connection limits exceed the safe integer range.");
  }
  return {
    maxPendingConnections,
    maxOpenTunnels,
    maxTunnelsPerLease,
    maxConnections,
  };
}

export interface AuthorityDataPlaneRoute {
  authorityInstanceId: string;
  backendAddresses: string[];
  backendAuthToken: string;
  sessionExpiresAt?: number;
  // Present when the token resolved through the access-lease service: the
  // router registers the admitted tunnel under this identity so lease end
  // closes it immediately and rotation closes older-generation tunnels.
  accessLeaseId?: string;
  tokenGeneration?: string;
}

export interface AuthorityDataPlaneRouteTable {
  resolveSessionToken(token: string): AuthorityDataPlaneRoute | null;
}

export interface AuthoritySessionRouteTable extends AuthorityDataPlaneRouteTable {
  createSession(args: {
    authorityInstanceId: string;
    backendAddresses: string[];
    backendAuthToken: string;
    expiresAt?: number;
    // Optional lease scope for route tables that mint sessions as access
    // leases; plain token tables ignore these.
    teamId?: string;
    volumeId?: string;
    branch?: string;
  }): { token: string; expiresAt?: number };
  deleteAuthority(authorityInstanceId: string): void;
}

// ---------------------------------------------------------------------------
// Live-tunnel registry for lease-scoped connections.
//
// Tunnels admitted with an access-lease token are registered per lease id;
// the lease service's onLeaseEnded/onLeaseRotated events (wired in main.ts)
// close them the moment the lease ends (release/revoke/revoke-owner/expiry
// sweep) or rotates past the tunnel's token generation. A tunnel therefore
// stays open exactly as long as its lease is active on the admitted
// generation: renewals reschedule the lease expiry sweep, so renewing keeps
// live tunnels open without any router-side action.
// ---------------------------------------------------------------------------

interface LeaseTunnel {
  tokenGeneration: string;
  client: Socket;
  backend: Socket;
}

export interface LeaseTunnelReservation {
  accessLeaseId: string;
  tokenGeneration: string;
  reservationId: symbol;
}

export class LeaseTunnelRegistry {
  private readonly tunnelsByLease = new Map<string, Set<LeaseTunnel>>();
  private readonly reservationsByLease = new Map<string, Set<LeaseTunnelReservation>>();
  private readonly maxOpenTunnels: number;
  private readonly maxTunnelsPerLease: number;
  private openTunnels = 0;
  private pendingTunnels = 0;

  constructor(
    limits: Pick<AuthorityDataPlaneRouterLimits, "maxOpenTunnels" | "maxTunnelsPerLease"> = {
      maxOpenTunnels: DEFAULT_MAX_OPEN_TUNNELS,
      maxTunnelsPerLease: DEFAULT_MAX_TUNNELS_PER_LEASE,
    }
  ) {
    this.maxOpenTunnels = positiveSafeInteger(limits.maxOpenTunnels, "maxOpenTunnels");
    this.maxTunnelsPerLease = positiveSafeInteger(
      limits.maxTunnelsPerLease,
      "maxTunnelsPerLease"
    );
    if (this.maxTunnelsPerLease > this.maxOpenTunnels) {
      throw new Error("maxTunnelsPerLease must not exceed maxOpenTunnels.");
    }
  }

  reserve(
    accessLeaseId: string,
    tokenGeneration: string
  ): LeaseTunnelReservation | null {
    const openForLease = this.tunnelsByLease.get(accessLeaseId)?.size ?? 0;
    const pendingForLease = this.reservationsByLease.get(accessLeaseId)?.size ?? 0;
    if (
      openForLease + pendingForLease >= this.maxTunnelsPerLease ||
      this.openTunnels + this.pendingTunnels >= this.maxOpenTunnels
    ) {
      return null;
    }
    const reservation: LeaseTunnelReservation = {
      accessLeaseId,
      tokenGeneration,
      reservationId: Symbol(accessLeaseId),
    };
    const reservations =
      this.reservationsByLease.get(accessLeaseId) ?? new Set<LeaseTunnelReservation>();
    reservations.add(reservation);
    this.reservationsByLease.set(accessLeaseId, reservations);
    this.pendingTunnels += 1;
    return reservation;
  }

  registerReserved(
    reservation: LeaseTunnelReservation,
    client: Socket,
    backend: Socket
  ): boolean {
    if (client.destroyed || backend.destroyed) {
      this.releaseReservation(reservation);
      return false;
    }
    if (!this.consumeReservation(reservation)) {
      return false;
    }
    const tunnel: LeaseTunnel = {
      tokenGeneration: reservation.tokenGeneration,
      client,
      backend,
    };
    const tunnels =
      this.tunnelsByLease.get(reservation.accessLeaseId) ?? new Set<LeaseTunnel>();
    tunnels.add(tunnel);
    this.tunnelsByLease.set(reservation.accessLeaseId, tunnels);
    this.openTunnels += 1;
    const remove = () => {
      const set = this.tunnelsByLease.get(reservation.accessLeaseId);
      if (!set) {
        return;
      }
      if (!set.delete(tunnel)) {
        return;
      }
      this.openTunnels -= 1;
      if (set.size === 0) {
        this.tunnelsByLease.delete(reservation.accessLeaseId);
      }
    };
    client.once("close", () => {
      remove();
      backend.destroy();
    });
    backend.once("close", () => {
      remove();
      client.destroy();
    });
    return true;
  }

  releaseReservation(reservation: LeaseTunnelReservation): void {
    this.consumeReservation(reservation);
  }

  closeLease(accessLeaseId: string): void {
    this.deleteReservations(accessLeaseId);
    const tunnels = this.tunnelsByLease.get(accessLeaseId);
    if (!tunnels) {
      return;
    }
    this.tunnelsByLease.delete(accessLeaseId);
    this.openTunnels -= tunnels.size;
    for (const tunnel of tunnels) {
      tunnel.client.destroy();
      tunnel.backend.destroy();
    }
  }

  // closeSupersededGenerations closes every tunnel for the lease that was
  // admitted under a token generation other than the current one (rotation
  // fencing, both directions).
  closeSupersededGenerations(accessLeaseId: string, currentTokenGeneration: string): void {
    const reservations = this.reservationsByLease.get(accessLeaseId);
    if (reservations) {
      for (const reservation of [...reservations]) {
        if (reservation.tokenGeneration !== currentTokenGeneration) {
          reservations.delete(reservation);
          this.pendingTunnels -= 1;
        }
      }
      if (reservations.size === 0) {
        this.reservationsByLease.delete(accessLeaseId);
      }
    }
    const tunnels = this.tunnelsByLease.get(accessLeaseId);
    if (!tunnels) {
      return;
    }
    for (const tunnel of [...tunnels]) {
      if (tunnel.tokenGeneration !== currentTokenGeneration) {
        tunnels.delete(tunnel);
        this.openTunnels -= 1;
        tunnel.client.destroy();
        tunnel.backend.destroy();
      }
    }
    if (tunnels.size === 0) {
      this.tunnelsByLease.delete(accessLeaseId);
    }
  }

  openTunnelCount(accessLeaseId: string): number {
    return this.tunnelsByLease.get(accessLeaseId)?.size ?? 0;
  }

  /** Every live lease-scoped tunnel, for the manager's /metrics gauge. */
  totalOpenTunnels(): number {
    return this.openTunnels;
  }

  pendingTunnelCount(): number {
    return this.pendingTunnels;
  }

  private consumeReservation(reservation: LeaseTunnelReservation): boolean {
    const reservations = this.reservationsByLease.get(reservation.accessLeaseId);
    if (!reservations?.delete(reservation)) {
      return false;
    }
    this.pendingTunnels -= 1;
    if (reservations.size === 0) {
      this.reservationsByLease.delete(reservation.accessLeaseId);
    }
    return true;
  }

  private deleteReservations(accessLeaseId: string): void {
    const reservations = this.reservationsByLease.get(accessLeaseId);
    if (!reservations) {
      return;
    }
    this.reservationsByLease.delete(accessLeaseId);
    this.pendingTunnels -= reservations.size;
  }
}

export type AuthorityRouteResolver = (
  authorityInstanceId: string
) => Pick<AuthorityDataPlaneRoute, "backendAddresses" | "backendAuthToken"> | null;

export class InMemoryAuthorityDataPlaneRouteTable implements AuthoritySessionRouteTable {
  private readonly routesBySessionToken = new Map<string, AuthorityDataPlaneRoute>();
  private readonly sessionTokensByInstanceId = new Map<string, Set<string>>();

  createSession(args: {
    authorityInstanceId: string;
    backendAddresses: string[];
    backendAuthToken: string;
    expiresAt?: number;
  }): { token: string; expiresAt?: number } {
    const token = `pfs_sess_${randomBytes(32).toString("base64url")}`;
    const route: AuthorityDataPlaneRoute = {
      authorityInstanceId: args.authorityInstanceId,
      backendAddresses: args.backendAddresses,
      backendAuthToken: args.backendAuthToken,
      ...(args.expiresAt !== undefined ? { sessionExpiresAt: args.expiresAt } : {}),
    };
    this.routesBySessionToken.set(token, route);
    const tokens = this.sessionTokensByInstanceId.get(args.authorityInstanceId) ?? new Set<string>();
    tokens.add(token);
    this.sessionTokensByInstanceId.set(args.authorityInstanceId, tokens);
    return {
      token,
      ...(args.expiresAt !== undefined ? { expiresAt: args.expiresAt } : {}),
    };
  }

  resolveSessionToken(token: string): AuthorityDataPlaneRoute | null {
    const route = this.routesBySessionToken.get(token);
    if (!route) {
      return null;
    }
    if (route.sessionExpiresAt !== undefined && route.sessionExpiresAt <= Date.now()) {
      this.routesBySessionToken.delete(token);
      this.sessionTokensByInstanceId.get(route.authorityInstanceId)?.delete(token);
      return null;
    }
    return route;
  }

  deleteAuthority(authorityInstanceId: string): void {
    const tokens = this.sessionTokensByInstanceId.get(authorityInstanceId);
    if (!tokens) {
      return;
    }
    for (const token of tokens) {
      this.routesBySessionToken.delete(token);
    }
    this.sessionTokensByInstanceId.delete(authorityInstanceId);
  }
}

export interface AuthorityDataPlaneRouterConfig {
  tlsCertPath?: string;
  tlsKeyPath?: string;
  // Inline PEM material (platforms whose secret stores inject env vars
  // rather than files — e.g. sealed variables). Exactly ONE source per
  // deployment: paths or PEMs, never a mix.
  tlsCertPem?: string;
  tlsKeyPem?: string;
  // Startup-resolved material. Production passes this exact object after
  // preflight so mutable certificate paths are never read a second time.
  tlsMaterial?: RouterTLSMaterial | null;
  transportMode?: string;
  tlsServerName?: string;
  tlsCaPath?: string;
  tlsCaPem?: string;
  allowPlaintextProduction?: boolean;
  // Startup-resolved immutable contract. main.ts supplies the exact object it
  // also gives the lease server so a mutable CA path cannot be read twice
  // into two different trust decisions.
  dataPlaneTransport?: DataPlaneTransport;
  handshakeTimeoutMs?: number;
  backendConnectTimeoutMs?: number;
  maxPendingConnections?: number;
  maxConnections?: number;
  // When set, lease-token tunnels are registered here so lease end and token
  // rotation can close them (see LeaseTunnelRegistry).
  tunnelRegistry?: LeaseTunnelRegistry;
}

export interface RouterTLSMaterial {
  cert: Buffer;
  key: Buffer;
}

function readExactlyOneOptionalSource(
  pathValue: string | undefined,
  inlineValue: string | undefined,
  pathLabel: string,
  pemLabel: string
): Buffer | null {
  const path = normalizeOptionalString(pathValue);
  const inline = inlineValue ?? "";
  const hasInline = inline.trim() !== "";
  if (path && hasInline) {
    throw new Error(`${pathLabel} and ${pemLabel} are mutually exclusive.`);
  }
  if (path) {
    const descriptor = openSync(path, "r");
    try {
      const buffer = Buffer.allocUnsafe(MAX_ROUTER_CA_BYTES + 1);
      let offset = 0;
      while (offset < buffer.length) {
        const count = readSync(descriptor, buffer, offset, buffer.length - offset, null);
        if (count === 0) {
          break;
        }
        offset += count;
      }
      return Buffer.from(buffer.subarray(0, offset));
    } finally {
      closeSync(descriptor);
    }
  }
  if (hasInline && Buffer.byteLength(inline, "utf8") > MAX_ROUTER_CA_BYTES) {
    throw new Error(`PortableFS data-plane private CA exceeds ${MAX_ROUTER_CA_BYTES} bytes.`);
  }
  return hasInline ? Buffer.from(inline, "utf8") : null;
}

export function validateStrictCertificatePEM(data: Buffer): void {
  parseStrictCertificatePEM(data, "PortableFS data-plane private CA", MAX_ROUTER_CA_BYTES);
}

function parseStrictCertificatePEM(
  data: Buffer,
  label: string,
  maxBytes: number
): X509Certificate[] {
  if (data.length === 0 || data.length > maxBytes) {
    throw new Error(
      `${label} must contain 1-${maxBytes} bytes.`
    );
  }
  const text = data.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(data)) {
    throw new Error(`${label} must be valid UTF-8 PEM.`);
  }
  const expression = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu;
  let cursor = 0;
  const certificates: X509Certificate[] = [];
  for (const match of text.matchAll(expression)) {
    const index = match.index;
    if (index === undefined || text.slice(cursor, index).trim() !== "") {
      throw new Error(`${label} contains data outside CERTIFICATE PEM blocks.`);
    }
    const block = match[0];
    try {
      certificates.push(new X509Certificate(block));
    } catch (error) {
      throw new Error(
        `${label} certificate ${certificates.length + 1} is invalid: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    cursor = index + block.length;
  }
  if (certificates.length === 0 || text.slice(cursor).trim() !== "") {
    throw new Error(
      certificates.length === 0
        ? `${label} contains no certificates.`
        : `${label} contains data outside CERTIFICATE PEM blocks.`
    );
  }
  return certificates;
}

export function validateDataPlaneServerName(serverName: string): void {
  if (
    serverName.length === 0 ||
    serverName.length > 253 ||
    serverName !== serverName.trim() ||
    /[\u0000-\u0020/\\]/u.test(serverName) ||
    serverName.includes("%") ||
    serverName.startsWith("[") ||
    serverName.endsWith("]")
  ) {
    throw new Error("PortableFS data-plane TLS server name is not a valid DNS name or IP address.");
  }
  if (isIP(serverName) !== 0) {
    return;
  }
  const validDNS = serverName.split(".").every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-") &&
      /^[A-Za-z0-9-]+$/u.test(label)
  );
  if (!validDNS) {
    throw new Error("PortableFS data-plane TLS server name is not a valid DNS name or IP address.");
  }
}

// Resolves the exact lease-bound transport advertised by the production
// manager. It uses the same router configuration that controls the listener,
// and never infers plaintext from missing TLS material.
export function resolveDataPlaneTransportContract(config: {
  transportMode?: string;
  tlsServerName?: string;
  tlsCaPath?: string;
  tlsCaPem?: string;
  allowPlaintextProduction?: boolean;
}): DataPlaneTransport {
  const mode = normalizeOptionalString(config.transportMode);
  const serverName = normalizeOptionalString(config.tlsServerName);
  const ca = readExactlyOneOptionalSource(
    config.tlsCaPath,
    config.tlsCaPem,
    "PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PATH",
    "PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PEM"
  );
  switch (mode) {
    case "tls-private-ca": {
      if (!serverName) {
        throw new Error(
          "tls-private-ca requires PORTABLEFS_AUTHORITY_ROUTER_TLS_SERVER_NAME."
        );
      }
      validateDataPlaneServerName(serverName);
      if (!ca) {
        throw new Error(
          "tls-private-ca requires exactly one of PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PATH or PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PEM."
        );
      }
      const anchors = parseStrictCertificatePEM(
        ca,
        "PortableFS data-plane private CA",
        MAX_ROUTER_CA_BYTES
      );
      const anchorFingerprints = new Set<string>();
      for (const [index, anchor] of anchors.entries()) {
        if (!anchor.ca) {
          throw new Error(
            `PortableFS data-plane private CA certificate ${index + 1} is not a CA certificate.`
          );
        }
        if (anchorFingerprints.has(anchor.fingerprint256)) {
          throw new Error(
            `PortableFS data-plane private CA repeats certificate ${index + 1}.`
          );
        }
        anchorFingerprints.add(anchor.fingerprint256);
      }
      return {
        mode,
        serverName,
        caPem: ca.toString("utf8"),
        caSha256: createHash("sha256").update(ca).digest("hex"),
      };
    }
    case "tls-system-pki":
      if (!serverName) {
        throw new Error(
          "tls-system-pki requires PORTABLEFS_AUTHORITY_ROUTER_TLS_SERVER_NAME."
        );
      }
      validateDataPlaneServerName(serverName);
      if (ca) {
        throw new Error(
          "tls-system-pki must not configure PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PATH or PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PEM."
        );
      }
      return { mode, serverName };
    case "plaintext":
      if (!config.allowPlaintextProduction) {
        throw new Error(
          "plaintext requires PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION=1."
        );
      }
      if (serverName || ca) {
        throw new Error("plaintext must not configure a TLS server name or private CA.");
      }
      return { mode };
    case "":
      throw new Error(
        "PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE is required (tls-private-ca, tls-system-pki, or plaintext)."
      );
    default:
      throw new Error(
        `PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE must be tls-private-ca, tls-system-pki, or plaintext; got ${mode}.`
      );
  }
}

// resolveRouterTlsMaterial answers the router's TLS cert/key bytes from
// exactly one configured source (file paths or inline PEMs), null when TLS
// is not configured, and throws on every ambiguous or half-configured shape.
export function resolveRouterTlsMaterial(config: {
  tlsCertPath?: string;
  tlsKeyPath?: string;
  tlsCertPem?: string;
  tlsKeyPem?: string;
}): RouterTLSMaterial | null {
  const certPath = normalizeOptionalString(config.tlsCertPath);
  const keyPath = normalizeOptionalString(config.tlsKeyPath);
  const certPem = normalizeOptionalString(config.tlsCertPem);
  const keyPem = normalizeOptionalString(config.tlsKeyPem);
  if ((certPath || keyPath) && (certPem || keyPem)) {
    throw new Error(
      "PortableFS data-plane router TLS accepts file paths OR inline PEMs, never both (remove PORTABLEFS_AUTHORITY_ROUTER_TLS_*_PATH or PORTABLEFS_AUTHORITY_ROUTER_TLS_*_PEM)."
    );
  }
  if (certPem || keyPem) {
    if (!certPem || !keyPem) {
      throw new Error(
        "PortableFS data-plane router TLS requires both PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM and PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PEM."
      );
    }
    const cert = Buffer.from(certPem, "utf8");
    const key = Buffer.from(keyPem, "utf8");
    validateTLSMaterialSize(cert, "router TLS certificate chain");
    validateTLSMaterialSize(key, "router TLS private key");
    return { cert, key };
  }
  if (certPath || keyPath) {
    if (!certPath || !keyPath) {
      throw new Error(
        "PortableFS data-plane router TLS requires both PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH and PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PATH."
      );
    }
    return {
      cert: readBoundedFile(certPath, "router TLS certificate chain"),
      key: readBoundedFile(keyPath, "router TLS private key"),
    };
  }
  return null;
}

function readBoundedFile(path: string, label: string): Buffer {
  const descriptor = openSync(path, "r");
  try {
    const buffer = Buffer.allocUnsafe(MAX_ROUTER_TLS_MATERIAL_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(descriptor, buffer, offset, buffer.length - offset, null);
      if (count === 0) {
        break;
      }
      offset += count;
    }
    const data = Buffer.from(buffer.subarray(0, offset));
    validateTLSMaterialSize(data, label);
    return data;
  } finally {
    closeSync(descriptor);
  }
}

function validateTLSMaterialSize(data: Buffer, label: string): void {
  if (data.length === 0 || data.length > MAX_ROUTER_TLS_MATERIAL_BYTES) {
    throw new Error(`${label} must contain 1-${MAX_ROUTER_TLS_MATERIAL_BYTES} bytes.`);
  }
}

function parseStrictPrivateKey(data: Buffer) {
  validateTLSMaterialSize(data, "router TLS private key");
  const text = data.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(data)) {
    throw new Error("router TLS private key must be valid UTF-8 PEM.");
  }
  const expression =
    /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/gu;
  const matches = [...text.matchAll(expression)];
  if (
    matches.length !== 1 ||
    matches[0]!.index === undefined ||
    text.slice(0, matches[0]!.index).trim() !== "" ||
    text.slice(matches[0]!.index! + matches[0]![0].length).trim() !== ""
  ) {
    throw new Error(
      "router TLS private key must contain exactly one unencrypted PRIVATE KEY PEM block and no other data."
    );
  }
  try {
    return createPrivateKey(matches[0]![0]);
  } catch (error) {
    throw new Error(
      `router TLS private key is invalid: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

// Performs the synchronous portion of the startup proof: exact PEM shape,
// leaf/private-key agreement, leaf hostname, validity, server EKU, and an
// ordered, signature-valid served intermediate chain.
export function validateRouterTLSIdentity(
  tls: RouterTLSMaterial,
  transport: Exclude<DataPlaneTransport, { mode: "plaintext" }>
): void {
  const certificates = parseStrictCertificatePEM(
    tls.cert,
    "router TLS certificate chain",
    MAX_ROUTER_TLS_MATERIAL_BYTES
  );
  const [leaf] = certificates;
  if (!leaf || leaf.ca) {
    throw new Error("router TLS certificate chain must begin with one non-CA serving leaf.");
  }
  const privateKey = parseStrictPrivateKey(tls.key);
  if (!leaf.checkPrivateKey(privateKey)) {
    throw new Error("router TLS private key does not match the serving leaf certificate.");
  }
  const nameMatch =
    isIP(transport.serverName) !== 0
      ? leaf.checkIP(transport.serverName)
      : leaf.checkHost(transport.serverName, {
          // Match Go x509.VerifyHostname: SAN-only, a wildcard must occupy
          // the complete left-most label, and it matches exactly one label.
          subject: "never",
          wildcards: true,
          partialWildcards: false,
          multiLabelWildcards: false,
          singleLabelSubdomains: false,
        });
  if (!nameMatch) {
    throw new Error(
      `router TLS serving leaf does not match advertised serverName ${transport.serverName}.`
    );
  }
  const now = Date.now();
  const seen = new Set<string>();
  for (let index = 0; index < certificates.length; index += 1) {
    const certificate = certificates[index]!;
    if (seen.has(certificate.fingerprint256)) {
      throw new Error(`router TLS certificate chain repeats certificate ${index + 1}.`);
    }
    seen.add(certificate.fingerprint256);
    if (
      certificate.validFromDate.getTime() > now ||
      certificate.validToDate.getTime() < now
    ) {
      throw new Error(`router TLS certificate ${index + 1} is not currently valid.`);
    }
  }
  for (let index = 0; index < certificates.length - 1; index += 1) {
    const certificate = certificates[index]!;
    const issuer = certificates[index + 1];
    if (
      issuer &&
      (!issuer.ca || !certificate.checkIssued(issuer) || !certificate.verify(issuer.publicKey))
    ) {
      throw new Error(
        `router TLS certificate chain is not an ordered signature-valid leaf-to-issuer chain at certificate ${index + 1}.`
      );
    }
  }
  const serverAuthOID = "1.3.6.1.5.5.7.3.1";
  const anyExtendedKeyUsageOID = "2.5.29.37.0";
  if (
    leaf.keyUsage.length > 0 &&
    !leaf.keyUsage.includes(serverAuthOID) &&
    !leaf.keyUsage.includes(anyExtendedKeyUsageOID)
  ) {
    throw new Error("router TLS serving leaf is not valid for TLS server authentication.");
  }
  // OpenSSL's server context construction is the final synchronous key/cert
  // parser and algorithm compatibility check used by the actual listener.
  createSecureContext({ cert: tls.cert, key: tls.key, minVersion: "TLSv1.3" });
}

// Production awaits this gate before publishing the real router listener.
// Both TLS modes perform a real local TLS 1.3 handshake through OpenSSL so
// path constraints, EKU, signatures, validity, and trust anchors are
// exercised. Private mode uses the exact lease CA; system mode uses Node's
// current default roots. The latter is a strong local gate, not a claim that
// every remote Go/Swift platform has an identical root snapshot.
export async function preflightAuthorityDataPlaneRouterTLS(
  tls: RouterTLSMaterial | null,
  transport: DataPlaneTransport
): Promise<void> {
  if (transport.mode === "plaintext") {
    if (tls) {
      throw new Error("plaintext transport must not configure router TLS certificate material.");
    }
    return;
  }
  if (!tls) {
    throw new Error(`${transport.mode} requires router TLS certificate material.`);
  }
  validateRouterTLSIdentity(tls, transport);
  await preflightTLSTrust(tls, transport);
}

async function preflightTLSTrust(
  tls: RouterTLSMaterial,
  transport: Exclude<DataPlaneTransport, { mode: "plaintext" }>
): Promise<void> {
  const trustLabel =
    transport.mode === "tls-private-ca" ? "private-CA" : "system-PKI";
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let client: TLSSocket | undefined;
    const server = createTlsServer(
      { cert: tls.cert, key: tls.key, minVersion: "TLSv1.3" },
      (socket) => socket.end()
    );
    const timeout = setTimeout(
      () => finish(new Error(`router TLS ${trustLabel} preflight timed out.`)),
      TLS_PREFLIGHT_TIMEOUT_MS
    );
    timeout.unref?.();

    const finish = (error?: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      client?.destroy();
      const complete = () =>
        error
          ? reject(new Error(`router TLS ${trustLabel} trust preflight failed: ${error.message}`))
          : resolve();
      if (server.listening) {
        server.close(() => complete());
      } else {
        complete();
      }
    };

    server.once("error", (error) => finish(error));
    server.once("tlsClientError", (error) => finish(error));
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo | null;
      if (!address) {
        finish(new Error("preflight listener did not publish an address"));
        return;
      }
      client = connectTLS(
        {
          host: "127.0.0.1",
          port: address.port,
          ...(isIP(transport.serverName) === 0
            ? { servername: transport.serverName }
            : {}),
          ...(transport.mode === "tls-private-ca"
            ? {
                ca: transport.caPem,
                allowPartialTrustChain: true,
              }
            : {}),
          minVersion: "TLSv1.3",
          rejectUnauthorized: true,
          // Exact hostname/IP matching was already proven against the leaf
          // with X509Certificate.checkHost/checkIP above. Keep this handshake
          // dedicated to OpenSSL's trust-path and TLS-purpose validation.
          checkServerIdentity: () => undefined,
        },
        () => finish()
      );
      client.once("error", (error) => finish(error));
    });
  });
}

export function createAuthorityDataPlaneRouterServer(
  routeTable: AuthorityDataPlaneRouteTable,
  config: AuthorityDataPlaneRouterConfig = {}
): Server {
  const maxPendingConnections = positiveSafeInteger(
    config.maxPendingConnections ?? DEFAULT_MAX_PENDING_CONNECTIONS,
    "maxPendingConnections"
  );
  const maxConnections = positiveSafeInteger(
    config.maxConnections ?? DEFAULT_MAX_PENDING_CONNECTIONS + DEFAULT_MAX_OPEN_TUNNELS,
    "maxConnections"
  );
  let pendingConnections = 0;
  const handler = (socket: Socket) => {
    if (pendingConnections >= maxPendingConnections) {
      socket.destroy();
      return;
    }
    pendingConnections += 1;
    void handleClient(socket, routeTable, config).finally(() => {
      pendingConnections -= 1;
    });
  };

  const tls =
    config.tlsMaterial !== undefined ? config.tlsMaterial : resolveRouterTlsMaterial(config);
  if (normalizeOptionalString(config.transportMode) || config.dataPlaneTransport) {
    const transport = config.dataPlaneTransport ?? resolveDataPlaneTransportContract(config);
    if (
      normalizeOptionalString(config.transportMode) &&
      transport.mode !== normalizeOptionalString(config.transportMode)
    ) {
      throw new Error("resolved data-plane transport mode does not match router transport mode.");
    }
    if (transport.mode === "plaintext" && tls) {
      throw new Error("plaintext transport must not configure router TLS certificate material.");
    }
    if (transport.mode !== "plaintext" && !tls) {
      throw new Error(`${transport.mode} requires router TLS certificate material.`);
    }
    if (transport.mode !== "plaintext" && tls) {
      validateRouterTLSIdentity(tls, transport);
    }
  }
  let server: Server;
  if (tls) {
    server = createTlsServer(
      {
        cert: tls.cert,
        key: tls.key,
        minVersion: "TLSv1.3",
        handshakeTimeout: config.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS,
      },
      handler
    );
  } else {
    server = createNetServer(handler);
  }
  server.maxConnections = maxConnections;
  return server;
}

export function validateAuthorityDataPlaneRouterConfig(args: {
  listenAddr?: string;
  publicUrl?: string;
  tlsCertPath?: string;
  tlsKeyPath?: string;
  tlsCertPem?: string;
  tlsKeyPem?: string;
  transportMode?: string;
  tlsServerName?: string;
  tlsCaPath?: string;
  tlsCaPem?: string;
  allowPlaintextProduction?: boolean;
}): DataPlaneTransport {
  const listenAddr = args.listenAddr;
  if (!listenAddr || listenAddr.trim() === "") {
    throw new Error("PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR is required.");
  }
  parseAuthorityAddress(listenAddr, {
    label: "PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR",
  });
  const publicUrl = args.publicUrl;
  if (!publicUrl || publicUrl.trim() === "") {
    throw new Error("PORTABLEFS_AUTHORITY_ROUTER_URL is required.");
  }
  parseAuthorityAddress(publicUrl, {
    label: "PORTABLEFS_AUTHORITY_ROUTER_URL",
    allowedSchemes: ["tcp", "fsproto"],
  });
  const certPath = Boolean(normalizeOptionalString(args.tlsCertPath));
  const keyPath = Boolean(normalizeOptionalString(args.tlsKeyPath));
  const certPem = Boolean(normalizeOptionalString(args.tlsCertPem));
  const keyPem = Boolean(normalizeOptionalString(args.tlsKeyPem));
  if ((certPath || keyPath) && (certPem || keyPem)) {
    throw new Error(
      "PortableFS data-plane router TLS accepts file paths OR inline PEMs, never both (remove PORTABLEFS_AUTHORITY_ROUTER_TLS_*_PATH or PORTABLEFS_AUTHORITY_ROUTER_TLS_*_PEM)."
    );
  }
  if (certPath !== keyPath) {
    throw new Error(
      "PortableFS data-plane router TLS requires both PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH and PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PATH."
    );
  }
  if (certPem !== keyPem) {
    throw new Error(
      "PortableFS data-plane router TLS requires both PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM and PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PEM."
    );
  }
  const hasTls = certPath || certPem;
  const transport = resolveDataPlaneTransportContract(args);
  if (transport.mode === "plaintext" && hasTls) {
    throw new Error("plaintext transport must not configure router TLS certificate material.");
  }
  if (transport.mode !== "plaintext" && !hasTls) {
    throw new Error(
      `${transport.mode} requires router TLS certificate material (PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH/KEY_PATH or PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM/KEY_PEM).`
    );
  }
  return transport;
}

async function handleClient(
  client: Socket,
  routeTable: AuthorityDataPlaneRouteTable,
  config: AuthorityDataPlaneRouterConfig
): Promise<void> {
  const handshakeTimeoutMs = config.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  let backend: Socket | undefined;
  let reservation: LeaseTunnelReservation | undefined;
  try {
    const sessionToken = await readTokenFrame(client, handshakeTimeoutMs);
    const route = routeTable.resolveSessionToken(sessionToken);
    if (!route) {
      // The ONLY credential verdict this router makes: the token resolves to
      // no route at all (manager restart, rotation, release, revoke, expiry).
      await rejectClient(client, AckCode.CredentialRejected);
      return;
    }
    if (route.accessLeaseId !== undefined && config.tunnelRegistry) {
      reservation =
        config.tunnelRegistry.reserve(
          route.accessLeaseId,
          route.tokenGeneration ?? "1"
        ) ?? undefined;
      if (!reservation) {
        // The token resolved. The lease simply has no tunnel slot left.
        await rejectClient(client, AckCode.AtCapacity);
        return;
      }
    }
    let connectedBackend: Socket;
    try {
      connectedBackend = await connectBackend(route, {
        connectTimeoutMs: config.backendConnectTimeoutMs ?? DEFAULT_BACKEND_CONNECT_TIMEOUT_MS,
        handshakeTimeoutMs,
      });
    } catch {
      // The credential was good enough to route; there is no authority behind
      // it right now. Answering rather than closing silently is the difference
      // between the client reading an authority-side outage and the client
      // guessing at a dead credential.
      await rejectClient(client, AckCode.AuthorityUnavailable);
      return;
    }
    backend = connectedBackend;
    if (reservation && config.tunnelRegistry) {
      // The lease may have ended or rotated while the backend dial awaited
      // (its events fire only for already-registered tunnels). Re-resolve and
      // register synchronously before admitting, so no lease transition can
      // slip between the check and the registration.
      const revalidated = routeTable.resolveSessionToken(sessionToken);
      if (
        !revalidated ||
        revalidated.accessLeaseId !== route.accessLeaseId ||
        revalidated.tokenGeneration !== route.tokenGeneration
      ) {
        // The lease ended or rotated WHILE the backend dial awaited. The
        // token the client offered was live when it offered it; a race is not
        // a dead credential, and the next dial with a current credential is
        // what settles which.
        connectedBackend.destroy();
        await rejectClient(client, AckCode.LeaseTransition);
        return;
      }
      if (!config.tunnelRegistry.registerReserved(reservation, client, connectedBackend)) {
        // The reservation could not be consumed: a socket died during the
        // backend dial, or a rotation sweep took it. Same class of race.
        connectedBackend.destroy();
        await rejectClient(client, AckCode.LeaseTransition);
        return;
      }
      reservation = undefined;
    }
    await acceptClient(client);
    client.pipe(connectedBackend);
    connectedBackend.pipe(client);
    connectedBackend.once("error", () => client.destroy());
    client.once("error", () => connectedBackend.destroy());
  } catch {
    client.destroy();
    backend?.destroy();
  } finally {
    if (reservation && config.tunnelRegistry) {
      config.tunnelRegistry.releaseReservation(reservation);
    }
  }
}

function positiveIntegerEnv(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number
): number {
  const raw = env[name]?.trim();
  if (!raw) {
    return fallback;
  }
  return positiveSafeInteger(Number(raw), name);
}

function positiveSafeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer.`);
  }
  return value;
}

async function connectBackend(
  route: AuthorityDataPlaneRoute,
  options: { connectTimeoutMs: number; handshakeTimeoutMs: number }
): Promise<Socket> {
  let lastError: unknown;
  for (const address of route.backendAddresses) {
    let socket: Socket | undefined;
    try {
      socket = await connectSocket(address, options.connectTimeoutMs);
      await writeBackendTokenFrame(socket, route.backendAuthToken, options.handshakeTimeoutMs);
      return socket;
    } catch (error) {
      socket?.destroy();
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("No backend VCS authority is reachable.");
}

async function connectSocket(address: string, timeoutMs: number): Promise<Socket> {
  const { host, port } = parseHostPort(address);
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port });
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Timed out connecting to ${address}.`));
    }, timeoutMs);
    timeout.unref?.();
    socket.once("connect", () => {
      clearTimeout(timeout);
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

async function readTokenFrame(socket: Socket, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("PortableFS data-plane handshake timed out."));
    }, timeoutMs);
    timeout.unref?.();
    const cleanup = () => {
      clearTimeout(timeout);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("end", onEnd);
    };
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength < 2) {
        return;
      }
      const length = buffer.readUInt16BE(0);
      if (length > MAX_TOKEN_BYTES) {
        cleanup();
        reject(new Error("PortableFS data-plane session token is too large."));
        return;
      }
      const frameLength = 2 + length;
      if (buffer.byteLength < frameLength) {
        return;
      }
      const token = buffer.subarray(2, frameLength).toString("utf8");
      const extra = buffer.subarray(frameLength);
      cleanup();
      if (extra.byteLength > 0) {
        socket.unshift(extra);
      }
      resolve(token);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onEnd = () => {
      cleanup();
      reject(new Error("PortableFS data-plane handshake ended early."));
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("end", onEnd);
  });
}

async function writeBackendTokenFrame(
  socket: Socket,
  token: string,
  timeoutMs: number
): Promise<void> {
  const tokenBytes = Buffer.from(token);
  if (tokenBytes.byteLength > MAX_TOKEN_BYTES) {
    throw new Error("PortableFS backend auth token is too large.");
  }
  const header = Buffer.alloc(2);
  header.writeUInt16BE(tokenBytes.byteLength, 0);
  socket.write(Buffer.concat([header, tokenBytes]));
  const ack = await readExactly(socket, 1, timeoutMs);
  if (ack[0] !== 0) {
    throw new Error("PortableFS backend authority rejected the router handshake.");
  }
}

async function acceptClient(socket: Socket): Promise<void> {
  await writeAll(socket, Buffer.from([AckCode.Admitted]));
}

// rejectClient answers the exact refusal and closes. The code is REQUIRED:
// there is no such thing here as a refusal whose reason the router does not
// know, and defaulting one would put the old lie back.
async function rejectClient(socket: Socket, code: AckCodeValue): Promise<void> {
  await writeAll(socket, Buffer.from([code])).catch(() => undefined);
  socket.destroy();
}

function writeAll(socket: Socket, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(data, (error) => (error ? reject(error) : resolve()));
  });
}

function readExactly(socket: Socket, byteCount: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("PortableFS data-plane handshake timed out."));
    }, timeoutMs);
    timeout.unref?.();
    const cleanup = () => {
      clearTimeout(timeout);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("end", onEnd);
    };

    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength < byteCount) {
        return;
      }
      const needed = buffer.subarray(0, byteCount);
      const extra = buffer.subarray(byteCount);
      cleanup();
      if (extra.byteLength > 0) {
        socket.unshift(extra);
      }
      resolve(needed);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onEnd = () => {
      cleanup();
      reject(new Error("PortableFS data-plane handshake ended early."));
    };

    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("end", onEnd);
  });
}

function parseHostPort(address: string): { host: string; port: number } {
  return parseAuthorityAddress(address, { label: "PortableFS backend address" });
}

function timingSafeStringEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}

function normalizeOptionalString(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
}

export const testInternals = {
  timingSafeStringEqual,
};
