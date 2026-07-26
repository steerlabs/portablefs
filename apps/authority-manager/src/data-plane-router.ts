import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer as createNetServer, connect, type Server, type Socket } from "node:net";
import { createServer as createTlsServer } from "node:tls";

const MAX_TOKEN_BYTES = 4096;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5_000;
const DEFAULT_BACKEND_CONNECT_TIMEOUT_MS = 5_000;

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

export class LeaseTunnelRegistry {
  private readonly tunnelsByLease = new Map<string, Set<LeaseTunnel>>();

  register(
    accessLeaseId: string,
    tokenGeneration: string,
    client: Socket,
    backend: Socket
  ): void {
    const tunnel: LeaseTunnel = { tokenGeneration, client, backend };
    const tunnels = this.tunnelsByLease.get(accessLeaseId) ?? new Set<LeaseTunnel>();
    tunnels.add(tunnel);
    this.tunnelsByLease.set(accessLeaseId, tunnels);
    const remove = () => {
      const set = this.tunnelsByLease.get(accessLeaseId);
      if (!set) {
        return;
      }
      set.delete(tunnel);
      if (set.size === 0) {
        this.tunnelsByLease.delete(accessLeaseId);
      }
    };
    client.once("close", remove);
    backend.once("close", remove);
  }

  closeLease(accessLeaseId: string): void {
    const tunnels = this.tunnelsByLease.get(accessLeaseId);
    if (!tunnels) {
      return;
    }
    this.tunnelsByLease.delete(accessLeaseId);
    for (const tunnel of tunnels) {
      tunnel.client.destroy();
      tunnel.backend.destroy();
    }
  }

  // closeSupersededGenerations closes every tunnel for the lease that was
  // admitted under a token generation other than the current one (rotation
  // fencing, both directions).
  closeSupersededGenerations(accessLeaseId: string, currentTokenGeneration: string): void {
    const tunnels = this.tunnelsByLease.get(accessLeaseId);
    if (!tunnels) {
      return;
    }
    for (const tunnel of [...tunnels]) {
      if (tunnel.tokenGeneration !== currentTokenGeneration) {
        tunnels.delete(tunnel);
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
    let total = 0;
    for (const tunnels of this.tunnelsByLease.values()) {
      total += tunnels.size;
    }
    return total;
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
  handshakeTimeoutMs?: number;
  backendConnectTimeoutMs?: number;
  // When set, lease-token tunnels are registered here so lease end and token
  // rotation can close them (see LeaseTunnelRegistry).
  tunnelRegistry?: LeaseTunnelRegistry;
}

// resolveRouterTlsMaterial answers the router's TLS cert/key bytes from
// exactly one configured source (file paths or inline PEMs), null when TLS
// is not configured, and throws on every ambiguous or half-configured shape.
export function resolveRouterTlsMaterial(config: {
  tlsCertPath?: string;
  tlsKeyPath?: string;
  tlsCertPem?: string;
  tlsKeyPem?: string;
}): { cert: Buffer; key: Buffer } | null {
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
    return { cert: Buffer.from(certPem, "utf8"), key: Buffer.from(keyPem, "utf8") };
  }
  if (certPath || keyPath) {
    if (!certPath || !keyPath) {
      throw new Error(
        "PortableFS data-plane router TLS requires both PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH and PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PATH."
      );
    }
    return { cert: readFileSync(certPath), key: readFileSync(keyPath) };
  }
  return null;
}

export function createAuthorityDataPlaneRouterServer(
  routeTable: AuthorityDataPlaneRouteTable,
  config: AuthorityDataPlaneRouterConfig = {}
): Server {
  const handler = (socket: Socket) => {
    void handleClient(socket, routeTable, config);
  };

  const tls = resolveRouterTlsMaterial(config);
  if (tls) {
    return createTlsServer(
      {
        cert: tls.cert,
        key: tls.key,
        minVersion: "TLSv1.3",
      },
      handler
    );
  }

  return createNetServer(handler);
}

export function validateAuthorityDataPlaneRouterConfig(args: {
  authorityMode: "env" | "production";
  listenAddr?: string;
  publicUrl?: string;
  tlsCertPath?: string;
  tlsKeyPath?: string;
  tlsCertPem?: string;
  tlsKeyPem?: string;
  allowPlaintextProduction?: boolean;
}): void {
  if (!normalizeOptionalString(args.listenAddr)) {
    throw new Error("PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR is required.");
  }
  if (!normalizeOptionalString(args.publicUrl)) {
    throw new Error("PORTABLEFS_AUTHORITY_ROUTER_URL is required.");
  }
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
  if (args.authorityMode === "production" && !hasTls && !args.allowPlaintextProduction) {
    throw new Error(
      "Router TLS (PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH/KEY_PATH or PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM/KEY_PEM) is required in production; set PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION=1 only behind an authenticated private tunnel."
    );
  }
}

async function handleClient(
  client: Socket,
  routeTable: AuthorityDataPlaneRouteTable,
  config: AuthorityDataPlaneRouterConfig
): Promise<void> {
  const handshakeTimeoutMs = config.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  try {
    const sessionToken = await readTokenFrame(client, handshakeTimeoutMs);
    const route = routeTable.resolveSessionToken(sessionToken);
    if (!route) {
      await rejectClient(client);
      return;
    }
    const backend = await connectBackend(route, {
      connectTimeoutMs: config.backendConnectTimeoutMs ?? DEFAULT_BACKEND_CONNECT_TIMEOUT_MS,
      handshakeTimeoutMs,
    });
    if (route.accessLeaseId !== undefined && config.tunnelRegistry) {
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
        backend.destroy();
        await rejectClient(client);
        return;
      }
      config.tunnelRegistry.register(
        route.accessLeaseId,
        route.tokenGeneration ?? "1",
        client,
        backend
      );
    }
    await acceptClient(client);
    client.pipe(backend);
    backend.pipe(client);
    backend.once("error", () => client.destroy());
    client.once("error", () => backend.destroy());
  } catch {
    client.destroy();
  }
}

async function connectBackend(
  route: AuthorityDataPlaneRoute,
  options: { connectTimeoutMs: number; handshakeTimeoutMs: number }
): Promise<Socket> {
  let lastError: unknown;
  for (const address of route.backendAddresses) {
    try {
      const socket = await connectSocket(address, options.connectTimeoutMs);
      await writeBackendTokenFrame(socket, route.backendAuthToken, options.handshakeTimeoutMs);
      return socket;
    } catch (error) {
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
  await writeAll(socket, Buffer.from([0]));
}

async function rejectClient(socket: Socket): Promise<void> {
  await writeAll(socket, Buffer.from([1])).catch(() => undefined);
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
  const [host, portText] = address.trim().split(":");
  const port = portText ? Number(portText) : NaN;
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PortableFS backend address: ${address}`);
  }
  return { host, port };
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
