import type { IncomingMessage, ServerResponse } from "node:http";
import {
  historyMaterializerVersion,
  MetadataConflictError,
  type MetadataRepository,
  type PostgresHistoryRepository,
} from "@portablefs/metadata-db";

// ---------------------------------------------------------------------------
// Admin HistoryCut routes (migration 013 machinery). ADDITIVE and INTERNAL:
// everything lives under /v1/admin/history/*, admin-token-gated by the
// central tenant guard in server.ts before dispatch reaches this module.
// These are the SAME pfh caller functions the journal-bounding maintenance
// loop drives automatically (history-maintenance.ts), exposed so operators
// can drive and inspect the machinery manually: create a recovery cut, poll
// its status, adopt it. The database owns idempotency (permanent resource
// operations keyed by the caller's operationId), linearization, and
// authorization — these handlers only shape JSON.
//
// A repository without the 013 history surface answers 501
// HISTORY_UNAVAILABLE, never a half-configured behavior.
// ---------------------------------------------------------------------------

export interface AdminHistoryRouteContext {
  metadata: MetadataRepository;
  maxBodyBytes: number;
}

export async function routeAdminHistoryRequest(
  req: IncomingMessage,
  res: ServerResponse,
  deps: AdminHistoryRouteContext,
  url: URL,
  parts: string[]
): Promise<void> {
  const history = (deps.metadata as { history?: PostgresHistoryRepository }).history;
  if (!history) {
    sendJson(res, 501, {
      error: {
        code: "HISTORY_UNAVAILABLE",
        message: "This deployment's metadata repository has no history surface.",
      },
    });
    return;
  }
  const method = req.method ?? "GET";
  // parts: ["v1","admin","history", ...rest]
  const rest = parts.slice(3);

  try {
    if (method === "POST" && rest.length === 1 && rest[0] === "cuts") {
      const body = await readJson(req, deps.maxBodyBytes);
      const cut = await history.createCut({
        tenantId: requireString(body, "tenantId"),
        volumeId: requireString(body, "volumeId"),
        branchName: requireString(body, "branchName"),
        kind: requireCutKind(body),
        operationId: requireString(body, "operationId"),
        requestCanonicalJson: JSON.stringify(body),
        materializerVersion:
          optionalString(body, "materializerVersion") ?? historyMaterializerVersion,
      });
      sendJson(res, 200, { cut });
      return;
    }
    if (method === "GET" && rest.length === 2 && rest[0] === "cuts") {
      const cut = await history.cutStatus(requireQuery(url, "tenantId"), rest[1]!);
      if (!cut) {
        sendJson(res, 404, { error: { code: "HISTORY_CUT_NOT_FOUND", message: "No such cut." } });
        return;
      }
      sendJson(res, 200, { cut });
      return;
    }
    if (method === "POST" && rest.length === 3 && rest[0] === "cuts" && rest[2] === "adopt") {
      const body = await readJson(req, deps.maxBodyBytes);
      const outcome = await history.adoptCut({
        tenantId: requireString(body, "tenantId"),
        cutId: rest[1]!,
        anchorId: requireString(body, "anchorId"),
        operationId: requireString(body, "operationId"),
        requestCanonicalJson: JSON.stringify(body),
        servingCapability: requireString(body, "servingCapability"),
      });
      sendJson(res, 200, outcome);
      return;
    }
    sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Route not found." } });
  } catch (error) {
    sendHistoryError(res, error);
  }
}

// The pfh functions raise typed PF0xx SQLSTATEs; surface them as structured
// conflicts instead of opaque 500s.
function sendHistoryError(res: ServerResponse, error: unknown): void {
  if (error instanceof MetadataConflictError) {
    sendJson(res, error.status, { error: { code: error.code, message: error.message } });
    return;
  }
  const pgError = error as { code?: string; message?: string };
  if (typeof pgError?.code === "string" && pgError.code.startsWith("PF")) {
    const status =
      pgError.code === "PF007"
        ? 404
        : pgError.code === "PF001" || pgError.code === "PF002"
          ? 409
          : 400;
    sendJson(res, status, {
      error: { code: `HISTORY_${pgError.code}`, message: pgError.message ?? "History conflict." },
    });
    return;
  }
  // Do not echo raw internal error text (Postgres/driver detail, paths) to the
  // caller; log it server-side and return a fixed message.
  console.error("volume-api history internal error:", error);
  sendJson(res, 500, {
    error: { code: "HISTORY_INTERNAL", message: "Internal error." },
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (res.headersSent) {
    return;
  }
  const payload = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(payload);
}

async function readJson(req: IncomingMessage, maxBytes: number): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.byteLength;
    if (total > maxBytes) {
      throw new MetadataConflictError("VOLUME_BODY_TOO_LARGE", "Request body too large.", 413);
    }
    chunks.push(buffer);
  }
  if (total === 0) {
    return {};
  }
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new MetadataConflictError("VOLUME_BODY_INVALID", "Request body must be an object.", 400);
  }
  return parsed as Record<string, unknown>;
}

function requireString(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new MetadataConflictError(
      "VOLUME_BODY_INVALID",
      `Field ${key} must be a non-empty string.`,
      400
    );
  }
  return value;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function requireCutKind(body: Record<string, unknown>): "user" | "recovery" | "conversion_final" {
  const kind = requireString(body, "kind");
  if (kind !== "user" && kind !== "recovery" && kind !== "conversion_final") {
    throw new MetadataConflictError(
      "VOLUME_BODY_INVALID",
      "kind must be user, recovery, or conversion_final.",
      400
    );
  }
  return kind;
}

function requireQuery(url: URL, key: string): string {
  const value = url.searchParams.get(key);
  if (!value) {
    throw new MetadataConflictError(
      "VOLUME_BODY_INVALID",
      `Query parameter ${key} is required.`,
      400
    );
  }
  return value;
}
