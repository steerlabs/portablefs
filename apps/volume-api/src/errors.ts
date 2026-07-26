/**
 * Typed, client-visible Volume API error. Anything else thrown by a handler is
 * reported as the generic VOLUME_INTERNAL — raw internal error text never
 * reaches a client.
 */
export class VolumeApiError extends Error {
  readonly code: string;
  readonly status: number;
  /** Response headers the error carries (e.g. Retry-After on 429s). */
  readonly headers: Readonly<Record<string, string>> | undefined;

  constructor(code: string, message: string, status: number, headers?: Record<string, string>) {
    super(message);
    this.name = "VolumeApiError";
    this.code = code;
    this.status = status;
    this.headers = headers;
  }
}

export function isAbortError(error: unknown): boolean {
  return (
    (error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}
