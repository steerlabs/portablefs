// AccessLeaseError is a machine-readable lease-route failure; the server
// renders it as { error: { code, message } } with a stable code from
// @portablefs/protocol accessLeaseErrorCodes.
export class AccessLeaseError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "AccessLeaseError";
  }
}
