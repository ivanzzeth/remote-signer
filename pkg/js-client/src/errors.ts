/**
 * Error classes for remote-signer client
 */

export class RemoteSignerError extends Error {
  constructor(message: string, public readonly code?: string) {
    super(message);
    this.name = "RemoteSignerError";
  }
}

export class APIError extends RemoteSignerError {
  constructor(
    message: string,
    public readonly statusCode: number,
    code?: string
  ) {
    super(message, code);
    this.name = "APIError";
  }
}

export class SignError extends RemoteSignerError {
  constructor(
    message: string,
    public readonly requestID: string,
    public readonly status: string
  ) {
    super(message);
    this.name = "SignError";
  }
}

export class TimeoutError extends RemoteSignerError {
  constructor(message: string = "Timeout waiting for approval") {
    super(message);
    this.name = "TimeoutError";
  }
}

// Error codes
export const ErrorCodes = {
  UNAUTHORIZED: "unauthorized",
  NOT_FOUND: "not_found",
  INVALID_REQUEST: "invalid_request",
  SIGNER_NOT_FOUND: "signer_not_found",
  INVALID_PAYLOAD: "invalid_payload",
  RATE_LIMITED: "rate_limited",
  INTERNAL_ERROR: "internal_error",
  REJECTED: "rejected",
  BLOCKED: "blocked",
  PENDING_APPROVAL: "pending_approval",
} as const;
