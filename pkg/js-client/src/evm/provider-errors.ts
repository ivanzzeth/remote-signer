/**
 * Standard EIP-1193 error codes
 * @see https://eips.ethereum.org/EIPS/eip-1193#provider-errors
 */
export enum ProviderErrorCode {
  /**
   * The user rejected the request
   */
  USER_REJECTED = 4001,

  /**
   * The requested method and/or account has not been authorized by the user
   */
  UNAUTHORIZED = 4100,

  /**
   * The Provider does not support the requested method
   */
  UNSUPPORTED_METHOD = 4200,

  /**
   * The Provider is disconnected from all chains
   */
  DISCONNECTED = 4900,

  /**
   * The Provider is not connected to the requested chain
   */
  CHAIN_DISCONNECTED = 4901,
}

/**
 * Standard EIP-1193 Provider RPC Error
 * @see https://eips.ethereum.org/EIPS/eip-1193#provider-errors
 */
export class ProviderRpcError extends Error {
  /**
   * Standard error code
   */
  public readonly code: number;

  /**
   * Optional additional error data
   */
  public readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "ProviderRpcError";
    this.code = code;
    this.data = data;

    // Maintain proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ProviderRpcError);
    }
  }

  /**
   * Convert error to JSON-RPC error format
   */
  toJSON() {
    return {
      code: this.code,
      message: this.message,
      ...(this.data !== undefined && { data: this.data }),
    };
  }
}

/**
 * Helper functions to create standard errors
 */
export const providerErrors = {
  userRejectedRequest: (message = "User rejected the request") =>
    new ProviderRpcError(ProviderErrorCode.USER_REJECTED, message),

  unauthorized: (message = "Unauthorized to perform this action") =>
    new ProviderRpcError(ProviderErrorCode.UNAUTHORIZED, message),

  unsupportedMethod: (method: string) =>
    new ProviderRpcError(
      ProviderErrorCode.UNSUPPORTED_METHOD,
      `The method "${method}" is not supported`
    ),

  disconnected: (message = "Provider is disconnected from all chains") =>
    new ProviderRpcError(ProviderErrorCode.DISCONNECTED, message),

  chainDisconnected: (chainId: string) =>
    new ProviderRpcError(
      ProviderErrorCode.CHAIN_DISCONNECTED,
      `Provider is not connected to chain ${chainId}`
    ),

  /**
   * Create a custom RPC error
   */
  rpc: (code: number, message: string, data?: unknown) =>
    new ProviderRpcError(code, message, data),
};
