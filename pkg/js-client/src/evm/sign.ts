/**
 * EVM sign service: execute synchronous and async signing requests.
 */

import { HttpTransport } from "../transport";
import { SignError, TimeoutError } from "../errors";
import type {
  SignType,
  RequestStatus,
  HashPayload,
  RawMessagePayload,
  MessagePayload,
  TypedDataPayload,
  TransactionPayload,
} from "./types";
import type { RequestStatusResponse } from "./requests";
import type { SimulateResponse } from "./simulate";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Sign request */
export interface SignRequest {
  chain_id: string;
  signer_address: string;
  sign_type: SignType;
  payload:
    | HashPayload
    | RawMessagePayload
    | MessagePayload
    | TypedDataPayload
    | TransactionPayload;
}

/** Sign response */
export interface SignResponse {
  request_id: string;
  status: RequestStatus;
  signature?: string;
  signed_data?: string;
  message?: string;
  rule_matched_id?: string;
}

/** A single item in a batch sign request. */
export interface BatchSignItemRequest {
  chain_id: string;
  signer_address: string;
  sign_type: SignType;
  transaction: Record<string, any>;
}

/** Batch sign request. */
export interface BatchSignRequest {
  requests: BatchSignItemRequest[];
}

/** Per-transaction result in a batch sign response. */
export interface BatchSignResultDTO {
  index: number;
  request_id?: string;
  signature?: string;
  signed_data?: string;
  simulation?: SimulateResponse;
}

/** Batch sign response. */
export interface BatchSignResponse {
  results: BatchSignResultDTO[];
  net_balance_changes?: import("./simulate").BalanceChangeDTO[];
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmSignService {
  private pollInterval: number;
  private pollTimeout: number;

  constructor(
    private readonly transport: HttpTransport,
    pollInterval: number,
    pollTimeout: number,
  ) {
    this.pollInterval = pollInterval;
    this.pollTimeout = pollTimeout;
  }

  /**
   * Submit a signing request and poll until completion or timeout.
   */
  async execute(request: SignRequest): Promise<SignResponse> {
    return this.doSign(request, true);
  }

  /**
   * Submit a signing request without waiting for completion.
   */
  async executeAsync(request: SignRequest): Promise<SignResponse> {
    return this.doSign(request, false);
  }

  /**
   * Submit a batch of signing requests atomically.
   * If any transaction fails rules/budget/simulation, the entire batch is rejected.
   */
  async executeBatch(request: BatchSignRequest): Promise<BatchSignResponse> {
    return this.transport.request<BatchSignResponse>(
      "POST",
      "/api/v1/evm/sign/batch",
      request,
    );
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private async doSign(
    request: SignRequest,
    waitForApproval: boolean,
  ): Promise<SignResponse> {
    const response = await this.transport.request<SignResponse>(
      "POST",
      "/api/v1/evm/sign",
      request,
    );

    // If completed, return immediately
    if (response.status === "completed") {
      return response;
    }

    // If rejected or failed, throw error
    if (response.status === "rejected" || response.status === "failed") {
      throw new SignError(
        response.message || "Request rejected or failed",
        response.request_id,
        response.status,
      );
    }

    // If pending approval and we should wait
    if (
      waitForApproval &&
      (response.status === "pending" || response.status === "authorizing")
    ) {
      return this.pollForResult(response.request_id);
    }

    // Return pending status
    throw new SignError(
      response.message || "Pending manual approval",
      response.request_id,
      response.status,
    );
  }

  /**
   * Poll for the result of a pending request.
   */
  private async pollForResult(requestID: string): Promise<SignResponse> {
    const deadline = Date.now() + this.pollTimeout;
    const poll = async (): Promise<SignResponse> => {
      if (Date.now() > deadline) {
        throw new TimeoutError();
      }

      const status = await this.transport.request<RequestStatusResponse>(
        "GET",
        `/api/v1/evm/requests/${requestID}`,
        null,
      );

      switch (status.status) {
        case "completed":
          return {
            request_id: status.id,
            status: status.status,
            signature: status.signature,
            signed_data: status.signed_data,
            rule_matched_id: status.rule_matched_id || undefined,
          };
        case "rejected":
        case "failed":
          throw new SignError(
            status.error_message || "Request rejected or failed",
            status.id,
            status.status,
          );
        default:
          // Continue polling for pending/authorizing/signing
          await new Promise((resolve) => setTimeout(resolve, this.pollInterval));
          return poll();
      }
    };

    return poll();
  }
}
