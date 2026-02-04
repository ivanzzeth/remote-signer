/**
 * Remote Signer JavaScript Client
 */

import {
  ClientConfig,
  SignRequest,
  SignResponse,
  RequestStatusResponse,
  ListRequestsFilter,
  ListRequestsResponse,
  HealthResponse,
  ApproveRequest,
  ApproveResponse,
  RequestStatus,
} from "./types";
import {
  RemoteSignerError,
  APIError,
  SignError,
  TimeoutError,
  ErrorCodes,
} from "./errors";
import { parsePrivateKey, generateNonce, signRequest, signRequestWithNonce } from "./crypto";

export class RemoteSignerClient {
  private baseURL: string;
  private apiKeyID: string;
  private privateKey: Uint8Array;
  private pollInterval: number;
  private pollTimeout: number;
  private useNonce: boolean;
  private httpClient: {
    fetch: typeof fetch;
    timeout?: number;
  };

  constructor(config: ClientConfig) {
    if (!config.baseURL) {
      throw new Error("baseURL is required");
    }
    if (!config.apiKeyID) {
      throw new Error("apiKeyID is required");
    }
    if (!config.privateKey) {
      throw new Error("privateKey is required");
    }

    this.baseURL = config.baseURL.replace(/\/$/, "");
    this.apiKeyID = config.apiKeyID;
    this.privateKey = parsePrivateKey(config.privateKey);
    this.pollInterval = config.pollInterval ?? 2000; // 2 seconds
    this.pollTimeout = config.pollTimeout ?? 300000; // 5 minutes
    this.useNonce = config.useNonce ?? true;

    // Setup HTTP client
    this.httpClient = {
      fetch: globalThis.fetch,
      timeout: config.httpClient?.timeout ?? 30000, // 30 seconds
    };
  }

  /**
   * Health check
   */
  async health(): Promise<HealthResponse> {
    const response = await this.request("GET", "/health", null);
    return response as HealthResponse;
  }

  /**
   * Submit a signing request
   * If waitForApproval is true (default), polls until completion or timeout
   */
  async sign(
    request: SignRequest,
    waitForApproval: boolean = true
  ): Promise<SignResponse> {
    const response = await this.request<SignResponse>(
      "POST",
      "/api/v1/evm/sign",
      request
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
        response.status
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
      response.status
    );
  }

  /**
   * Get the status of a signing request
   */
  async getRequest(requestID: string): Promise<RequestStatusResponse> {
    const response = await this.request<RequestStatusResponse>(
      "GET",
      `/api/v1/evm/requests/${requestID}`,
      null
    );
    return response;
  }

  /**
   * List signing requests with optional filters
   */
  async listRequests(
    filter?: ListRequestsFilter
  ): Promise<ListRequestsResponse> {
    const params = new URLSearchParams();
    if (filter?.status) {
      params.append("status", filter.status);
    }
    if (filter?.signer_address) {
      params.append("signer_address", filter.signer_address);
    }
    if (filter?.chain_id) {
      params.append("chain_id", filter.chain_id);
    }
    if (filter?.limit) {
      params.append("limit", filter.limit.toString());
    }
    if (filter?.cursor) {
      params.append("cursor", filter.cursor);
    }
    if (filter?.cursor_id) {
      params.append("cursor_id", filter.cursor_id);
    }

    const queryString = params.toString();
    const path = `/api/v1/evm/requests${queryString ? `?${queryString}` : ""}`;

    const response = await this.request<ListRequestsResponse>("GET", path, null);
    return response;
  }

  /**
   * Approve or reject a pending request
   */
  async approveRequest(
    requestID: string,
    approveRequest: ApproveRequest
  ): Promise<ApproveResponse> {
    const response = await this.request<ApproveResponse>(
      "POST",
      `/api/v1/evm/requests/${requestID}/approve`,
      approveRequest
    );
    return response;
  }

  /**
   * Poll for the result of a pending request
   */
  private async pollForResult(requestID: string): Promise<SignResponse> {
    const deadline = Date.now() + this.pollTimeout;
    const poll = async (): Promise<SignResponse> => {
      if (Date.now() > deadline) {
        throw new TimeoutError();
      }

      const status = await this.getRequest(requestID);

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
            status.status
          );
        default:
          // Continue polling for pending/authorizing/signing
          await new Promise((resolve) => setTimeout(resolve, this.pollInterval));
          return poll();
      }
    };

    return poll();
  }

  /**
   * Make an authenticated HTTP request
   */
  private async request<T>(
    method: string,
    path: string,
    body: any
  ): Promise<T> {
    const url = this.baseURL + path;
    const bodyBytes = body ? new TextEncoder().encode(JSON.stringify(body)) : new Uint8Array(0);
    const timestamp = Date.now();

    // Sign the request
    let signature: string;
    let nonce: string | undefined;

    if (this.useNonce) {
      nonce = generateNonce();
      signature = signRequestWithNonce(
        this.privateKey,
        timestamp,
        nonce,
        method,
        path,
        bodyBytes
      );
    } else {
      signature = signRequest(
        this.privateKey,
        timestamp,
        method,
        path,
        bodyBytes
      );
    }

    // Build headers
    const headers: Record<string, string> = {
      "X-API-Key-ID": this.apiKeyID,
      "X-Timestamp": timestamp.toString(),
      "X-Signature": signature,
    };

    if (nonce) {
      headers["X-Nonce"] = nonce;
    }

    if (body) {
      headers["Content-Type"] = "application/json";
    }

    // Make request
    const controller = new AbortController();
    const timeoutId = this.httpClient.timeout
      ? setTimeout(() => controller.abort(), this.httpClient.timeout)
      : null;

    try {
      const response = await this.httpClient.fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      const responseBody = await response.text();
      let data: any;

      try {
        data = responseBody ? JSON.parse(responseBody) : {};
      } catch {
        data = { message: responseBody };
      }

      if (!response.ok) {
        const error = data as { error?: string; message?: string };
        throw new APIError(
          error.message || `HTTP ${response.status}`,
          response.status,
          error.error
        );
      }

      return data as T;
    } catch (error) {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      if (error instanceof APIError) {
        throw error;
      }

      if (error instanceof Error && error.name === "AbortError") {
        throw new TimeoutError("Request timeout");
      }

      throw new RemoteSignerError(
        error instanceof Error ? error.message : "Unknown error"
      );
    }
  }
}
