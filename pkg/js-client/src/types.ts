/**
 * Type definitions for remote-signer client
 */

// Sign types
export type SignType =
  | "hash"
  | "raw_message"
  | "eip191"
  | "personal"
  | "typed_data"
  | "transaction";

// Request status values
export type RequestStatus =
  | "pending"
  | "authorizing"
  | "signing"
  | "completed"
  | "rejected"
  | "failed";

// Sign request payloads
export interface HashPayload {
  hash: string; // 0x prefixed, 32 bytes
}

export interface RawMessagePayload {
  raw_message: string | Uint8Array; // base64 or bytes
}

export interface MessagePayload {
  message: string;
}

export interface TypedDataField {
  name: string;
  type: string;
}

export interface TypedDataDomain {
  name?: string;
  version?: string;
  chainId?: string;
  verifyingContract?: string;
  salt?: string;
}

export interface TypedData {
  types: Record<string, TypedDataField[]>;
  primaryType: string;
  domain: TypedDataDomain;
  message: Record<string, any>;
}

export interface TypedDataPayload {
  typed_data: TypedData;
}

export interface Transaction {
  to?: string;
  value: string;
  data?: string;
  nonce?: number;
  gas: number;
  gasPrice?: string; // legacy
  gasTipCap?: string; // EIP-1559
  gasFeeCap?: string; // EIP-1559
  txType: "legacy" | "eip2930" | "eip1559";
}

export interface TransactionPayload {
  transaction: Transaction;
}

// Sign request
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

// Sign response
export interface SignResponse {
  request_id: string;
  status: RequestStatus;
  signature?: string;
  signed_data?: string;
  message?: string;
  rule_matched_id?: string;
}

// Request status
export interface RequestStatusResponse {
  id: string;
  api_key_id: string;
  chain_type: string;
  chain_id: string;
  signer_address: string;
  sign_type: string;
  status: RequestStatus;
  signature?: string;
  signed_data?: string;
  error_message?: string;
  rule_matched_id?: string;
  approved_by?: string;
  approved_at?: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

// List requests filter
export interface ListRequestsFilter {
  status?: RequestStatus;
  signer_address?: string;
  chain_id?: string;
  limit?: number;
  cursor?: string;
  cursor_id?: string;
}

// List requests response
export interface ListRequestsResponse {
  requests: RequestStatusResponse[];
  total: number;
  next_cursor?: string;
  next_cursor_id?: string;
  has_more: boolean;
}

// Health response
export interface HealthResponse {
  status: string;
  version: string;
}

// Error response
export interface ErrorResponse {
  error: string;
  message: string;
}

// Client configuration
export interface ClientConfig {
  baseURL: string;
  apiKeyID: string;
  privateKey: string | Uint8Array; // hex string or bytes
  httpClient?: {
    timeout?: number;
  };
  pollInterval?: number; // milliseconds, default: 2000
  pollTimeout?: number; // milliseconds, default: 300000 (5 minutes)
  useNonce?: boolean; // default: true
}

// Approve request
export interface ApproveRequest {
  approved: boolean;
  rule_type?: string;
  rule_mode?: "whitelist" | "blocklist";
  rule_name?: string;
  max_value?: string; // for evm_value_limit
}

// Approve response
export interface ApproveResponse {
  request_id: string;
  status: RequestStatus;
  signature?: string;
  signed_data?: string;
  generated_rule?: {
    id: string;
    name: string;
    type: string;
    mode: string;
  };
}
