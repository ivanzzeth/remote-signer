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

// TLS configuration (Node.js only, ignored in browser)
export interface TLSConfig {
  /** CA certificate (PEM string or Buffer). Required for self-signed server certs. */
  ca?: string | Uint8Array;
  /** Client certificate (PEM string or Buffer). Required for mTLS. */
  cert?: string | Uint8Array;
  /** Client private key (PEM string or Buffer). Required for mTLS. */
  key?: string | Uint8Array;
  /** Skip server certificate verification. WARNING: insecure, testing only. Default: true */
  rejectUnauthorized?: boolean;
}

// Client configuration
export interface ClientConfig {
  baseURL: string;
  apiKeyID: string;
  privateKey: string | Uint8Array; // hex string or bytes
  httpClient?: {
    timeout?: number;
    /** Custom fetch function. Overrides default globalThis.fetch and TLS config. */
    fetch?: typeof fetch;
    /** TLS configuration for Node.js environments. Ignored in browsers. */
    tls?: TLSConfig;
  };
  pollInterval?: number; // milliseconds, default: 2000
  pollTimeout?: number; // milliseconds, default: 300000 (5 minutes)
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

// ============================================================================
// Signer types
// ============================================================================

export interface SignerInfo {
  address: string;
  chain_type: string;
  enabled: boolean;
  source: string; // "config" | "api"
}

export interface ListSignersResponse {
  signers: SignerInfo[];
}

export interface CreateSignerRequest {
  password: string;
}

export interface CreateSignerResponse {
  address: string;
  message: string;
}

// ============================================================================
// HD Wallet types
// ============================================================================

export interface CreateHDWalletRequest {
  action?: "create" | "import"; // default: "create"
  password: string;
  mnemonic?: string; // required for import
  entropy_bits?: number; // for create, default 256
}

export interface HDWalletResponse {
  primary_address: string;
  base_path: string;
  derived_count: number;
  derived?: SignerInfo[];
}

export interface ListHDWalletsResponse {
  wallets: HDWalletResponse[];
}

export interface DeriveAddressRequest {
  index?: number;
  start?: number;
  count?: number;
}

export interface DeriveAddressResponse {
  derived: SignerInfo[];
}

export interface ListDerivedAddressesResponse {
  derived: SignerInfo[];
}

// ============================================================================
// Rule types
// ============================================================================

export type RuleType =
  | "evm_address_list"
  | "evm_contract_method"
  | "evm_value_limit"
  | "evm_solidity_expression"
  | "signer_restriction"
  | "sign_type_restriction"
  | "message_pattern";

export type RuleMode = "whitelist" | "blocklist";

export interface Rule {
  id: string;
  name: string;
  description?: string;
  type: RuleType;
  mode: RuleMode;
  source: string;
  chain_type?: string;
  chain_id?: string;
  api_key_id?: string;
  signer_address?: string;
  config: Record<string, any>;
  enabled: boolean;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ListRulesResponse {
  rules: Rule[];
}

export interface CreateRuleRequest {
  name: string;
  description?: string;
  type: RuleType;
  mode: RuleMode;
  chain_type?: string;
  chain_id?: string;
  api_key_id?: string;
  signer_address?: string;
  config: Record<string, any>;
  enabled?: boolean;
  expires_at?: string;
}

export interface UpdateRuleRequest {
  name?: string;
  description?: string;
  mode?: RuleMode;
  config?: Record<string, any>;
  enabled?: boolean;
  expires_at?: string;
}

// ============================================================================
// Audit types
// ============================================================================

export type AuditEventType =
  | "auth_success"
  | "auth_failure"
  | "sign_request"
  | "sign_complete"
  | "sign_failed"
  | "sign_rejected"
  | "rule_matched"
  | "approval_request"
  | "approval_granted"
  | "approval_denied"
  | "rule_created"
  | "rule_updated"
  | "rule_deleted"
  | "rate_limit_hit";

export interface AuditRecord {
  id: string;
  event_type: AuditEventType;
  severity: "info" | "warning" | "critical";
  timestamp: string;
  api_key_id: string;
  actor_address?: string;
  sign_request_id?: string;
  signer_address?: string;
  chain_type?: string;
  chain_id?: string;
  rule_id?: string;
  details?: Record<string, any>;
  error_message?: string;
  request_method?: string;
  request_path?: string;
}

export interface ListAuditFilter {
  event_type?: AuditEventType;
  api_key_id?: string;
  chain_type?: string;
  start_time?: string; // RFC3339
  end_time?: string; // RFC3339
  limit?: number;
  cursor?: string;
  cursor_id?: string;
}

export interface ListAuditResponse {
  records: AuditRecord[];
  total: number;
  next_cursor?: string;
  next_cursor_id?: string;
  has_more: boolean;
}

// ============================================================================
// Preview rule types
// ============================================================================

export interface PreviewRuleRequest {
  rule_type: string;
  rule_mode: RuleMode;
  rule_name?: string;
  max_value?: string;
}

export interface PreviewRuleResponse {
  id: string;
  name: string;
  type: string;
  mode: string;
  source: string;
  chain_type?: string;
  chain_id?: string;
  api_key_id?: string;
  signer_address?: string;
  config: Record<string, any>;
  enabled: boolean;
}
