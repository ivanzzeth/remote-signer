/**
 * Remote Signer JavaScript Client Library
 *
 * @example
 * ```typescript
 * import { RemoteSignerClient } from '@remote-signer/client';
 *
 * const client = new RemoteSignerClient({
 *   baseURL: 'http://localhost:8548',
 *   apiKeyID: 'my-api-key',
 *   privateKey: 'your-ed25519-private-key-hex',
 * });
 *
 * // New resource-based API
 * const response = await client.evm.sign.execute({
 *   chain_id: '1',
 *   signer_address: '0x...',
 *   sign_type: 'personal',
 *   payload: { message: 'Hello, World!' }
 * });
 *
 * // Backward-compatible API (deprecated)
 * const response2 = await client.sign({
 *   chain_id: '1',
 *   signer_address: '0x...',
 *   sign_type: 'personal',
 *   payload: { message: 'Hello, World!' }
 * });
 * ```
 */

// Client
export { RemoteSignerClient, HealthResponse, ErrorResponse } from "./client";

// Transport
export { HttpTransport, ClientConfig, TLSConfig } from "./transport";

// EVM (all services + types)
export {
  EvmService,
  EvmSignService,
  EvmRequestService,
  EvmRuleService,
  EvmSignerService,
  EvmHDWalletService,
  EvmGuardService,
} from "./evm";
export type {
  // Shared EVM types
  SignType,
  RequestStatus,
  HashPayload,
  RawMessagePayload,
  MessagePayload,
  TypedDataField,
  TypedDataDomain,
  TypedData,
  TypedDataPayload,
  Transaction,
  TransactionPayload,
  // Sign types
  SignRequest,
  SignResponse,
  // Request types
  RequestStatusResponse,
  ListRequestsFilter,
  ListRequestsResponse,
  ApproveRequest,
  ApproveResponse,
  PreviewRuleRequest,
  PreviewRuleResponse,
  // Rule types
  RuleType,
  RuleMode,
  Rule,
  ListRulesResponse,
  CreateRuleRequest,
  UpdateRuleRequest,
  // Signer types
  SignerInfo,
  ListSignersResponse,
  CreateSignerRequest,
  CreateSignerResponse,
  // HD wallet types
  CreateHDWalletRequest,
  HDWalletResponse,
  ListHDWalletsResponse,
  DeriveAddressRequest,
  DeriveAddressResponse,
  ListDerivedAddressesResponse,
} from "./evm";

// Audit
export { AuditService } from "./audit";
export type {
  AuditEventType,
  AuditRecord,
  ListAuditFilter,
  ListAuditResponse,
} from "./audit";

// Templates
export { TemplateService } from "./templates";

// Errors
export * from "./errors";

// Crypto
export * from "./crypto";
