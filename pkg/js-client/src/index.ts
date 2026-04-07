/**
 * Remote Signer JavaScript Client Library
 *
 * Supports both browser and Node.js:
 * - Browser: use the ESM build (globalThis.fetch, Web Crypto API). TLS/mTLS (custom CA, client cert) is not available; use standard HTTPS.
 * - Node.js: same ESM/CJS build; TLS/mTLS is supported via httpClient.tls (custom CA, client certificates).
 *
 * @example
 * ```typescript
 * import { RemoteSignerClient } from 'remote-signer-client';
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
  EvmSimulateService,
  RemoteSigner,
  EIP1193Provider,
  ProviderRpcError,
  providerErrors,
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
  BatchSignItemRequest,
  BatchSignRequest,
  BatchSignResultDTO,
  BatchSignResponse,
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
  RuleBudget,
  ListRulesFilter,
  ListRulesResponse,
  CreateRuleRequest,
  UpdateRuleRequest,
  // Signer types
  SignerInfo,
  ListSignersFilter,
  ListSignersResponse,
  CreateSignerRequest,
  CreateSignerResponse,
  GrantAccessRequest,
  TransferOwnershipRequest,
  SignerAccessEntry,
  // HD wallet types
  CreateHDWalletRequest,
  HDWalletResponse,
  ListHDWalletsResponse,
  DeriveAddressRequest,
  DeriveAddressResponse,
  ListDerivedAddressesResponse,
  // Simulate types
  SimulateRequest,
  SimulateResponse,
  BalanceChangeDTO,
  SimEventDTO,
  SimulateTxDTO,
  SimulateBatchRequest,
  SimulateResultDTO,
  SimulateBatchResponse,
  ChainStatusDTO,
  SimulationStatusResponse,
  // EIP-1193 Provider types
  EIP1193ProviderConfig,
  SignersSource,
  RequestArguments,
  ProviderConnectInfo,
  ProviderMessage,
  ProviderErrorCode,
  // Ethsig interfaces
  Signer,
  AddressGetter,
  HashSigner,
  RawMessageSigner,
  EIP191Signer,
  PersonalSigner,
  TypedDataSigner,
  TransactionSigner,
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
export type {
  TemplateVariable,
  Template,
  ListTemplatesFilter,
  ListTemplatesResponse,
  CreateTemplateRequest,
  UpdateTemplateRequest,
  BudgetConfig,
  ScheduleConfig,
  InstantiateRequest,
  InstantiateResponse,
  RevokeInstanceResponse,
} from "./templates";

// API Keys
export { APIKeyService } from "./apikeys";
export type {
  APIKey,
  ListAPIKeysFilter,
  ListAPIKeysResponse,
  CreateAPIKeyRequest,
  UpdateAPIKeyRequest,
} from "./apikeys";

// ACLs
export { ACLService } from "./acls";
export type { IPWhitelistResponse } from "./acls";

// Presets
export { PresetService } from "./presets";
export type {
  PresetEntry,
  ListPresetsResponse,
  PresetVarsResponse,
  ApplyPresetRequest,
  ApplyResultItem,
  ApplyPresetResponse,
} from "./presets";

// Errors
export * from "./errors";

// Crypto
export * from "./crypto";
