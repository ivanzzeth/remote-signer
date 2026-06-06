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
  EvmBudgetService,
  EvmRPCProxyService,
  EvmTransactionService,
  RemoteSigner,
  EIP1193Provider,
  ProviderRpcError,
  providerErrors,
  MemoryProviderStorage,
} from "./evm";
export type {
  ProviderStorage,
  PersistedProviderState,
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
  RequestSimulation,
  SimulationDecision,
  // Rule types
  RuleType,
  RuleMode,
  Rule,
  RuleVariableDef,
  RuleBudget,
  ListRulesFilter,
  ListRulesResponse,
  CreateRuleRequest,
  UpdateRuleRequest,
  ValidateTestResult,
  ValidateRuleResponse,
  BatchValidateResponse,
  ProposeRuleRequest,
  // Signer types
  SignerInfo,
  ListSignersFilter,
  ListSignersResponse,
  CreateKeystoreParams,
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
  ListSimulationsFilter,
  SimulationHistoryItem,
  ListSimulationsResponse,
  RevertDetailDTO,
  // Budgets
  BudgetKind,
  BudgetEntry,
  ListBudgetsResponse,
  CreateBudgetRequest,
  UpdateBudgetRequest,
  // EIP-1193 Provider types
  EIP1193ProviderConfig,
  SignersSource,
  RequestArguments,
  ProviderConnectInfo,
  ProviderMessage,
  ProviderErrorCode,
  // RPC proxy
  RPCProxyRequest,
  RPCProxyResponse,
  // On-chain transactions
  OnChainTransaction,
  OnChainTransactionStatus,
  ListTransactionsFilter,
  ListTransactionsResponse,
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
export { AuditService, ALL_AUDIT_EVENT_TYPES } from "./audit";
export type {
  AuditEventType,
  AuditRecord,
  ListAuditFilter,
  ListAuditResponse,
} from "./audit";

// Templates
export { TemplateService } from "./templates";
export type {
  VariableType,
  TemplateVariable,
  VariableGroup,
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
  ValidateTestResult as TemplateValidateTestResult,
  ValidateRuleResultItem,
  ValidateTemplateResponse,
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
  PresetDetail,
  PresetVariableDetail,
  ApplyPresetRequest,
  ApplyResultItem,
  ApplyPresetResponse,
  ValidatePresetResponse,
} from "./presets";

// Registry (hot-reload templates and presets from disk)
export { RegistryService } from "./registry";
export type {
  RegistryRefreshError,
  RegistryRefreshReport,
  RegistryRefreshResponse,
} from "./registry";

// Settings
export { SettingsService, SETTINGS_GROUPS } from "./settings";
export type { SettingsGroup, SettingsSnapshot } from "./settings";

// Wallets (organisational collections of signers — not multi-sig).
export { WalletService } from "./wallets";
export type {
  Wallet,
  WalletMember,
  CreateWalletRequest,
  ListWalletsFilter,
  ListWalletsResponse,
  AddWalletMemberRequest,
  ListWalletMembersResponse,
} from "./wallets";

// Errors
export * from "./errors";

// Crypto
export * from "./crypto";
