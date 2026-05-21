/**
 * EVM service: groups all EVM sub-services and re-exports types.
 */

import { HttpTransport } from "../transport";
import { EvmSignService } from "./sign";
import { EvmRequestService } from "./requests";
import { EvmRuleService } from "./rules";
import { EvmSignerService } from "./signers";
import { EvmHDWalletService } from "./hdwallets";
import { EvmGuardService } from "./guard";
import { EvmSimulateService } from "./simulate";
import { EvmBudgetService } from "./budgets";
import { EvmRPCProxyService } from "./rpc_proxy";
import { EvmTransactionService } from "./transactions";

// ---------------------------------------------------------------------------
// Composite EVM service
// ---------------------------------------------------------------------------

export class EvmService {
  public readonly sign: EvmSignService;
  public readonly requests: EvmRequestService;
  public readonly rules: EvmRuleService;
  public readonly signers: EvmSignerService;
  public readonly hdWallets: EvmHDWalletService;
  public readonly guard: EvmGuardService;
  public readonly simulate: EvmSimulateService;
  public readonly budgets: EvmBudgetService;
  // Wallet-side JSON-RPC proxy. EIP1193Provider routes every read +
  // signed-tx broadcast through this service so the daemon stays the
  // single source of chain-RPC config (URL, API key, rate limit).
  public readonly rpcProxy: EvmRPCProxyService;
  // On-chain transaction tracker — read-only view over the
  // /api/v1/evm/transactions endpoints the wallet RPC proxy
  // populates. UIs use this to surface broadcast → mined status.
  public readonly transactions: EvmTransactionService;

  constructor(transport: HttpTransport, pollInterval: number, pollTimeout: number) {
    this.sign = new EvmSignService(transport, pollInterval, pollTimeout);
    this.requests = new EvmRequestService(transport);
    this.rules = new EvmRuleService(transport);
    this.signers = new EvmSignerService(transport);
    this.hdWallets = new EvmHDWalletService(transport, this.sign);
    this.guard = new EvmGuardService(transport);
    this.simulate = new EvmSimulateService(transport);
    this.budgets = new EvmBudgetService(transport);
    this.rpcProxy = new EvmRPCProxyService(transport);
    this.transactions = new EvmTransactionService(transport);
  }
}

// Re-export all types and services
export * from "./types";
export * from "./sign";
export * from "./requests";
export * from "./rules";
export * from "./signers";
export * from "./hdwallets";
export * from "./remote_signer";
export * from "./guard";
export * from "./simulate";
export * from "./budgets";
export * from "./rpc_proxy";
// transactions: re-export under a distinct surface to avoid clashing
// with `Transaction` from ./types (the unsigned tx payload that goes
// INTO sign requests — different concept from the on-chain row this
// service returns).
export {
  EvmTransactionService,
  type Transaction as OnChainTransaction,
  type TransactionStatus as OnChainTransactionStatus,
  type ListTransactionsFilter,
  type ListTransactionsResponse,
} from "./transactions";
export * from "./ethsig";
export * from "./provider-errors";
export * from "./provider-types";
export * from "./provider-storage";
export * from "./eip1193";
