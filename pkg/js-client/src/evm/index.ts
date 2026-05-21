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
export * from "./ethsig";
export * from "./provider-errors";
export * from "./provider-types";
export * from "./provider-storage";
export * from "./eip1193";
