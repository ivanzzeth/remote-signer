/**
 * Remote Signer JavaScript Client - thin facade over resource-based services.
 * Usable in browser and Node.js; see transport.ts for HTTP/TLS behaviour per environment.
 */

import { HttpTransport, ClientConfig } from "./transport";
import { EvmService } from "./evm";
import { AuditService } from "./audit";
import { TemplateService } from "./templates";

// ---------------------------------------------------------------------------
// Types kept at client level
// ---------------------------------------------------------------------------

/** Health check response */
export interface HealthResponse {
  status: string;
  version: string;
}

/** Generic error response from the API */
export interface ErrorResponse {
  error: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class RemoteSignerClient {
  public readonly evm: EvmService;
  public readonly audit: AuditService;
  public readonly templates: TemplateService;
  private transport: HttpTransport;

  constructor(config: ClientConfig) {
    this.transport = new HttpTransport(config);

    const pollInterval = config.pollInterval ?? 2000; // 2 seconds
    const pollTimeout = config.pollTimeout ?? 300000; // 5 minutes

    this.evm = new EvmService(this.transport, pollInterval, pollTimeout);
    this.audit = new AuditService(this.transport);
    this.templates = new TemplateService(this.transport);
  }

  /**
   * Health check.
   */
  async health(): Promise<HealthResponse> {
    return this.transport.request<HealthResponse>("GET", "/health", null);
  }

  /**
   * Prometheus metrics endpoint.
   */
  async metrics(): Promise<string> {
    return this.transport.requestNoAuth<string>("GET", "/metrics");
  }

  // =========================================================================
  // Backward-compatible convenience methods (delegate to sub-services)
  // =========================================================================

  /** @deprecated Use client.evm.sign.execute(request) */
  async sign(
    request: Parameters<EvmService["sign"]["execute"]>[0],
    waitForApproval: boolean = true,
  ) {
    return waitForApproval
      ? this.evm.sign.execute(request)
      : this.evm.sign.executeAsync(request);
  }

  /** @deprecated Use client.evm.requests.get(requestID) */
  async getRequest(requestID: string) {
    return this.evm.requests.get(requestID);
  }

  /** @deprecated Use client.evm.requests.list(filter) */
  async listRequests(filter?: Parameters<EvmService["requests"]["list"]>[0]) {
    return this.evm.requests.list(filter);
  }

  /** @deprecated Use client.evm.requests.approve(requestID, req) */
  async approveRequest(
    requestID: string,
    approveRequest: Parameters<EvmService["requests"]["approve"]>[1],
  ) {
    return this.evm.requests.approve(requestID, approveRequest);
  }

  /** @deprecated Use client.evm.signers.list() */
  async listSigners() {
    return this.evm.signers.list();
  }

  /** @deprecated Use client.evm.signers.create(req) */
  async createSigner(
    req: Parameters<EvmService["signers"]["create"]>[0],
  ) {
    return this.evm.signers.create(req);
  }

  /** @deprecated Use client.evm.rules.list() */
  async listRules() {
    return this.evm.rules.list();
  }

  /** @deprecated Use client.evm.rules.get(ruleID) */
  async getRule(ruleID: string) {
    return this.evm.rules.get(ruleID);
  }

  /** @deprecated Use client.evm.rules.create(rule) */
  async createRule(rule: Parameters<EvmService["rules"]["create"]>[0]) {
    return this.evm.rules.create(rule);
  }

  /** @deprecated Use client.evm.rules.update(ruleID, update) */
  async updateRule(
    ruleID: string,
    update: Parameters<EvmService["rules"]["update"]>[1],
  ) {
    return this.evm.rules.update(ruleID, update);
  }

  /** @deprecated Use client.evm.rules.delete(ruleID) */
  async deleteRule(ruleID: string) {
    return this.evm.rules.delete(ruleID);
  }

  /** @deprecated Use client.audit.list(filter) */
  async listAuditLogs(
    filter?: Parameters<AuditService["list"]>[0],
  ) {
    return this.audit.list(filter);
  }

  /** @deprecated Use client.evm.requests.previewRule(requestID, req) */
  async previewRule(
    requestID: string,
    previewRequest: Parameters<EvmService["requests"]["previewRule"]>[1],
  ) {
    return this.evm.requests.previewRule(requestID, previewRequest);
  }

  /** @deprecated Use client.evm.hdWallets.create(req) */
  async createHDWallet(
    req: Parameters<EvmService["hdWallets"]["create"]>[0],
  ) {
    return this.evm.hdWallets.create(req);
  }

  /** @deprecated Use client.evm.hdWallets.import(req) */
  async importHDWallet(
    req: Parameters<EvmService["hdWallets"]["import"]>[0],
  ) {
    return this.evm.hdWallets.import(req);
  }

  /** @deprecated Use client.evm.hdWallets.list() */
  async listHDWallets() {
    return this.evm.hdWallets.list();
  }

  /** @deprecated Use client.evm.hdWallets.deriveAddress(primaryAddr, req) */
  async deriveAddress(
    primaryAddr: string,
    req: Parameters<EvmService["hdWallets"]["deriveAddress"]>[1],
  ) {
    return this.evm.hdWallets.deriveAddress(primaryAddr, req);
  }

  /** @deprecated Use client.evm.hdWallets.listDerived(primaryAddr) */
  async listDerivedAddresses(primaryAddr: string) {
    return this.evm.hdWallets.listDerived(primaryAddr);
  }
}
