/**
 * EVM guard service: manage the guard state.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmGuardService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * Resume the guard (e.g. after a pause or restart).
   */
  async resume(): Promise<void> {
    await this.transport.request<void>(
      "POST",
      "/api/v1/evm/guard/resume",
      null,
    );
  }
}
