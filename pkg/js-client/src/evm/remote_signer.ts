/**
 * RemoteSigner wraps an EvmSignService + address + chainID, providing
 * convenience signing methods that implement the ethsig Signer interface.
 *
 * All sign methods return raw 0x-prefixed hex signatures (not SignResponse).
 * For the full response object, use evm.sign.execute() directly.
 *
 * Usage:
 *   const signer = await client.evm.hdWallets.getSigner(primaryAddr, "1", 0);
 *   const sig = await signer.signHash("0x...");
 */

import type { Signer } from "./ethsig";
import type { EvmSignService } from "./sign";
import type { TypedData, Transaction } from "./types";

export class RemoteSigner implements Signer {
  constructor(
    private readonly sign: EvmSignService,
    public readonly address: string,
    public readonly chainID: string,
  ) {}

  getAddress(): string {
    return this.address;
  }

  /** Sign a pre-computed 32-byte hash (0x-prefixed hex). */
  async signHash(hash: string): Promise<string> {
    const resp = await this.sign.execute({
      chain_id: this.chainID,
      signer_address: this.address,
      sign_type: "hash",
      payload: { hash },
    });
    return resp.signature!;
  }

  /** Sign raw message bytes (base64-encoded string or Uint8Array). */
  async signRawMessage(rawMessage: string | Uint8Array): Promise<string> {
    const resp = await this.sign.execute({
      chain_id: this.chainID,
      signer_address: this.address,
      sign_type: "raw_message",
      payload: { raw_message: rawMessage },
    });
    return resp.signature!;
  }

  /** Sign an EIP-191 formatted message. */
  async signEIP191Message(message: string): Promise<string> {
    const resp = await this.sign.execute({
      chain_id: this.chainID,
      signer_address: this.address,
      sign_type: "eip191",
      payload: { message },
    });
    return resp.signature!;
  }

  /** Sign using personal_sign (EIP-191 version 0x45). */
  async personalSign(message: string): Promise<string> {
    const resp = await this.sign.execute({
      chain_id: this.chainID,
      signer_address: this.address,
      sign_type: "personal",
      payload: { message },
    });
    return resp.signature!;
  }

  /** Sign EIP-712 typed data. */
  async signTypedData(typedData: TypedData): Promise<string> {
    const resp = await this.sign.execute({
      chain_id: this.chainID,
      signer_address: this.address,
      sign_type: "typed_data",
      payload: { typed_data: typedData },
    });
    return resp.signature!;
  }

  /** Sign an EVM transaction. Returns signed transaction hex. */
  async signTransaction(transaction: Transaction): Promise<string> {
    const resp = await this.sign.execute({
      chain_id: this.chainID,
      signer_address: this.address,
      sign_type: "transaction",
      payload: { transaction },
    });
    return resp.signed_data!;
  }
}
