/**
 * Ethsig-compatible interfaces mirroring Go's ethsig package.
 *
 * These interfaces define the signing contract that RemoteSigner implements.
 * When the ethsig-js library is created, it will use these same interfaces,
 * making RemoteSigner a drop-in implementation.
 *
 * All sign methods return Promise<string> (0x-prefixed hex signature),
 * matching Go's []byte return convention.
 */

import type { TypedData, Transaction } from "./types";

/** Returns the signer's address. Mirrors Go ethsig.AddressGetter. */
export interface AddressGetter {
  getAddress(): string; // 0x-prefixed address
}

/** Signs a pre-computed hash. Mirrors Go ethsig.HashSigner. */
export interface HashSigner {
  signHash(hash: string): Promise<string>; // hash: 0x hex, returns 0x hex signature
}

/** Signs raw message bytes. Mirrors Go ethsig.RawMessageSigner. */
export interface RawMessageSigner {
  signRawMessage(raw: string | Uint8Array): Promise<string>; // returns 0x hex signature
}

/** Signs an EIP-191 formatted message. Mirrors Go ethsig.EIP191Signer. */
export interface EIP191Signer {
  signEIP191Message(message: string): Promise<string>; // returns 0x hex signature
}

/** Signs using personal_sign (EIP-191 version 0x45). Mirrors Go ethsig.PersonalSigner. */
export interface PersonalSigner {
  personalSign(message: string): Promise<string>; // returns 0x hex signature
}

/** Signs EIP-712 typed data. Mirrors Go ethsig.TypedDataSigner. */
export interface TypedDataSigner {
  signTypedData(typedData: TypedData): Promise<string>; // returns 0x hex signature
}

/** Signs an EVM transaction. Mirrors Go ethsig.TransactionSigner. */
export interface TransactionSigner {
  signTransaction(transaction: Transaction): Promise<string>; // returns 0x hex signed tx
}

/** Composite interface equivalent to Go's ethsig.Signer wrapping all sub-interfaces. */
export interface Signer
  extends AddressGetter,
    HashSigner,
    RawMessageSigner,
    EIP191Signer,
    PersonalSigner,
    TypedDataSigner,
    TransactionSigner {}
