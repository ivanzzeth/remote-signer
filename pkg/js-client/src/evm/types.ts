/**
 * Shared EVM types: sign types, payload types, request/response structures.
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
