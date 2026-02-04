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
 * const response = await client.sign({
 *   chain_id: '1',
 *   signer_address: '0x...',
 *   sign_type: 'personal',
 *   payload: { message: 'Hello, World!' }
 * });
 * ```
 */

export { RemoteSignerClient } from "./client";
export * from "./types";
export * from "./errors";
export * from "./crypto";
