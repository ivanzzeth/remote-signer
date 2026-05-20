// Keystore decryption for the extension popup.
//
// Mirrors web/src/lib/keystore.ts's decrypt path so the popup can accept
// the daemon's encrypted admin keystore JSON in addition to plaintext
// PEM/hex. Encryption isn't needed here — the popup persists the raw
// 32-byte seed in chrome.storage.local once unlocked, exactly like it
// did before this feature for plaintext-PEM inputs. The keystore itself
// is never stored in extension state; we only transit it through the
// "import key" UI.
//
// Format: ethsig's EnhancedKeyFile envelope (version=1) wrapping
// go-ethereum's CryptoJSON. See web/src/lib/keystore.ts for the full
// shape doc-block.

import { keccak_256 } from "@noble/hashes/sha3";
import { scrypt } from "@noble/hashes/scrypt";

const SEED_LEN = 32;

interface KeystoreFile {
  version: number;
  key_type: string;
  identifier?: string;
  label?: string;
  crypto: CryptoJSON;
}

interface CryptoJSON {
  cipher: string;
  ciphertext: string;
  cipherparams: { iv: string };
  kdf: string;
  kdfparams: ScryptParams;
  mac: string;
}

interface ScryptParams {
  n: number;
  r: number;
  p: number;
  dklen: number;
  salt: string;
}

/**
 * Returns true when `input` looks like an EnhancedKeyFile keystore JSON.
 * Shape-based — actual decrypt happens on submit and surfaces a real
 * error for malformed input.
 */
export function detectKeystoreJSON(input: string): boolean {
  const trimmed = input.trim();
  if (!trimmed.startsWith("{")) return false;
  try {
    const parsed = JSON.parse(trimmed);
    return (
      typeof parsed === "object" &&
      parsed !== null &&
      "crypto" in parsed &&
      "version" in parsed
    );
  } catch {
    return false;
  }
}

/**
 * Decrypts a keystore JSON with the given password and returns the
 * 32-byte Ed25519 seed. Throws the literal "wrong password" on MAC
 * mismatch so the popup can render a clean error.
 */
export async function decryptKeystore(
  json: string | KeystoreFile,
  password: string,
): Promise<Uint8Array> {
  const ks: KeystoreFile = typeof json === "string" ? JSON.parse(json) : json;
  if (ks.version !== 1) {
    throw new Error(
      `unsupported keystore version: ${ks.version} (expected 1 — the EnhancedKeyFile envelope)`,
    );
  }
  if (ks.key_type !== "ed25519") {
    throw new Error(
      `unsupported key_type: ${ks.key_type} (popup only handles Ed25519 admin/agent keys)`,
    );
  }
  if (ks.crypto.cipher !== "aes-128-ctr") {
    throw new Error(`unsupported cipher: ${ks.crypto.cipher}`);
  }
  if (ks.crypto.kdf !== "scrypt") {
    throw new Error(`unsupported kdf: ${ks.crypto.kdf}`);
  }

  const params = ks.crypto.kdfparams;
  const salt = hexToBytes(params.salt);
  const iv = hexToBytes(ks.crypto.cipherparams.iv);
  const ciphertext = hexToBytes(ks.crypto.ciphertext);
  const expectedMac = hexToBytes(ks.crypto.mac);

  // Honour the params encoded in the file rather than hardcoded
  // defaults — someone might have re-encrypted with different N/r/p.
  await Promise.resolve(); // give the UI a tick to paint "Unlocking…"
  const pwBytes = new TextEncoder().encode(password);
  const derivedKey = scrypt(pwBytes, salt, {
    N: params.n,
    r: params.r,
    p: params.p,
    dkLen: params.dklen,
  });
  const aesKey = derivedKey.slice(0, 16);
  const macKey = derivedKey.slice(16, 32);

  const macInput = new Uint8Array(macKey.length + ciphertext.length);
  macInput.set(macKey, 0);
  macInput.set(ciphertext, macKey.length);
  const actualMac = keccak_256(macInput);
  if (!constantTimeEqual(actualMac, expectedMac)) {
    throw new Error("wrong password");
  }

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    aesKey as BufferSource,
    { name: "AES-CTR" },
    false,
    ["decrypt"],
  );
  const out = await crypto.subtle.decrypt(
    { name: "AES-CTR", counter: iv as BufferSource, length: 128 },
    cryptoKey,
    ciphertext as BufferSource,
  );
  const seed = new Uint8Array(out);
  if (seed.length !== SEED_LEN) {
    throw new Error(
      `decrypted seed has unexpected length ${seed.length} (expected ${SEED_LEN})`,
    );
  }
  return seed;
}

/** Converts raw bytes to lowercase hex (no 0x prefix). */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error("invalid hex: odd length");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex char at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
