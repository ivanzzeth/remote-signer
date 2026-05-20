// Browser-side password-encrypted private-key storage.
//
// Format: go-ethereum keystore v3 + ethsig's EnhancedKeyFile wrapper.
// We deliberately match the on-disk format the daemon produces so the
// same JSON can be imported into the CLI later (and vice versa). The
// shape is:
//
//   {
//     "version":    3,                // ethsig EnhancedKeyFile version
//     "key_type":   "ed25519",        // ethsig key-type tag
//     "identifier": "<api-key-id>",   // operator-meaningful label
//     "crypto":    { ...go-ethereum CryptoJSON... }
//   }
//
// The inner Crypto block:
//
//   - kdf:     "scrypt"
//   - kdfparams: { N, r, p, dklen, salt(hex) }
//   - cipher:    "aes-128-ctr"
//   - cipherparams: { iv(hex) }
//   - ciphertext:   hex
//   - mac:          keccak256( derivedKey[16:32] || ciphertext ) as hex
//
// AES key is derivedKey[0:16]; MAC key is derivedKey[16:32]. This is the
// long-standing Ethereum convention — same code in go-ethereum, ethers,
// web3.js, MetaMask. We reimplement it here against @noble/hashes
// (scrypt + keccak256) + WebCrypto SubtleCrypto (AES-CTR) to keep the
// browser bundle small (no ethers).
//
// We never persist the unencrypted seed. The 32-byte Ed25519 seed only
// exists in memory while a session is unlocked.

import { keccak_256 } from "@noble/hashes/sha3";
import { scrypt } from "@noble/hashes/scrypt";

// ──────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────

// scrypt N=262144 (2^18), r=8, p=1 — same as ethsig's defaultScryptN /
// keystore.StandardScryptN. Takes ~2–5s in a modern browser; that cost
// is paid ONCE per session (or per password change) so it's a fine
// UX trade for the brute-force resistance.
const SCRYPT_N = 262144;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const DK_LEN = 32;

const SEED_LEN = 32; // Ed25519 seed bytes

// ──────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────

export interface KeystoreFile {
  version: number;
  key_type: string;
  identifier: string;
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
 * Encrypts a 32-byte Ed25519 seed with the given password and returns
 * the keystore JSON (compatible with the daemon's keystore CLI).
 *
 * Identifier is the operator-meaningful label — typically the API key ID
 * (e.g. "admin") so the resulting JSON is self-describing.
 */
export async function encryptSeed(
  seed: Uint8Array,
  password: string,
  identifier: string,
): Promise<KeystoreFile> {
  if (seed.length !== SEED_LEN) {
    throw new Error(
      `seed must be ${SEED_LEN} bytes (Ed25519); got ${seed.length}`,
    );
  }
  const pwError = validatePassword(password);
  if (pwError) {
    throw new Error(pwError);
  }

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const derivedKey = await deriveKey(password, salt);
  const aesKey = derivedKey.slice(0, 16);
  const macKey = derivedKey.slice(16, 32);

  const ciphertext = await aesCtrTransform(aesKey, iv, seed);
  const mac = computeMac(macKey, ciphertext);

  return {
    version: 3,
    key_type: "ed25519",
    identifier,
    crypto: {
      cipher: "aes-128-ctr",
      ciphertext: bytesToHex(ciphertext),
      cipherparams: { iv: bytesToHex(iv) },
      kdf: "scrypt",
      kdfparams: {
        n: SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        dklen: DK_LEN,
        salt: bytesToHex(salt),
      },
      mac: bytesToHex(mac),
    },
  };
}

/**
 * Decrypts a keystore JSON. Throws "wrong password" on MAC mismatch — the
 * UI uses this string verbatim to render an unlock-failed message, so
 * don't reword it without also updating Login.tsx.
 *
 * Returns the 32-byte seed plus the identifier (api-key-id) so callers
 * don't have to remember which key they unlocked when they have multiple.
 */
export async function decryptKeystore(
  json: string | KeystoreFile,
  password: string,
): Promise<{ seed: Uint8Array; identifier: string }> {
  const ks: KeystoreFile = typeof json === "string" ? JSON.parse(json) : json;

  if (ks.version !== 3) {
    throw new Error(
      `unsupported keystore version: ${ks.version} (expected 3)`,
    );
  }
  if (ks.key_type !== "ed25519") {
    throw new Error(
      `unsupported key_type: ${ks.key_type} (only ed25519 admin keys are accepted in the web UI)`,
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

  // Honour the params encoded in the file rather than our defaults —
  // someone might have re-encrypted with different N/r/p.
  const derivedKey = await deriveKeyWithParams(
    password,
    salt,
    params.n,
    params.r,
    params.p,
    params.dklen,
  );
  const aesKey = derivedKey.slice(0, 16);
  const macKey = derivedKey.slice(16, 32);

  const actualMac = computeMac(macKey, ciphertext);
  if (!constantTimeEqual(actualMac, expectedMac)) {
    throw new Error("wrong password");
  }

  const seed = await aesCtrTransform(aesKey, iv, ciphertext);
  if (seed.length !== SEED_LEN) {
    throw new Error(
      `decrypted seed has unexpected length ${seed.length} (expected ${SEED_LEN})`,
    );
  }

  return { seed, identifier: ks.identifier };
}

/**
 * Returns null if the password meets the strength policy, otherwise a
 * human-readable error message. Policy: at least 10 characters with at
 * least one each of lowercase letter, uppercase letter, digit, and
 * special character. Mirror the rule in the UI's onboarding form.
 */
export function validatePassword(password: string): string | null {
  if (password.length < 10) {
    return "Password must be at least 10 characters";
  }
  if (!/[a-z]/.test(password)) {
    return "Password must contain a lowercase letter";
  }
  if (!/[A-Z]/.test(password)) {
    return "Password must contain an uppercase letter";
  }
  if (!/[0-9]/.test(password)) {
    return "Password must contain a digit";
  }
  // Special characters: anything that's not a letter or digit. Avoids
  // hardcoding a list operators have to memorise (every weird punctuation
  // counts).
  if (!/[^A-Za-z0-9]/.test(password)) {
    return "Password must contain a special character (e.g. !@#$%)";
  }
  return null;
}

// ──────────────────────────────────────────────────────────────────────
// KDF + cipher primitives
// ──────────────────────────────────────────────────────────────────────

async function deriveKey(
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  return deriveKeyWithParams(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, DK_LEN);
}

async function deriveKeyWithParams(
  password: string,
  salt: Uint8Array,
  n: number,
  r: number,
  p: number,
  dklen: number,
): Promise<Uint8Array> {
  // @noble/hashes scrypt is sync but heavy — we wrap in a microtask so
  // the UI thread has a chance to render the "Unlocking…" indicator
  // before the 2–5s CPU burn. Sync is fine post-yield.
  await new Promise((resolve) => setTimeout(resolve, 0));
  const pwBytes = new TextEncoder().encode(password);
  return scrypt(pwBytes, salt, { N: n, r, p, dkLen: dklen });
}

async function aesCtrTransform(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  // WebCrypto's AES-CTR: counter is the 16-byte IV; length is the number
  // of counter bits (we use 128 to match go-ethereum's
  // ethkeystore.EncryptDataV3 which doesn't fragment the counter).
  // Inputs/outputs must be ArrayBuffer-backed; pass typed-array .buffer
  // when those go through SubtleCrypto.
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "AES-CTR" },
    false,
    ["encrypt", "decrypt"],
  );
  // encrypt and decrypt are symmetric for CTR; we use encrypt for both
  // directions since the operation is identical.
  const out = await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: iv as BufferSource, length: 128 },
    cryptoKey,
    data as BufferSource,
  );
  return new Uint8Array(out);
}

function computeMac(macKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const input = new Uint8Array(macKey.length + ciphertext.length);
  input.set(macKey, 0);
  input.set(ciphertext, macKey.length);
  return keccak_256(input);
}

// ──────────────────────────────────────────────────────────────────────
// Hex + constant-time helpers
// ──────────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
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
