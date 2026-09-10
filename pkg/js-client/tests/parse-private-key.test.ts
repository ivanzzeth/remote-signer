import { parsePrivateKey } from '../src/crypto';

const SEED = new Uint8Array(32).map((_, i) => i + 1);
const PUB = new Uint8Array(32).map((_, i) => 200 - i); // stand-in public half
const FULL = new Uint8Array([...SEED, ...PUB]);

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

// A real Ed25519 PKCS#8 DER: 16-byte prefix + 32-byte seed = 48 bytes.
const PKCS8 = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ...SEED,
]);

describe('parsePrivateKey', () => {
  // Every shape an operator actually has. The bare-base64 ones are what you get
  // off a deployed daemon, where there is no file to open — the same input the
  // CLI's --api-key-base64 takes. Pasting one into the web UI used to fail with
  // "expected hex or PKCS#8 PEM input".
  it.each([
    ['32-byte Uint8Array', SEED],
    ['64-byte Uint8Array', FULL],
    ['hex seed', hex(SEED)],
    ['hex seed with 0x', '0x' + hex(SEED)],
    ['hex full key', hex(FULL)],
    ['PKCS#8 PEM block', `-----BEGIN PRIVATE KEY-----\n${b64(PKCS8)}\n-----END PRIVATE KEY-----`],
    ['bare base64 PKCS#8 DER', b64(PKCS8)],
    ['bare base64 seed', b64(SEED)],
    ['bare base64 full key', b64(FULL)],
    ['bare base64 with whitespace', `  ${b64(PKCS8)}\n`],
  ])('accepts %s and returns the seed', (_name, input) => {
    expect(Array.from(parsePrivateKey(input as never))).toEqual(Array.from(SEED));
  });

  // ⛔ 64 hex characters are also 64 valid base64 characters, and 64 % 4 === 0,
  // so a hex seed decodes cleanly as 48 bytes of base64. Hex must be tried
  // first; checking base64 first reads every hex key as a different key.
  it('reads an all-hex string as hex, not as base64', () => {
    const allHexLookingBase64 = 'abcdef0123456789'.repeat(4); // 64 chars, valid as both
    const got = parsePrivateKey(allHexLookingBase64);
    expect(Array.from(got)).toEqual(
      Array.from(Buffer.from(allHexLookingBase64, 'hex'))
    );
  });

  it.each([
    ['not hex, not base64', 'this is not a key!!'],
    ['base64 that decodes too short', Buffer.from('short').toString('base64')],
  ])('refuses %s', (_name, input) => {
    expect(() => parsePrivateKey(input)).toThrow();
  });

  it('names all three accepted forms when it refuses', () => {
    expect(() => parsePrivateKey('this is not a key!!')).toThrow(/hex, base64, or a PKCS#8 PEM/);
  });
});
