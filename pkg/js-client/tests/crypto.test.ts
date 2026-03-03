import { parsePrivateKey, signRequestWithNonce, generateNonce } from '../src/crypto';

describe('crypto', () => {
  it('signRequestWithNonce should work without external noble sha512Sync setup', () => {
    const priv = parsePrivateKey('0x' + '11'.repeat(32)); // 32 bytes seed
    const nonce = generateNonce();
    const sig = signRequestWithNonce(priv, 1700000000, nonce, 'GET', '/health', new Uint8Array());
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);
  });
});
