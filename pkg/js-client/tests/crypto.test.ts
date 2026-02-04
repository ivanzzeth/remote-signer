import { parsePrivateKey, signRequest } from '../src/crypto';

describe('crypto', () => {
  it('signRequest should work without external noble sha512Sync setup', () => {
    const priv = parsePrivateKey('0x' + '11'.repeat(32)); // 32 bytes seed
    const sig = signRequest(priv, 1700000000, 'GET', '/health', new Uint8Array());
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);
  });
});
