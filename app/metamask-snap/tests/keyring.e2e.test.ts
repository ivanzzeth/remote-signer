/**
 * E2E tests for Keyring mode
 *
 * These tests do NOT run a real MetaMask extension. They validate our exported
 * `onKeyringRequest` handler + state transitions against the Go e2e server.
 */

// Mock MetaMask Snap environment
let mockState: Record<string, any> = {};
let mockDialogResponse: boolean = true; // Default to approve

const mockSnapRequest = jest.fn(async (args: any) => {
  if (args.method === 'snap_manageState') {
    const { operation, newState } = args.params;
    if (operation === 'get') {
      return mockState || null;
    } else if (operation === 'update') {
      mockState = { ...mockState, ...newState };
      return undefined;
    }
  } else if (args.method === 'snap_dialog') {
    return mockDialogResponse;
  }
  return undefined;
});

(global as any).snap = { request: mockSnapRequest };

// Import handlers after mocking snap
// @ts-ignore
import { onRpcRequest, onKeyringRequest } from '../src/index';

describe('MetaMask Snap Keyring E2E Tests', () => {
  const TEST_BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:8548';
  const TEST_API_KEY_ID = process.env.E2E_API_KEY_ID || 'test-admin-key';
  const TEST_PRIVATE_KEY = (process.env.E2E_PRIVATE_KEY ||
    'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890')
    .trim()
    .slice(0, 64);

  beforeAll(async () => {
    // reset state for this suite
    mockState = {};
    mockDialogResponse = true;

    // configure (this writes baseURL/apiKeyID/privateKey into state)
    const res = await onRpcRequest({
      origin: 'test',
      request: {
        jsonrpc: '2.0',
        id: 1,
        method: 'configure',
        params: {
          baseURL: TEST_BASE_URL,
          apiKeyID: TEST_API_KEY_ID,
          privateKey: TEST_PRIVATE_KEY,
        },
      },
    } as any);
    if ((res as any).error) {
      throw new Error(`configure failed: ${(res as any).error.message}`);
    }
  });

  afterEach(() => {
    mockDialogResponse = true;
    jest.clearAllMocks();
  });

  it('should create and list a remote signer account', async () => {
    const acct = await onKeyringRequest({
      origin: 'test',
      request: {
        method: 'createAccount',
        params: { options: { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' } },
      },
    } as any);

    expect(acct).toHaveProperty('id');
    expect(acct).toHaveProperty('address');

    const list = await onKeyringRequest({
      origin: 'test',
      request: { method: 'listAccounts' },
    } as any);
    expect(Array.isArray(list)).toBe(true);
    expect((list as any[]).length).toBeGreaterThan(0);
  });

  it('should sign personal_sign via remote signer', async () => {
    const acct = await onKeyringRequest({
      origin: 'test',
      request: {
        method: 'createAccount',
        params: { options: { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' } },
      },
    } as any);

    const resp = await onKeyringRequest({
      origin: 'test',
      request: {
        id: 'req-1',
        scope: '',
        account: (acct as any).id,
        request: {
          method: 'personal_sign',
          params: [
            'Hello, World!',
            '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
          ],
        },
      },
    } as any);

    expect(resp).toHaveProperty('pending');
    expect((resp as any).pending).toBe(false);
    expect(resp).toHaveProperty('result');
    expect(typeof (resp as any).result).toBe('string');
    expect((resp as any).result).toMatch(/^0x[a-fA-F0-9]+$/);
  });
});
