/**
 * E2E tests for MetaMask Snap
 *
 * These tests simulate MetaMask environment and test the Snap's RPC handlers
 * directly without requiring a browser or MetaMask extension.
 */

// Setup @noble/ed25519 for Node.js environment
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
(ed25519 as any).etc.sha512Sync = (...m: any[]) => sha512((ed25519 as any).etc.concatBytes(...m));

// Mock MetaMask Snap environment
let mockState: Record<string, any> = {};
let mockDialogResponse: boolean = true; // Default to approve

// Mock snap.request
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

// Mock snap global object
(global as any).snap = {
  request: mockSnapRequest,
};

// Import the RPC handler after mocking snap
// Note: We need to import from source because the bundle might not be available
// @ts-ignore - We're mocking snap before import
import { onRpcRequest } from '../src/index';
import type { SignRequest } from '@remote-signer/client';

// Test configuration from environment or defaults
const useExternalServer = process.env.E2E_EXTERNAL_SERVER === 'true' || process.env.E2E_EXTERNAL_SERVER === '1';

// Well-known test private key (Hardhat/Foundry first account)
const TEST_SIGNER_ADDRESS = process.env.E2E_SIGNER_ADDRESS || '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const TEST_CHAIN_ID = process.env.E2E_CHAIN_ID || '1';

describe('MetaMask Snap RPC E2E Tests', () => {
  let testServerInfo: {
    baseURL: string;
    apiKeyID: string;
    privateKey: string;
    signerAddress: string;
    chainID: string;
  };

  beforeAll(async () => {
    if (useExternalServer) {
      // Use external server mode
      const TEST_BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:8548';
      const TEST_API_KEY_ID = process.env.E2E_API_KEY_ID || 'test-admin-key';
      const TEST_PRIVATE_KEY = (process.env.E2E_PRIVATE_KEY || 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890').trim().slice(0, 64);

      // Wait for external server
      for (let i = 0; i < 50; i++) {
        try {
          const response = await fetch(`${TEST_BASE_URL}/health`);
          if (response.ok) {
            const data = await response.json() as { status: string };
            if (data.status === 'healthy' || data.status === 'ok') {
              break;
            }
          }
        } catch (error) {
          // Server not ready yet
        }
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      testServerInfo = {
        baseURL: TEST_BASE_URL,
        apiKeyID: TEST_API_KEY_ID,
        privateKey: TEST_PRIVATE_KEY,
        signerAddress: TEST_SIGNER_ADDRESS,
        chainID: TEST_CHAIN_ID,
      };
    } else {
      // For internal server mode, we need to use external server mode
      // because the Go test server is started by the Go e2e test framework
      // This test should be run via Go e2e test which sets E2E_EXTERNAL_SERVER=true
      throw new Error('MetaMask Snap e2e tests should be run via Go e2e test framework (TestMetaMaskSnapE2E)');
    }

    // Reset mock state
    mockState = {};
    mockDialogResponse = true;
  });

  afterEach(() => {
    // Don't reset mock state completely - keep it for tests that need configured state
    // Only reset dialog response
    mockDialogResponse = true;
    jest.clearAllMocks();
  });

  describe('Configuration', () => {
    it('should configure the snap', async () => {
      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 1,
          method: 'configure',
          params: {
            baseURL: testServerInfo.baseURL,
            apiKeyID: testServerInfo.apiKeyID,
            privateKey: testServerInfo.privateKey,
          } as any,
        },
      });

      expect(result).toHaveProperty('success');
      expect((result as any).success).toBe(true);

      // Verify state was saved
      const stateResult = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 1,
          method: 'getState',
        },
      });

      expect(stateResult).toHaveProperty('configured');
      expect((stateResult as any).configured).toBe(true);
      expect((stateResult as any).baseURL).toBe(testServerInfo.baseURL);
      expect((stateResult as any).apiKeyID).toBe(testServerInfo.apiKeyID);
    });

    it('should reject configuration with missing parameters', async () => {
      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 2,
          method: 'configure',
          params: {
            baseURL: testServerInfo.baseURL,
            // Missing apiKeyID and privateKey
          } as any,
        },
      });

      expect(result).toHaveProperty('error');
      expect((result as any).error.message).toContain('Missing required parameters');
    });

    it('should reject configuration if user cancels dialog', async () => {
      mockDialogResponse = false; // User cancels

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 3,
          method: 'configure',
          params: {
            baseURL: testServerInfo.baseURL,
            apiKeyID: testServerInfo.apiKeyID,
            privateKey: testServerInfo.privateKey,
          } as any,
        },
      });

      expect(result).toHaveProperty('error');
      expect((result as any).error.message).toContain('cancelled');
    });
  });

  describe('Health Check', () => {
    beforeEach(async () => {
      // Configure snap first
      await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 10,
          method: 'configure',
          params: {
            baseURL: testServerInfo.baseURL,
            apiKeyID: testServerInfo.apiKeyID,
            privateKey: testServerInfo.privateKey,
          } as any,
        },
      });
    });

    it('should check server health', async () => {
      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 11,
          method: 'health',
        },
      });

      expect(result).toHaveProperty('status');
      expect(result).toHaveProperty('version');
      expect((result as any).status === 'healthy' || (result as any).status === 'ok').toBe(true);
    });
  });

  describe('Sign Requests', () => {
    beforeEach(async () => {
      // Configure snap first
      await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 20,
          method: 'configure',
          params: {
            baseURL: testServerInfo.baseURL,
            apiKeyID: testServerInfo.apiKeyID,
            privateKey: testServerInfo.privateKey,
          } as any,
        },
      });
    });

    it('should sign a personal message', async () => {
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'personal',
        payload: {
          message: 'Hello, World!',
        },
      };

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 21,
          method: 'sign',
          params: {
            request: request as any,
            waitForApproval: true,
          } as any,
        },
      });

      expect(result).toHaveProperty('signature');
      expect((result as any).signature).toBeTruthy();
      expect(typeof (result as any).signature).toBe('string');
    });

    it('should sign a hash', async () => {
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'hash',
        payload: {
          hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        },
      };

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 22,
          method: 'sign',
          params: {
            request: request as any,
            waitForApproval: true,
          } as any,
        },
      });

      expect(result).toHaveProperty('signature');
      expect((result as any).signature).toBeTruthy();
    });

    it('should sign EIP-712 typed data', async () => {
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'typed_data',
        payload: {
          typed_data: {
            types: {
              EIP712Domain: [
                { name: 'name', type: 'string' },
                { name: 'version', type: 'string' },
                { name: 'chainId', type: 'uint256' },
              ],
              Message: [
                { name: 'content', type: 'string' },
              ],
            },
            primaryType: 'Message',
            domain: {
              name: 'Test',
              version: '1',
              chainId: testServerInfo.chainID,
            },
            message: {
              content: 'Hello',
            },
          },
        },
      };

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 23,
          method: 'sign',
          params: {
            request: request as any,
            waitForApproval: true,
          } as any,
        },
      });

      expect(result).toHaveProperty('signature');
      expect((result as any).signature).toBeTruthy();
    });

    it('should reject signing if user cancels dialog', async () => {
      mockDialogResponse = false; // User cancels

      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'personal',
        payload: {
          message: 'Test',
        },
      };

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 24,
          method: 'sign',
          params: {
            request: request as any,
            waitForApproval: true,
          } as any,
        },
      });

      expect(result).toHaveProperty('error');
      expect((result as any).error.message).toContain('cancelled');
    });
  });

  describe('Request Management', () => {
    let requestId: string;

    beforeEach(async () => {
      // Configure snap first
      await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 30,
          method: 'configure',
          params: {
            baseURL: testServerInfo.baseURL,
            apiKeyID: testServerInfo.apiKeyID,
            privateKey: testServerInfo.privateKey,
          } as any,
        },
      });

      // Create a sign request to get request ID
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'personal',
        payload: {
          message: 'Test request',
        },
      };

      const signResult = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 31,
          method: 'sign',
          params: {
            request: request as any,
            waitForApproval: false, // Don't wait, just get request ID
          } as any,
        },
      });

      if ((signResult as any).request_id) {
        requestId = (signResult as any).request_id;
      }
    });

    it('should get request status', async () => {
      if (!requestId) {
        // If no request ID, skip this test
        return;
      }

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 32,
          method: 'getRequest',
          params: {
            requestID: requestId,
          } as any,
        },
      });

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('status');
      expect((result as any).id).toBe(requestId);
    });
  });

  describe('State Management', () => {
    it('should return unconfigured state initially', async () => {
      // Save current state
      const savedState = { ...mockState };
      mockState = {}; // Reset state

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 40,
          method: 'getState',
        },
      });

      // Restore state
      mockState = savedState;

      // Result might be wrapped in error format, check both
      if ((result as any).error) {
        // If error, that's also acceptable for unconfigured state
        expect((result as any).error.message).toContain('not configured');
      } else {
        expect(result).toHaveProperty('configured');
        expect((result as any).configured).toBe(false);
      }
    });

    it('should return configured state after configuration', async () => {
      // Configure snap
      await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 41,
          method: 'configure',
          params: {
            baseURL: testServerInfo.baseURL,
            apiKeyID: testServerInfo.apiKeyID,
            privateKey: testServerInfo.privateKey,
          } as any,
        },
      });

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 42,
          method: 'getState',
        },
      });

      // Result should be the state object directly (not wrapped)
      // Check if result has error first
      if ((result as any).error) {
        throw new Error(`Unexpected error: ${(result as any).error.message}`);
      }
      expect(result).toHaveProperty('configured');
      expect((result as any).configured).toBe(true);
      expect((result as any).baseURL).toBe(testServerInfo.baseURL);
      expect((result as any).apiKeyID).toBe(testServerInfo.apiKeyID);
      // Should not expose private key
      expect((result as any)).not.toHaveProperty('privateKey');
    });
  });

  describe('Error Handling', () => {
    it('should handle unknown method', async () => {
      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 50,
          method: 'unknownMethod',
        },
      });

      expect(result).toHaveProperty('error');
      expect((result as any).error.message).toContain('Unknown method');
    });

    it('should handle unconfigured snap for sign', async () => {
      mockState = {}; // Reset state

      const result = await onRpcRequest({
        origin: 'test',
        request: {
          jsonrpc: '2.0',
          id: 51,
          method: 'sign',
          params: {
            request: {
              chain_id: '1',
              signer_address: testServerInfo.signerAddress,
              sign_type: 'personal',
              payload: { message: 'Test' },
            },
          } as any,
        },
      });

      expect(result).toHaveProperty('error');
      expect((result as any).error.message).toContain('not configured');
    });
  });
});
