/**
 * E2E tests for Remote Signer JavaScript Client
 *
 * These tests automatically start a Go test server if E2E_EXTERNAL_SERVER is not set.
 * To use an external server, set E2E_EXTERNAL_SERVER=true
 */

// Setup @noble/ed25519 for Node.js environment
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
(ed25519 as any).etc.sha512Sync = (...m: any[]) => sha512((ed25519 as any).etc.concatBytes(...m));

// Import from built dist to avoid ES module issues in Jest
import type { SignRequest } from '../dist';
import { RemoteSignerClient } from '../dist';

// Import test server setup
import { startTestServer, stopTestServer } from './setup-test-server';

// Test configuration from environment or defaults
const useExternalServer = process.env.E2E_EXTERNAL_SERVER === 'true' || process.env.E2E_EXTERNAL_SERVER === '1';

// Well-known test private key (Hardhat/Foundry first account)
// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
const TEST_SIGNER_ADDRESS = process.env.E2E_SIGNER_ADDRESS || '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const TEST_CHAIN_ID = process.env.E2E_CHAIN_ID || '1';

describe('Remote Signer Client E2E Tests', () => {
  let client: RemoteSignerClient;
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
      // Start Go test server
      testServerInfo = await startTestServer();
    }

    // Create client
    client = new RemoteSignerClient({
      baseURL: testServerInfo.baseURL,
      apiKeyID: testServerInfo.apiKeyID,
      privateKey: testServerInfo.privateKey,
      pollInterval: 1000, // 1 second for faster tests
      pollTimeout: 30000, // 30 seconds
    });
  });

  afterAll(async () => {
    if (!useExternalServer) {
      await stopTestServer();
    }
  });

  describe('Health Check', () => {
    it('should check server health', async () => {
      const health = await client.health();
      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('version');
      expect(health.status === 'healthy' || health.status === 'ok').toBe(true);
    });
  });

  describe('Sign Requests', () => {
    it('should sign a personal message', async () => {
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'personal',
        payload: {
          message: 'Hello, World!',
        },
      };

      const response = await client.sign(request, true);

      expect(response).toHaveProperty('request_id');
      expect(response).toHaveProperty('status');
      expect(response.status).toBe('completed');
      expect(response).toHaveProperty('signature');
      expect(response.signature).toBeTruthy();
      expect(response.signature).toMatch(/^0x[a-fA-F0-9]+$/);
    }, 60000);

    it('should sign a hash', async () => {
      const hash = '0x' + '1'.repeat(64); // 32 bytes

      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'hash',
        payload: {
          hash,
        },
      };

      const response = await client.sign(request, true);

      expect(response.status).toBe('completed');
      expect(response.signature).toBeTruthy();
      expect(response.signature).toMatch(/^0x[a-fA-F0-9]+$/);
    }, 60000);

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

      const response = await client.sign(request, true);

      expect(response.status).toBe('completed');
      expect(response.signature).toBeTruthy();
      expect(response.signature).toMatch(/^0x[a-fA-F0-9]+$/);
    }, 60000);

    it('should sign a transaction', async () => {
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'transaction',
        payload: {
          transaction: {
            to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
            value: '1000000000000000000', // 1 ETH
            gas: 21000,
            gasPrice: '20000000000', // 20 gwei
            txType: 'legacy',
          },
        },
      };

      // Submit transaction - it may require manual approval
      let response;
      try {
        response = await client.sign(request, true);
        // If we get here, request was auto-approved
        expect(response.status).toBe('completed');
        expect(response.signature).toBeTruthy();
      } catch (error: any) {
        // If it throws SignError with pending status, manually approve it
        if (error.name === 'SignError' && error.status === 'pending' && error.requestId) {
          const approved = await client.approveRequest(error.requestId, { approved: true });
          expect(approved.status).toBe('completed');
          expect(approved.signature).toBeTruthy();
        } else {
          throw error;
        }
      }
    }, 60000);
  });

  describe('Request Management', () => {
    let testRequestId: string;

    it('should list requests', async () => {
      const response = await client.listRequests({ limit: 10 });

      expect(response).toHaveProperty('requests');
      expect(response).toHaveProperty('total');
      expect(response).toHaveProperty('has_more');
      expect(Array.isArray(response.requests)).toBe(true);
      expect(typeof response.total).toBe('number');
      expect(typeof response.has_more).toBe('boolean');

      if (response.requests.length > 0) {
        testRequestId = response.requests[0].id;
        expect(response.requests[0]).toHaveProperty('id');
        expect(response.requests[0]).toHaveProperty('status');
        expect(response.requests[0]).toHaveProperty('signer_address');
      }
    });

    it('should get request by ID', async () => {
      if (!testRequestId) {
        // Create a request first
        const signResponse = await client.sign({
          chain_id: testServerInfo.chainID,
          signer_address: testServerInfo.signerAddress,
          sign_type: 'personal',
          payload: { message: 'Test for getRequest' },
        }, true);

        testRequestId = signResponse.request_id;
      }

      const request = await client.getRequest(testRequestId);

      expect(request).toHaveProperty('id');
      expect(request.id).toBe(testRequestId);
      expect(request).toHaveProperty('status');
      expect(request).toHaveProperty('signer_address');
      expect(request).toHaveProperty('sign_type');
      expect(request).toHaveProperty('chain_id');
      expect(request).toHaveProperty('created_at');
    });

    it('should filter requests by status', async () => {
      const response = await client.listRequests({
        status: 'completed',
        limit: 5,
      });

      expect(Array.isArray(response.requests)).toBe(true);
      if (response.requests.length > 0) {
        expect(response.requests.every(r => r.status === 'completed')).toBe(true);
      }
    });

    it('should filter requests by signer address', async () => {
      const response = await client.listRequests({
        signer_address: testServerInfo.signerAddress,
        limit: 5,
      });

      expect(Array.isArray(response.requests)).toBe(true);
      if (response.requests.length > 0) {
        expect(response.requests.every(r => r.signer_address === testServerInfo.signerAddress)).toBe(true);
      }
    });

    it('should handle pagination with cursor', async () => {
      const firstPage = await client.listRequests({ limit: 2 });

      if (firstPage.has_more && firstPage.next_cursor) {
        const secondPage = await client.listRequests({
          limit: 2,
          cursor: firstPage.next_cursor,
        });

        expect(Array.isArray(secondPage.requests)).toBe(true);
        // Ensure different requests
        if (firstPage.requests.length > 0 && secondPage.requests.length > 0) {
          expect(firstPage.requests[0].id).not.toBe(secondPage.requests[0].id);
        }
      }
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid API key', async () => {
      const invalidClient = new RemoteSignerClient({
        baseURL: testServerInfo.baseURL,
        apiKeyID: 'invalid-key-id',
        privateKey: testServerInfo.privateKey,
      });

      // Health endpoint doesn't require auth, so test with a protected endpoint
      await expect(invalidClient.listRequests({ limit: 1 })).rejects.toThrow();
    });

    it('should handle invalid signer address', async () => {
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: '0x0000000000000000000000000000000000000000',
        sign_type: 'personal',
        payload: {
          message: 'Test',
        },
      };

      await expect(client.sign(request, true)).rejects.toThrow();
    });

    it('should handle network errors gracefully', async () => {
      const invalidClient = new RemoteSignerClient({
        baseURL: 'http://localhost:99999',
        apiKeyID: testServerInfo.apiKeyID,
        privateKey: testServerInfo.privateKey,
      });

      await expect(invalidClient.health()).rejects.toThrow();
    });

    it('should handle invalid request format', async () => {
      const invalidRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'invalid_type',
        payload: {},
      } as any;

      await expect(client.sign(invalidRequest, true)).rejects.toThrow();
    });
  });

  describe('Polling', () => {
    it('should poll for pending request completion', async () => {
      const request: SignRequest = {
        chain_id: testServerInfo.chainID,
        signer_address: testServerInfo.signerAddress,
        sign_type: 'personal',
        payload: {
          message: 'Polling test',
        },
      };

      const response = await client.sign(request, true);

      expect(response.status).toBe('completed');
      expect(response.signature).toBeTruthy();
    }, 60000); // Longer timeout for polling
  });

  describe('Authentication', () => {
    it('should sign requests with Ed25519', async () => {
      // This test verifies that authentication works
      const health = await client.health();
      expect(health.status === 'healthy' || health.status === 'ok').toBe(true);

      // Test authenticated endpoint
      const requests = await client.listRequests({ limit: 1 });
      expect(requests).toHaveProperty('requests');
    });

    it('should handle authentication errors', async () => {
      const wrongKeyClient = new RemoteSignerClient({
        baseURL: testServerInfo.baseURL,
        apiKeyID: testServerInfo.apiKeyID,
        privateKey: '0000000000000000000000000000000000000000000000000000000000000000',
      });

      // Health endpoint doesn't require auth, so test with a protected endpoint
      await expect(wrongKeyClient.listRequests({ limit: 1 })).rejects.toThrow();
    });
  });
});
