/**
 * Basic usage examples for Remote Signer JavaScript Client
 */

import { RemoteSignerClient, APIError, SignError, TimeoutError } from '../src';

// Initialize client
const client = new RemoteSignerClient({
  baseURL: 'http://localhost:8548',
  apiKeyID: 'my-api-key',
  privateKey: 'your-ed25519-private-key-hex', // 64 hex characters
  pollInterval: 2000, // 2 seconds
  pollTimeout: 300000, // 5 minutes
});

// Example 1: Health check
async function checkHealth() {
  try {
    const health = await client.health();
    console.log('Service health:', health);
  } catch (error) {
    console.error('Health check failed:', error);
  }
}

// Example 2: Sign personal message
async function signPersonalMessage() {
  try {
    const response = await client.sign({
      chain_id: '1',
      signer_address: '0x1234567890123456789012345678901234567890',
      sign_type: 'personal',
      payload: {
        message: 'Hello, World!'
      }
    });

    console.log('Signature:', response.signature);
    console.log('Request ID:', response.request_id);
  } catch (error) {
    console.error('Signing failed:', error);
  }
}

// Example 3: Sign transaction
async function signTransaction() {
  try {
    const response = await client.sign({
      chain_id: '1',
      signer_address: '0x1234567890123456789012345678901234567890',
      sign_type: 'transaction',
      payload: {
        transaction: {
          to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2',
          value: '1000000000000000000', // 1 ETH in wei
          gas: 21000,
          gasPrice: '20000000000',
          txType: 'legacy'
        }
      }
    });

    console.log('Signed transaction:', response.signed_data);
  } catch (error) {
    console.error('Transaction signing failed:', error);
  }
}

// Example 4: Sign EIP-712 typed data
async function signTypedData() {
  try {
    const response = await client.sign({
      chain_id: '1',
      signer_address: '0x1234567890123456789012345678901234567890',
      sign_type: 'typed_data',
      payload: {
        typed_data: {
          types: {
            EIP712Domain: [
              { name: 'name', type: 'string' },
              { name: 'version', type: 'string' },
              { name: 'chainId', type: 'uint256' }
            ],
            Message: [
              { name: 'content', type: 'string' }
            ]
          },
          primaryType: 'Message',
          domain: {
            name: 'Example',
            version: '1',
            chainId: '1'
          },
          message: {
            content: 'Hello'
          }
        }
      }
    });

    console.log('Typed data signature:', response.signature);
  } catch (error) {
    console.error('Typed data signing failed:', error);
  }
}

// Example 5: Get request status
async function getRequestStatus(requestID: string) {
  try {
    const status = await client.getRequest(requestID);
    console.log('Request status:', status);
  } catch (error) {
    console.error('Failed to get request status:', error);
  }
}

// Example 6: List requests
async function listRequests() {
  try {
    const response = await client.listRequests({
      status: 'completed',
      limit: 10
    });

    console.log('Total requests:', response.total);
    console.log('Requests:', response.requests);
  } catch (error) {
    console.error('Failed to list requests:', error);
  }
}

// Example 7: Approve pending request
async function approveRequest(requestID: string) {
  try {
    const response = await client.approveRequest(requestID, {
      approved: true,
      rule_type: 'evm_address_list',
      rule_mode: 'whitelist',
      rule_name: 'Allow transfers to 0x...'
    });

    console.log('Approval result:', response);
  } catch (error) {
    console.error('Failed to approve request:', error);
  }
}

// Example 8: Error handling
async function signWithErrorHandling() {
  try {
    const response = await client.sign({
      chain_id: '1',
      signer_address: '0x...',
      sign_type: 'personal',
      payload: { message: 'Hello' }
    });
    console.log('Success:', response);
  } catch (error) {
    if (error instanceof APIError) {
      console.error('API Error:', error.statusCode, error.message);
    } else if (error instanceof SignError) {
      console.error('Sign Error:', error.requestID, error.status);
    } else if (error instanceof TimeoutError) {
      console.error('Timeout waiting for approval');
    } else {
      console.error('Unknown error:', error);
    }
  }
}

// =============================================================================
// TLS / mTLS examples (Node.js only)
// =============================================================================

// Example 9: Node.js with self-signed CA (TLS only, no client cert)
function createTLSClient() {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require('fs');

  return new RemoteSignerClient({
    baseURL: 'https://localhost:8549',
    apiKeyID: 'my-api-key',
    privateKey: 'your-ed25519-private-key-hex',
    httpClient: {
      tls: {
        ca: fs.readFileSync('certs/ca.crt'),
      },
    },
  });
}

// Example 10: Node.js with mTLS (client certificate required by server)
function createMTLSClient() {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require('fs');

  return new RemoteSignerClient({
    baseURL: 'https://localhost:8549',
    apiKeyID: 'my-api-key',
    privateKey: 'your-ed25519-private-key-hex',
    httpClient: {
      timeout: 30000,
      tls: {
        ca: fs.readFileSync('certs/ca.crt'),      // CA to verify server cert
        cert: fs.readFileSync('certs/client.crt'), // Client certificate
        key: fs.readFileSync('certs/client.key'),  // Client private key
      },
    },
  });
}

// Example 11: Skip certificate verification (testing only!)
function createInsecureClient() {
  return new RemoteSignerClient({
    baseURL: 'https://localhost:8549',
    apiKeyID: 'my-api-key',
    privateKey: 'your-ed25519-private-key-hex',
    httpClient: {
      tls: {
        rejectUnauthorized: false, // WARNING: insecure, testing only
      },
    },
  });
}

// Example 12: Browser client (behind reverse proxy, no TLS config needed)
// In browser environments, TLS is handled by the browser itself.
// Use a reverse proxy (Nginx/Caddy) with a public TLS certificate.
function createBrowserClient() {
  return new RemoteSignerClient({
    baseURL: 'https://signer.example.com', // Reverse proxy URL
    apiKeyID: 'my-api-key',
    privateKey: 'your-ed25519-private-key-hex',
    // No httpClient.tls needed - browser handles TLS natively
  });
}

// Example 13: Custom fetch function (advanced)
function createCustomFetchClient() {
  const customFetch: typeof fetch = async (input, init) => {
    console.log('Custom fetch:', input);
    return globalThis.fetch(input, init);
  };

  return new RemoteSignerClient({
    baseURL: 'http://localhost:8548',
    apiKeyID: 'my-api-key',
    privateKey: 'your-ed25519-private-key-hex',
    httpClient: {
      fetch: customFetch,
    },
  });
}

// Run examples
async function main() {
  await checkHealth();
  // await signPersonalMessage();
  // await signTransaction();
  // await signTypedData();
}

main().catch(console.error);
