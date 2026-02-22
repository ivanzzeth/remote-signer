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
  useNonce: true // Enable nonce for replay protection
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

// Run examples
async function main() {
  await checkHealth();
  // await signPersonalMessage();
  // await signTransaction();
  // await signTypedData();
}

main().catch(console.error);
