/**
 * Example usage of Remote Signer MetaMask Snap
 * 
 * This file demonstrates how to use the snap from a dApp
 */

// Example: Configure the snap
async function configureSnap(snapId: string) {
  const result = await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'configure',
        params: {
          baseURL: 'http://localhost:8548',
          apiKeyID: 'my-api-key',
          privateKey: 'your-ed25519-private-key-hex' // 64 hex characters
        }
      }
    }
  });

  console.log('Configuration result:', result);
  return result;
}

// Example: Sign a personal message
async function signPersonalMessage(snapId: string) {
  const response = await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'sign',
        params: {
          request: {
            chain_id: '1',
            signer_address: '0x1234567890123456789012345678901234567890',
            sign_type: 'personal',
            payload: {
              message: 'Hello, World!'
            }
          },
          waitForApproval: true
        }
      }
    }
  });

  console.log('Signature:', response.signature);
  return response;
}

// Example: Sign a transaction
async function signTransaction(snapId: string) {
  const response = await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'sign',
        params: {
          request: {
            chain_id: '1',
            signer_address: '0x1234567890123456789012345678901234567890',
            sign_type: 'transaction',
            payload: {
              transaction: {
                to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
                value: '1000000000000000000', // 1 ETH in wei
                gas: 21000,
                gasPrice: '20000000000',
                txType: 'legacy'
              }
            }
          },
          waitForApproval: true
        }
      }
    }
  });

  console.log('Signed transaction:', response.signed_data);
  return response;
}

// Example: Sign EIP-712 typed data
async function signTypedData(snapId: string) {
  const response = await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'sign',
        params: {
          request: {
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
          },
          waitForApproval: true
        }
      }
    }
  });

  console.log('Typed data signature:', response.signature);
  return response;
}

// Example: Get request status
async function getRequestStatus(snapId: string, requestID: string) {
  const status = await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'getRequest',
        params: {
          requestID
        }
      }
    }
  });

  console.log('Request status:', status);
  return status;
}

// Example: Health check
async function checkHealth(snapId: string) {
  const health = await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'health'
      }
    }
  });

  console.log('Health:', health);
  return health;
}

// Example: Get snap state
async function getSnapState(snapId: string) {
  const state = await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'getState'
      }
    }
  });

  console.log('Snap state:', state);
  return state;
}

// Export for use in dApps
export {
  configureSnap,
  signPersonalMessage,
  signTransaction,
  signTypedData,
  getRequestStatus,
  checkHealth,
  getSnapState
};
