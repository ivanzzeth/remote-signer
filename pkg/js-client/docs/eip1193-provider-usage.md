# EIP-1193 Provider Usage Guide

## Overview

The `EIP1193Provider` is a fully compliant EIP-1193 Ethereum Provider implementation with multi-account support. It's compatible with MetaMask's interface and works with most Ethereum DApps.

## Features

- ✅ Full EIP-1193 compliance
- ✅ Multi-account management (switchAccount, addAccount, removeAccount)
- ✅ Three initialization modes (client auto-fetch, HD wallet derive, manual)
- ✅ Complete event system (connect, disconnect, chainChanged, accountsChanged, message)
- ✅ MetaMask compatibility (selectedAddress, isMetaMask, isConnected)
- ✅ Standard ProviderRpcError with EIP-1193 error codes
- ✅ Chain switching support

## Installation

```bash
npm install remote-signer-client
```

## Quick Start

### 1. Auto-fetch signers from backend (Recommended)

```typescript
import { RemoteSignerClient, EIP1193Provider } from 'remote-signer-client';

// Create client
const client = new RemoteSignerClient({
  baseURL: 'http://localhost:8548',
  apiKeyID: 'my-api-key',
  privateKey: 'your-ed25519-private-key-hex',
});

// Create provider with auto-fetch mode
const provider = await EIP1193Provider.create({
  signersSource: {
    type: "client",
    client: client,
    chainId: 1, // Optional, defaults to provider's defaultChainId
  },
  defaultChainId: 1, // Ethereum mainnet
  rpcOverrides: {
    1: "https://eth-mainnet.alchemyapi.io/v2/YOUR-API-KEY",
    137: "https://polygon-rpc.com",
  },
});

// Provider is ready to use
console.log("Connected:", provider.isConnected());
console.log("Active account:", provider.selectedAddress);

// Get all accounts
const accounts = await provider.request({ method: "eth_accounts" });
console.log("All accounts:", accounts);
```

### 2. Derive from HD wallet

```typescript
const provider = await EIP1193Provider.create({
  signersSource: {
    type: "hdwallet",
    client: client,
    primaryAddress: "0xYourPrimaryAddress",
    chainId: "1",
    start: 0,
    count: 10, // Derive 10 addresses
  },
  defaultChainId: 1,
});
```

### 3. Manual signer list

```typescript
import { RemoteSigner } from 'remote-signer-client';

const signer1 = new RemoteSigner(client.evm.sign, "0xAddress1", "1");
const signer2 = new RemoteSigner(client.evm.sign, "0xAddress2", "1");

const provider = await EIP1193Provider.create({
  signersSource: {
    type: "manual",
    signers: [signer1, signer2],
  },
  defaultChainId: 1,
});
```

## Account Management

### Switch active account

```typescript
// Switch by index
await provider.switchAccount(1);

// Switch by address
await provider.switchAccount("0xAddress2");

// Listen to account changes
provider.on("accountsChanged", (accounts) => {
  console.log("Active account changed to:", accounts[0]);
  console.log("All accounts:", accounts);
});
```

### Add new account

```typescript
const newSigner = new RemoteSigner(client.evm.sign, "0xNewAddress", "1");
await provider.addAccount(newSigner);
```

### Remove account

```typescript
// Remove by index
await provider.removeAccount(1);

// Remove by address
await provider.removeAccount("0xAddress2");
```

### Disconnect all accounts

```typescript
await provider.disconnect();

provider.on("disconnect", (error) => {
  console.log("Provider disconnected:", error.message);
});
```

## Chain Switching

```typescript
// Switch to Polygon (137)
await provider.switchChain(137);

// Or use hex format
await provider.switchChain("0x89");

// Listen to chain changes
provider.on("chainChanged", (chainId) => {
  console.log("Chain changed to:", parseInt(chainId, 16));
});

// Chain switching also triggers accountsChanged event
provider.on("accountsChanged", (accounts) => {
  console.log("Accounts after chain switch:", accounts);
});
```

## Signing Messages

### Personal Sign

```typescript
const message = "0x48656c6c6f20576f726c64"; // "Hello World" in hex
const signature = await provider.request({
  method: "personal_sign",
  params: [message, provider.selectedAddress],
});
```

### Sign Typed Data (EIP-712)

```typescript
const typedData = {
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ],
    Person: [
      { name: "name", type: "string" },
      { name: "wallet", type: "address" },
    ],
  },
  domain: {
    name: "Ether Mail",
    version: "1",
    chainId: 1,
    verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
  },
  primaryType: "Person",
  message: {
    name: "Bob",
    wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
  },
};

const signature = await provider.request({
  method: "eth_signTypedData_v4",
  params: [provider.selectedAddress, JSON.stringify(typedData)],
});
```

### Sign Transaction

```typescript
const tx = {
  from: provider.selectedAddress,
  to: "0xRecipientAddress",
  value: "0x1000000000000000", // 0.001 ETH
  gas: "0x5208",
  gasPrice: "0x3B9ACA00", // 1 gwei
};

const signedTx = await provider.request({
  method: "eth_signTransaction",
  params: [tx],
});
```

### Send Transaction (Sign + Broadcast)

```typescript
const txHash = await provider.request({
  method: "eth_sendTransaction",
  params: [tx],
});

console.log("Transaction hash:", txHash);
```

## Event Handling

### All EIP-1193 Events

```typescript
// Connection events
provider.on("connect", (connectInfo) => {
  console.log("Connected to chain:", connectInfo.chainId);
});

provider.on("disconnect", (error) => {
  console.log("Disconnected:", error.message);
});

// Account changes
provider.on("accountsChanged", (accounts) => {
  if (accounts.length === 0) {
    console.log("No accounts available");
  } else {
    console.log("Active account:", accounts[0]);
    console.log("All accounts:", accounts);
  }
});

// Chain changes
provider.on("chainChanged", (chainId) => {
  console.log("Chain ID:", chainId);
  // Recommended: reload the page on chain change
  // window.location.reload();
});

// Generic message event
provider.on("message", (message) => {
  console.log("Message:", message.type, message.data);
});
```

### Remove Event Listeners

```typescript
const handler = (accounts) => console.log("Accounts:", accounts);

provider.on("accountsChanged", handler);
provider.removeListener("accountsChanged", handler);
```

## Error Handling

```typescript
import { ProviderRpcError, ProviderErrorCode } from 'remote-signer-client';

try {
  const signature = await provider.request({
    method: "personal_sign",
    params: ["0xmessage", "0xWrongAddress"],
  });
} catch (error) {
  if (error instanceof ProviderRpcError) {
    switch (error.code) {
      case ProviderErrorCode.USER_REJECTED:
        console.log("User rejected the request");
        break;
      case ProviderErrorCode.UNAUTHORIZED:
        console.log("Unauthorized:", error.message);
        break;
      case ProviderErrorCode.UNSUPPORTED_METHOD:
        console.log("Method not supported:", error.message);
        break;
      case ProviderErrorCode.DISCONNECTED:
        console.log("Provider is disconnected");
        break;
      case ProviderErrorCode.CHAIN_DISCONNECTED:
        console.log("Not connected to requested chain");
        break;
      default:
        console.log("RPC error:", error.code, error.message);
    }
  } else {
    console.error("Unknown error:", error);
  }
}
```

## Browser Integration

### Inject into window.ethereum

```typescript
// In your DApp initialization
const provider = await EIP1193Provider.create({ /* config */ });

// Make it available as window.ethereum
(window as any).ethereum = provider;

// Now DApps can detect and use it
if ((window as any).ethereum) {
  console.log("Ethereum provider detected!");
  console.log("Is MetaMask?", (window as any).ethereum.isMetaMask);
}
```

### Use with Web3.js

```typescript
import Web3 from 'web3';

const provider = await EIP1193Provider.create({ /* config */ });
const web3 = new Web3(provider as any);

// Now you can use web3 as normal
const accounts = await web3.eth.getAccounts();
const balance = await web3.eth.getBalance(accounts[0]);
```

### Use with ethers.js

```typescript
import { ethers } from 'ethers';

const provider = await EIP1193Provider.create({ /* config */ });
const ethersProvider = new ethers.BrowserProvider(provider as any);

const signer = await ethersProvider.getSigner();
const address = await signer.getAddress();
const balance = await ethersProvider.getBalance(address);
```

## Advanced Configuration

### Dynamic RPC Resolver

```typescript
const provider = await EIP1193Provider.create({
  signersSource: { /* ... */ },
  
  // Use rpcResolver for dynamic RPC URL resolution
  rpcResolver: async (chainId: number) => {
    const rpcUrls: Record<number, string> = {
      1: "https://eth-mainnet.alchemyapi.io/v2/YOUR-API-KEY",
      137: "https://polygon-rpc.com",
      56: "https://bsc-dataseed.binance.org",
    };
    
    return rpcUrls[chainId] || `https://rpc.chain-${chainId}.example.com`;
  },
});
```

### Set Default Active Account

```typescript
const provider = await EIP1193Provider.create({
  signersSource: { /* ... */ },
  defaultAccountIndex: 2, // Start with third account as active
});
```

## MetaMask Compatibility

The provider exposes the same interface as MetaMask:

```typescript
console.log(provider.isMetaMask); // true
console.log(provider.selectedAddress); // "0x..."
console.log(provider.chainId); // "0x1"
console.log(provider.isConnected()); // true
```

This ensures compatibility with DApps that check for MetaMask:

```typescript
if (window.ethereum?.isMetaMask) {
  // DApp will recognize our provider as MetaMask-compatible
  await window.ethereum.request({ method: "eth_requestAccounts" });
}
```

## Complete Example

```typescript
import { RemoteSignerClient, EIP1193Provider, ProviderRpcError } from 'remote-signer-client';

async function main() {
  // 1. Create client
  const client = new RemoteSignerClient({
    baseURL: 'http://localhost:8548',
    apiKeyID: 'my-api-key',
    privateKey: 'your-ed25519-private-key-hex',
  });

  // 2. Create provider
  const provider = await EIP1193Provider.create({
    signersSource: {
      type: "client",
      client: client,
      chainId: 1,
    },
    defaultChainId: 1,
    rpcOverrides: {
      1: "https://eth-mainnet.alchemyapi.io/v2/YOUR-API-KEY",
    },
  });

  // 3. Setup event listeners
  provider.on("accountsChanged", (accounts) => {
    console.log("Accounts changed:", accounts);
  });

  provider.on("chainChanged", (chainId) => {
    console.log("Chain changed:", chainId);
  });

  // 4. Get accounts
  const accounts = await provider.request({ method: "eth_accounts" });
  console.log("Available accounts:", accounts);

  // 5. Sign a message
  try {
    const message = "0x48656c6c6f"; // "Hello" in hex
    const signature = await provider.request({
      method: "personal_sign",
      params: [message, provider.selectedAddress],
    });
    console.log("Signature:", signature);
  } catch (error) {
    if (error instanceof ProviderRpcError) {
      console.error("Signing failed:", error.code, error.message);
    }
  }

  // 6. Switch account
  if (accounts.length > 1) {
    await provider.switchAccount(1);
    console.log("Switched to:", provider.selectedAddress);
  }

  // 7. Cleanup
  await provider.disconnect();
}

main().catch(console.error);
```

## Best Practices

1. **Always use async/await** with `EIP1193Provider.create()` - it's an async factory method
2. **Handle errors** - wrap RPC calls in try/catch and check for `ProviderRpcError`
3. **Listen to events** - especially `accountsChanged` and `chainChanged`
4. **Verify addresses** - check that the address in request params matches `selectedAddress`
5. **Configure RPC URLs** - provide `rpcOverrides` or `rpcResolver` for all chains you support
6. **Clean up** - call `disconnect()` when done to prevent memory leaks

## Breaking Changes from v0.0.5

If you're upgrading from the old single-account provider:

### Old (v0.0.5)
```typescript
const provider = new EIP1193Provider({
  signer: remoteSigner,
  chainId: 1,
  rpcUrl: "https://...",
});
```

### New (v0.0.6+)
```typescript
const provider = await EIP1193Provider.create({
  signersSource: {
    type: "manual",
    signers: [remoteSigner],
  },
  defaultChainId: 1,
  rpcOverrides: { 1: "https://..." },
});
```

Key changes:
- ✅ Constructor replaced with `async create()` method
- ✅ Single `signer` → multi-account `signersSource`
- ✅ `rpcUrl` → `rpcOverrides` or `rpcResolver`
- ✅ `eth_accounts` now returns all accounts (active first)
- ✅ Chain switching emits both `chainChanged` and `accountsChanged`
- ✅ All errors are now `ProviderRpcError` with standard codes

## Troubleshooting

### "No RPC URL configured for chain X"

Configure RPC URLs for the chain:

```typescript
rpcOverrides: {
  1: "https://eth-mainnet.alchemyapi.io/v2/YOUR-API-KEY",
  // Add other chains as needed
},
```

### "Address mismatch" errors

Ensure you're using the active account in signing requests:

```typescript
const address = provider.selectedAddress;
await provider.request({
  method: "personal_sign",
  params: [message, address], // Use active address
});
```

### Events not firing

Make sure you register event listeners AFTER creating the provider:

```typescript
const provider = await EIP1193Provider.create({ /* config */ });
provider.on("accountsChanged", handler); // Register AFTER create
```

## Further Reading

- [EIP-1193 Specification](https://eips.ethereum.org/EIPS/eip-1193)
- [MetaMask Provider API](https://docs.metamask.io/guide/ethereum-provider.html)
- [Remote Signer Documentation](../README.md)
