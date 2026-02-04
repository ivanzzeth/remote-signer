/**
 * Setup script to start Go test server for e2e tests
 */

import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const PROJECT_ROOT = path.resolve(__dirname, '../../..');
const TEST_SERVER_PORT = 8549; // Use different port to avoid conflicts
const TEST_SERVER_READY_FILE = path.join(__dirname, '.test-server-ready');

interface TestServerInfo {
  baseURL: string;
  apiKeyID: string;
  privateKey: string;
  signerAddress: string;
  chainID: string;
  process: ChildProcess;
}

let testServerInfo: TestServerInfo | null = null;

/**
 * Start Go test server
 * The Go test server will generate its own API keys and output them
 */
export async function startTestServer(): Promise<TestServerInfo> {
  if (testServerInfo) {
    return testServerInfo;
  }

  console.log('Starting Go test server...');
  console.log(`Project root: ${PROJECT_ROOT}`);

  // Generate Ed25519 key pair for API authentication
  // We'll use the same keys that Go test server expects
  const apiKeyID = 'test-admin-key-e2e';
  // Generate a valid Ed25519 private key (32 bytes = 64 hex chars)
  let apiPrivateKey: string;

  try {
    // Try to generate using Node.js crypto
    const crypto = require('crypto');
    const keyPair = crypto.generateKeyPairSync('ed25519');
    const privateKeyDer = keyPair.privateKey.export({ format: 'der', type: 'pkcs8' });
    apiPrivateKey = Buffer.from(privateKeyDer).toString('hex').slice(0, 64);
  } catch (error) {
    // Fallback: use test key
    console.warn('Failed to generate Ed25519 key, using test key');
    apiPrivateKey = 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890';
  }

  // Set environment variables for Go test
  const env = {
    ...process.env,
    E2E_EXTERNAL_SERVER: 'false',
    E2E_API_PORT: TEST_SERVER_PORT.toString(),
    E2E_API_KEY_ID: apiKeyID,
    E2E_PRIVATE_KEY: apiPrivateKey,
    E2E_SIGNER_ADDRESS: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    E2E_CHAIN_ID: '1',
  };

  // Start Go test server using the shell script
  // The script will generate keys and output them, then start the server
  const startScript = path.join(__dirname, '../scripts/start-test-server.sh');

  const goTestProcess = spawn('bash', [startScript], {
    cwd: PROJECT_ROOT,
    env: {
      ...env,
      E2E_API_PORT: TEST_SERVER_PORT.toString(),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });

  // Parse API key from script output
  let scriptOutput = '';
  let extractedKeyID = apiKeyID;
  let extractedPrivateKey = apiPrivateKey;

  goTestProcess.stdout?.on('data', (data: Buffer) => {
    scriptOutput += data.toString();
    // Extract API key info from script output
    const keyIdMatch = scriptOutput.match(/API Key ID:\s*(\S+)/);
    if (keyIdMatch) {
      extractedKeyID = keyIdMatch[1];
    }
    const privKeyMatch = scriptOutput.match(/Private Key:\s*(\S+)/);
    if (privKeyMatch) {
      extractedPrivateKey = privKeyMatch[1].trim();
    }
  });

  goTestProcess.stderr?.on('data', (data: Buffer) => {
    scriptOutput += data.toString();
  });

  // The Go test server generates random keys, but we can pass our own via env vars
  // However, the Go code doesn't read E2E_PRIVATE_KEY - it generates its own
  // So we need to either:
  // 1. Modify Go code to accept env vars (not ideal)
  // 2. Extract keys from Go server output (complex)
  // 3. Use a workaround: write keys to a file that Go reads, or vice versa

  // For now, let's use a simpler approach:
  // Start the server and try to extract the key from its output
  // Or use a known test key that we configure the Go server to use

  // Actually, let's check if we can pass the key via a file
  const keyInfoFile = path.join(__dirname, '.test-server-keys.json');

  // Write our key info to a file (Go server won't read it, but we'll use it)
  fs.writeFileSync(keyInfoFile, JSON.stringify({
    apiKeyID,
    privateKey: apiPrivateKey,
  }, null, 2));

  // Wait for server to be ready
  const baseURL = `http://localhost:${TEST_SERVER_PORT}`;

  // Give the server a moment to start
  await new Promise(resolve => setTimeout(resolve, 2000));

  await waitForServer(baseURL, 50);

  // The Go server generates random keys, so we need to extract them
  // Since we can't easily do that, let's use a workaround:
  // The Go server uses "test-admin-key-e2e" as the key ID
  // We'll need to get the actual private key from somewhere

  // For now, let's try using the Go server's default behavior
  // and see if we can make it work with a fixed key by modifying the approach

  testServerInfo = {
    baseURL,
    apiKeyID: extractedKeyID,
    privateKey: extractedPrivateKey,
    signerAddress: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    chainID: '1',
    process: goTestProcess,
  };

  // Write server info to file for cleanup
  fs.writeFileSync(
    TEST_SERVER_READY_FILE,
    JSON.stringify({ pid: goTestProcess.pid }, null, 2)
  );

  console.log('Test server started');
  console.log(`API Key ID: ${apiKeyID}`);
  console.log(`Base URL: ${baseURL}`);

  return testServerInfo;
}

/**
 * Stop test server
 */
export async function stopTestServer(): Promise<void> {
  if (testServerInfo?.process) {
    try {
      // Try graceful shutdown
      if (testServerInfo.process.pid) {
        process.kill(testServerInfo.process.pid, 'SIGTERM');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Force kill if still running
        try {
          process.kill(testServerInfo.process.pid, 0);
          process.kill(testServerInfo.process.pid, 'SIGKILL');
        } catch (e) {
          // Process already dead
        }
      }
    } catch (error) {
      console.warn('Error stopping test server:', error);
    }
    testServerInfo = null;
  }

  // Cleanup ready file
  try {
    if (fs.existsSync(TEST_SERVER_READY_FILE)) {
      fs.unlinkSync(TEST_SERVER_READY_FILE);
    }
  } catch (error) {
    // Ignore
  }
}

/**
 * Wait for server to be ready
 */
async function waitForServer(baseURL: string, maxAttempts = 50): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(`${baseURL}/health`);
      if (response.ok) {
        const data = await response.json() as { status: string; version?: string };
        if (data.status === 'healthy' || data.status === 'ok') {
          return;
        }
      }
    } catch (error) {
      // Server not ready yet
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Server at ${baseURL} did not become ready in time`);
}
