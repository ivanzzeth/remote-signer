/**
 * Example: Remote Signer JS/TS Client with TLS/mTLS
 *
 * This example demonstrates how to use the JavaScript/TypeScript client SDK
 * to interact with a remote-signer service, including TLS and mTLS configuration.
 *
 * Usage (Node.js with mTLS):
 *
 *   export REMOTE_SIGNER_URL=https://localhost:8549
 *   export REMOTE_SIGNER_API_KEY_ID=dev-key-1
 *   export REMOTE_SIGNER_PRIVATE_KEY=<your-ed25519-private-key-hex>
 *
 *   npx ts-node example.ts \
 *     --ca-cert ../../certs/ca.crt \
 *     --client-cert ../../certs/client.crt \
 *     --client-key ../../certs/client.key
 *
 * Usage (plain HTTP, no TLS):
 *
 *   REMOTE_SIGNER_URL=http://localhost:8548 npx ts-node example.ts
 */

import * as fs from "fs";
import * as path from "path";
import { RemoteSignerClient, APIError, SignError, TimeoutError } from "../../pkg/js-client/src";

// Parse CLI args
function parseArgs(): {
  caCert?: string;
  clientCert?: string;
  clientKey?: string;
  skipVerify: boolean;
} {
  const args = process.argv.slice(2);
  const result: any = { skipVerify: false };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--ca-cert":
        result.caCert = args[++i];
        break;
      case "--client-cert":
        result.clientCert = args[++i];
        break;
      case "--client-key":
        result.clientKey = args[++i];
        break;
      case "--skip-verify":
        result.skipVerify = true;
        break;
    }
  }

  return result;
}

async function main() {
  const args = parseArgs();

  // Read config from environment
  const baseURL = process.env.REMOTE_SIGNER_URL || "https://localhost:8549";
  const apiKeyID = process.env.REMOTE_SIGNER_API_KEY_ID;
  const privateKey = process.env.REMOTE_SIGNER_PRIVATE_KEY;

  if (!apiKeyID) {
    console.error("REMOTE_SIGNER_API_KEY_ID environment variable is required");
    process.exit(1);
  }
  if (!privateKey) {
    console.error("REMOTE_SIGNER_PRIVATE_KEY environment variable is required");
    process.exit(1);
  }

  // Build TLS config if any TLS options provided
  const tlsConfig: any = {};
  if (args.caCert) {
    tlsConfig.ca = fs.readFileSync(path.resolve(args.caCert));
  }
  if (args.clientCert) {
    tlsConfig.cert = fs.readFileSync(path.resolve(args.clientCert));
  }
  if (args.clientKey) {
    tlsConfig.key = fs.readFileSync(path.resolve(args.clientKey));
  }
  if (args.skipVerify) {
    tlsConfig.rejectUnauthorized = false;
  }

  const hasTLS = Object.keys(tlsConfig).length > 0;

  // Create client
  const client = new RemoteSignerClient({
    baseURL,
    apiKeyID,
    privateKey,
    httpClient: hasTLS ? { tls: tlsConfig } : undefined,
  });

  // 1. Health check
  console.log("=== Health Check ===");
  try {
    const health = await client.health();
    console.log(`Status: ${health.status}, Version: ${health.version}`);
  } catch (error) {
    console.error("Health check failed:", error);
    process.exit(1);
  }
  console.log();

  // 2. List signers
  console.log("=== List Signers ===");
  let signerAddress: string | undefined;
  try {
    const signers = await client.listSigners();
    for (const s of signers.signers) {
      console.log(`  Address: ${s.address}, Enabled: ${s.enabled}`);
    }
    if (signers.signers.length > 0) {
      signerAddress = signers.signers[0].address;
    }
  } catch (error) {
    console.error("List signers failed:", error);
  }
  console.log();

  // 3. List requests
  console.log("=== List Requests ===");
  try {
    const requests = await client.listRequests({ limit: 5 });
    console.log(`Total: ${requests.total}`);
    for (const r of requests.requests) {
      console.log(`  ID: ${r.id}, Status: ${r.status}, SignType: ${r.sign_type}`);
    }
  } catch (error) {
    console.error("List requests failed:", error);
  }
  console.log();

  // 4. Sign a personal message (won't wait for approval)
  console.log("=== Sign Personal Message ===");
  if (signerAddress) {
    console.log(`Using signer: ${signerAddress}`);
    try {
      const resp = await client.sign(
        {
          chain_id: "1",
          signer_address: signerAddress,
          sign_type: "personal",
          payload: { message: "Hello from JS client example!" },
        },
        false // don't wait for approval
      );
      console.log(`Request ID: ${resp.request_id}, Status: ${resp.status}`);
      if (resp.signature) {
        console.log(`Signature: ${resp.signature}`);
      }
    } catch (error) {
      if (error instanceof SignError) {
        console.log(`Sign result: Request ${error.requestID}, Status: ${error.status}`);
      } else if (error instanceof APIError) {
        console.log(`API Error: ${error.statusCode} - ${error.message}`);
      } else {
        console.log(`Sign result: ${error}`);
      }
    }
  } else {
    console.log("No signers available. Skipping sign example.");
  }

  console.log("\nDone!");
}

main().catch(console.error);
