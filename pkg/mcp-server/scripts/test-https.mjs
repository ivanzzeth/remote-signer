#!/usr/bin/env node
/**
 * Local test script for HTTPS client behaviour.
 * Run from agents repo root with same env as .cursor/mcp.json, e.g.:
 *
 *   cd /path/to/agents && \
 *   REMOTE_SIGNER_URL=https://localhost:8548 \
 *   REMOTE_SIGNER_API_KEY_ID=admin \
 *   REMOTE_SIGNER_PRIVATE_KEY_FILE=projects/personal/ivanzzeth/remote-signer/data/admin_private.pem \
 *   REMOTE_SIGNER_CA_FILE=projects/personal/ivanzzeth/remote-signer/certs/ca.crt \
 *   REMOTE_SIGNER_CLIENT_CERT_FILE=projects/personal/ivanzzeth/remote-signer/certs/client.crt \
 *   REMOTE_SIGNER_CLIENT_KEY_FILE=projects/personal/ivanzzeth/remote-signer/certs/client.key \
 *   node projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/scripts/test-https.mjs
 *
 * Expect: success (list of rules) or ECONNREFUSED if backend is not running.
 * Bug before fix: "Client sent an HTTP request to an HTTPS server".
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { RemoteSignerClient } = require("remote-signer-client");

function readPrivateKeyHex() {
  const hex = process.env.REMOTE_SIGNER_PRIVATE_KEY?.trim();
  if (hex) return hex;
  const filePath = process.env.REMOTE_SIGNER_PRIVATE_KEY_FILE?.trim();
  if (!filePath) return "";
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    console.error(`Error: REMOTE_SIGNER_PRIVATE_KEY_FILE not found: ${resolved}`);
    process.exit(1);
  }
  const pem = fs.readFileSync(resolved, "utf8");
  const key = crypto.createPrivateKey(pem);
  const jwk = key.export({ format: "jwk" });
  if (!jwk.d) {
    console.error("Error: PEM does not contain Ed25519 private key");
    process.exit(1);
  }
  const raw = Buffer.from(jwk.d, "base64url");
  return raw.toString("hex");
}

function readTLSConfig() {
  const caPath = process.env.REMOTE_SIGNER_CA_FILE?.trim();
  const certPath = process.env.REMOTE_SIGNER_CLIENT_CERT_FILE?.trim();
  const keyPath = process.env.REMOTE_SIGNER_CLIENT_KEY_FILE?.trim();
  const skipVerify = process.env.REMOTE_SIGNER_TLS_INSECURE_SKIP_VERIFY;
  const rejectUnauthorized = !(skipVerify === "1" || skipVerify === "true");
  if (!caPath && !certPath && !keyPath && rejectUnauthorized) return undefined;
  const tls = { rejectUnauthorized };
  if (caPath) {
    const p = path.resolve(caPath);
    if (!fs.existsSync(p)) {
      console.error(`Error: REMOTE_SIGNER_CA_FILE not found: ${p}`);
      process.exit(1);
    }
    tls.ca = fs.readFileSync(p, "utf8");
  }
  if (certPath) {
    const p = path.resolve(certPath);
    if (!fs.existsSync(p)) {
      console.error(`Error: REMOTE_SIGNER_CLIENT_CERT_FILE not found: ${p}`);
      process.exit(1);
    }
    tls.cert = fs.readFileSync(p, "utf8");
  }
  if (keyPath) {
    const p = path.resolve(keyPath);
    if (!fs.existsSync(p)) {
      console.error(`Error: REMOTE_SIGNER_CLIENT_KEY_FILE not found: ${p}`);
      process.exit(1);
    }
    tls.key = fs.readFileSync(p, "utf8");
  }
  return tls;
}

const BASE_URL = process.env.REMOTE_SIGNER_URL || "http://localhost:8548";
const API_KEY_ID = process.env.REMOTE_SIGNER_API_KEY_ID || "";
const PRIVATE_KEY = readPrivateKeyHex();
const tlsConfig = readTLSConfig();

if (!API_KEY_ID || !PRIVATE_KEY) {
  console.error("Set REMOTE_SIGNER_API_KEY_ID and REMOTE_SIGNER_PRIVATE_KEY or REMOTE_SIGNER_PRIVATE_KEY_FILE");
  process.exit(1);
}

const client = new RemoteSignerClient({
  baseURL: BASE_URL,
  apiKeyID: API_KEY_ID,
  privateKey: PRIVATE_KEY,
  pollInterval: 2000,
  pollTimeout: 300000,
  ...(tlsConfig && { httpClient: { tls: tlsConfig } }),
});

console.log("Calling evm.rules.list() at", BASE_URL, "...");
client.evm.rules
  .list()
  .then((data) => {
    console.log("OK:", JSON.stringify(data, null, 2));
  })
  .catch((err) => {
    console.error("Error:", err.message || err);
    process.exit(1);
  });
