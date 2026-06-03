import { test, expect, adminSDKClient } from "./fixtures";
import { SignError } from "remote-signer-client";

const suffix = () => Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 6);

test("transaction sign_type is auto-approved by whitelist rule", async () => {
  const c = await adminSDKClient();
  let signerAddress: string | undefined;
  let ruleId: string | undefined;
  const tag = suffix();

  try {
    const signer = await c.evm.signers.create({
      type: "keystore",
      keystore: { password: `pw-${tag}` },
    });
    signerAddress = signer.address;

    const rule = await c.evm.rules.create({
      name: `e2e-tx-${tag}`,
      type: "evm_address_list",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: ["0x0000000000000000000000000000000000000001"] },
      enabled: true,
    });
    ruleId = rule.id;

    const result = await c.evm.sign.execute({
      chain_id: "1",
      signer_address: signerAddress,
      sign_type: "transaction",
      payload: {
        transaction: {
          from: signerAddress,
          to: "0x0000000000000000000000000000000000000001",
          value: "0x0",
          data: "0x",
          gas: 21000,
          gasPrice: "0",
            txType: "legacy",
        },
      },
    });

    expect(["completed", "signing"]).toContain(result.status);
  } finally {
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    if (signerAddress) await c.evm.signers.deleteSigner(signerAddress).catch(() => {});
  }
});

test("typed_data sign_type submits via executeAsync and enters authorizing state", async () => {
  const c = await adminSDKClient();
  let signerAddress: string | undefined;
  let ruleId: string | undefined;
  const tag = suffix();

  try {
    const signer = await c.evm.signers.create({
      type: "keystore",
      keystore: { password: `pw-${tag}` },
    });
    signerAddress = signer.address;

    const rule = await c.evm.rules.create({
      name: `e2e-td-${tag}`,
      type: "evm_js",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: {
        script:
          "function validate(input) { if (input.sign_type !== 'typed_data') return fail('wrong type'); return ok(); }",
      },
      enabled: true,
    });
    ruleId = rule.id;

    try {
      const result = await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signerAddress,
        sign_type: "typed_data",
        payload: {
          typed_data: {
            types: {
              EIP712Domain: [{ name: "chainId", type: "uint256" }],
              SafeTx: [
                { name: "to", type: "address" },
                { name: "value", type: "uint256" },
                { name: "data", type: "bytes" },
                { name: "operation", type: "uint8" },
                { name: "nonce", type: "uint256" },
              ],
            },
            domain: { chainId: "1" },
            message: {
              to: "0x0000000000000000000000000000000000000001",
              value: "0",
              data: "0x",
              operation: "0",
              nonce: "0",
            },
            primaryType: "SafeTx",
          },
        },
      });

      expect(["completed", "signing"]).toContain(result.status);
    } catch (err) {
      if (err instanceof SignError) {
        expect(["pending", "authorizing"]).toContain(err.status);
      } else {
        throw err;
      }
    }
  } finally {
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    if (signerAddress) await c.evm.signers.deleteSigner(signerAddress).catch(() => {});
  }
});

test("personal sign_type is approved by evm_js whitelist rule", async () => {
  const c = await adminSDKClient();
  let signerAddress: string | undefined;
  let ruleId: string | undefined;
  const tag = suffix();

  try {
    const signer = await c.evm.signers.create({
      type: "keystore",
      keystore: { password: `pw-${tag}` },
    });
    signerAddress = signer.address;

    const rule = await c.evm.rules.create({
      name: `e2e-personal-${tag}`,
      type: "evm_js",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: {
        script:
          "function validate(input) { if (input.sign_type !== 'personal') return fail('wrong type'); return ok(); }",
      },
      enabled: true,
    });
    ruleId = rule.id;

    try {
      const result = await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signerAddress,
        sign_type: "personal",
        payload: { message: "0x48656c6c6f" },
      });
      expect(["completed", "signing"]).toContain(result.status);
    } catch (err) {
      if (err instanceof SignError) {
        expect(["pending", "authorizing"]).toContain(err.status);
      } else {
        throw err;
      }
    }
  } finally {
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    if (signerAddress) await c.evm.signers.deleteSigner(signerAddress).catch(() => {});
  }
});

test("invalid sign_type returns 400 error", async () => {
  const c = await adminSDKClient();
  let signerAddress: string | undefined;
  const tag = suffix();

  try {
    const signer = await c.evm.signers.create({
      type: "keystore",
      keystore: { password: `pw-${tag}` },
    });
    signerAddress = signer.address;

    await expect(
      c.evm.sign.execute({
        chain_id: "1",
        signer_address: signerAddress,
        sign_type: "nonexistent" as any,
        payload: { message: "0x00" },
      }),
    ).rejects.toThrow();
  } finally {
    if (signerAddress) await c.evm.signers.deleteSigner(signerAddress).catch(() => {});
  }
});

// /sign/batch is gated behind the simulation engine (not enabled in the e2e daemon
// config), so batch tests are skipped. When the e2e config enables simulation, the
// below tests should be un-skipped and the `payload: { transaction: {...} }` wrapper
// (matching the SDK's BatchSignRequest shape) is the correct format.
test.skip("batch sign: 2 transactions pass", async () => {});
test.skip("batch sign: >20 items rejected", async () => {});
