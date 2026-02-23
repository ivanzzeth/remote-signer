#!/usr/bin/env python3
"""Generate rules/templates/polymarket.safe.template.yaml from rules/polymarket.safe.yaml."""

import re

HEADER = """# Polymarket Protocol Rules (TEMPLATE)
# Parameterized with ${variable} placeholders. Bind variables when creating an instance.
#
# Variables: chain_id, protocol addresses, domain names, and the allowed Safe wallet.
# Use test_variables for validate-rules; use instance config.variables for deployment.

variables:
  - name: chain_id
    type: string
    description: "Chain ID (e.g. 137 for Polygon)"
    required: true
  - name: ctf_exchange_address
    type: address
    description: "CTF Exchange contract address"
    required: true
  - name: neg_risk_adapter_address
    type: address
    description: "NegRiskAdapter contract address"
    required: true
  - name: neg_risk_exchange_address
    type: address
    description: "NegRiskExchange contract address"
    required: true
  - name: conditional_tokens_address
    type: address
    description: "ConditionalTokens (CTF) contract address"
    required: true
  - name: safe_proxy_factory_address
    type: address
    description: "Safe Proxy Factory contract address"
    required: true
  - name: usdc_bridged_address
    type: address
    description: "USDC.e (Bridged) token address"
    required: true
  - name: allowed_safe_address
    type: address
    description: "Allowed Safe wallet address (verifyingContract / txTo for SafeTx and execTransaction)"
    required: true
  - name: clob_auth_domain_name
    type: string
    description: "ClobAuth EIP-712 domain name"
    required: true
  - name: clob_auth_domain_version
    type: string
    description: "ClobAuth EIP-712 domain version"
    required: true
  - name: ctf_exchange_domain_name
    type: string
    description: "CTF Exchange EIP-712 domain name"
    required: true
  - name: ctf_exchange_domain_version
    type: string
    description: "CTF Exchange EIP-712 domain version"
    required: true
  - name: safe_factory_domain_name
    type: string
    description: "Safe Factory EIP-712 domain name"
    required: true

# Default values for template validation (Polygon mainnet)
test_variables:
  chain_id: "137"
  ctf_exchange_address: "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
  neg_risk_adapter_address: "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296"
  neg_risk_exchange_address: "0xC5d563A36AE78145C45a50134d48A1215220f80a"
  conditional_tokens_address: "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"
  safe_proxy_factory_address: "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b"
  usdc_bridged_address: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
  allowed_safe_address: "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
  clob_auth_domain_name: "ClobAuthDomain"
  clob_auth_domain_version: "1"
  ctf_exchange_domain_name: "Polymarket CTF Exchange"
  ctf_exchange_domain_version: "1"
  safe_factory_domain_name: "Polymarket Contract Proxy Factory"

"""

# Order matters: replace longer / more specific strings first
REPLACEMENTS = [
    ("0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E", "${ctf_exchange_address}"),
    ("0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296", "${neg_risk_adapter_address}"),
    ("0xC5d563A36AE78145C45a50134d48A1215220f80a", "${neg_risk_exchange_address}"),
    ("0x4D97DCd97eC945f40cF65F87097ACe5EA0476045", "${conditional_tokens_address}"),
    ("0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b", "${safe_proxy_factory_address}"),
    ("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "${usdc_bridged_address}"),
    ("0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837", "${allowed_safe_address}"),
    ('keccak256(bytes("ClobAuthDomain"))', 'keccak256(bytes("${clob_auth_domain_name}"))'),
    ('keccak256(bytes("Polymarket CTF Exchange"))', 'keccak256(bytes("${ctf_exchange_domain_name}"))'),
    ('keccak256(bytes("Polymarket Contract Proxy Factory"))', 'keccak256(bytes("${safe_factory_domain_name}"))'),
    ('eip712_domainChainId == 137,', 'eip712_domainChainId == ${chain_id},'),
    ('chainId: "137"', 'chainId: "${chain_id}"'),
    ('chain_id: "137"', 'chain_id: "${chain_id}"'),
    # domain name/version in test_cases (quoted YAML values)
    ('name: "ClobAuthDomain"', 'name: "${clob_auth_domain_name}"'),
    ('version: "1"', 'version: "${clob_auth_domain_version}"'),
    ('name: "Polymarket CTF Exchange"', 'name: "${ctf_exchange_domain_name}"'),
    ('name: "Polymarket Contract Proxy Factory"', 'name: "${safe_factory_domain_name}"'),
]


def main():
    base = __file__
    if base.endswith(".py"):
        base = base[: -len(".py")]
    root = base[: base.rfind("scripts")]
    src = root + "rules/polymarket.safe.yaml"
    dst = root + "rules/templates/polymarket.safe.template.yaml"

    with open(src, "r", encoding="utf-8") as f:
        content = f.read()

    # Skip first 41 lines (comment block and empty line before "rules:")
    lines = content.split("\n")
    if lines[0].strip().startswith("#") and "rules:" in content[:2000]:
        idx = next(i for i, line in enumerate(lines) if line.strip() == "rules:")
        content = "\n".join(lines[idx:])  # from "rules:" onward
    else:
        content = content

    for old, new in REPLACEMENTS:
        content = content.replace(old, new)
    # Domain version: first occurrence is ClobAuth, second is CTF Exchange
    content = content.replace(
        'keccak256(bytes("1"))', 'keccak256(bytes("${clob_auth_domain_version}"))', 1
    )
    content = content.replace(
        'keccak256(bytes("1"))', 'keccak256(bytes("${ctf_exchange_domain_version}"))', 1
    )

    out = HEADER + content
    with open(dst, "w", encoding="utf-8") as f:
        f.write(out)
    print("Written:", dst)


if __name__ == "__main__":
    main()
