// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

// Env var names for request-as-input (one compile per rule, no recompile when request changes)
const (
	envRuleTxTo       = "RULE_TX_TO"
	envRuleTxValue    = "RULE_TX_VALUE"
	envRuleTxSelector = "RULE_TX_SELECTOR"
	envRuleTxData     = "RULE_TX_DATA"
	envRuleChainID    = "RULE_CHAIN_ID"
	envRuleSigner     = "RULE_SIGNER"
)

// solidityExpressionTemplate is for require-based rules (Expression mode).
// Request data is read from env at runtime so the script is invariant per rule (compile once per rule).
// Context variables: to, value, selector, data, chainId, signer (and tx_*/ctx_* aliases).
const solidityExpressionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

contract RuleEvaluator is Script {
    {{.InMappingDeclarations}}

    constructor() {
        {{.InMappingConstructorInit}}
    }

    function run() public view returns (bool) {
        // Transaction context from env (request-as-input: no recompile per request)
        address tx_to = vm.envAddress("RULE_TX_TO");
        uint256 tx_value = vm.envUint("RULE_TX_VALUE");
        bytes4 tx_selector = _envBytes4("RULE_TX_SELECTOR");
        bytes memory tx_data = vm.envBytes("RULE_TX_DATA");

        // Signing context
        uint256 ctx_chainId = vm.envUint("RULE_CHAIN_ID");
        address ctx_signer = vm.envAddress("RULE_SIGNER");

        // Backward-compatible short aliases
        address to = tx_to;
        uint256 value = tx_value;
        bytes4 selector = tx_selector;
        bytes memory data = tx_data;
        uint256 chainId = ctx_chainId;
        address signer = ctx_signer;

        // Suppress unused variable warnings
        tx_to; tx_value; tx_selector; tx_data; ctx_chainId; ctx_signer;
        to; value; selector; data; chainId; signer;

        // User-defined validation logic
        {{.Expression}}

        // If we reach here, all require() passed
        return true;
    }

    function _envBytes4(string memory key) internal view returns (bytes4) {
        bytes memory b = vm.envBytes(key);
        if (b.length >= 4) return bytes4(b);
        return bytes4(0);
    }
}
`

// solidityFunctionTemplate is for function-based rules (Functions mode).
// Request data is read from env in setUp (request-as-input: compile once per rule).
// Uses two contracts: RuleContract (user functions) and RuleEvaluatorTest (forge test).
const solidityFunctionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// RuleContract contains user-defined validation functions
contract RuleContract {
    {{.InMappingDeclarations}}

    address public immutable txTo;
    uint256 public immutable txValue;
    bytes4 public immutable txSelector;
    bytes public txData;
    uint256 public immutable txChainId;
    address public immutable txSigner;

    constructor(
        address _txTo,
        uint256 _txValue,
        bytes4 _txSelector,
        bytes memory _txData,
        uint256 _txChainId,
        address _txSigner
    ) {
        txTo = _txTo;
        txValue = _txValue;
        txSelector = _txSelector;
        txData = _txData;
        txChainId = _txChainId;
        txSigner = _txSigner;
        {{.InMappingConstructorInit}}
    }

    fallback() external {
        revert("function not whitelisted");
    }

    {{.Functions}}
}

contract RuleEvaluatorTest is Test {
    RuleContract public ruleContract;

    function setUp() public {
        bytes4 sel = _envBytes4("RULE_TX_SELECTOR");
        ruleContract = new RuleContract(
            vm.envAddress("RULE_TX_TO"),
            vm.envUint("RULE_TX_VALUE"),
            sel,
            vm.envBytes("RULE_TX_DATA"),
            vm.envUint("RULE_CHAIN_ID"),
            vm.envAddress("RULE_SIGNER")
        );
    }

    function _envBytes4(string memory key) internal view returns (bytes4) {
        bytes memory b = vm.envBytes(key);
        if (b.length >= 4) return bytes4(b);
        return bytes4(0);
    }

    function test_rule() public {
        bytes memory txData = ruleContract.txData();
        require(txData.length >= 4, "calldata too short: no selector");
        (bool success, bytes memory returnData) = address(ruleContract).call(txData);
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    revert(add(returnData, 32), mload(returnData))
                }
            }
            revert("no matching function or validation failed");
        }
    }
}
`

// solidityTypedDataExpressionTemplate is for EIP-712 typed data validation using require() statements
// Context variables use prefixes to avoid conflicts with user-defined field names:
// - eip712_* : EIP-712 domain context (eip712_primaryType, eip712_domainName, etc.)
// - ctx_* : Signing context (ctx_chainId, ctx_signer)
// Message fields are accessible via struct instance (e.g., order.taker, permit.value)
const solidityTypedDataExpressionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
    {{.StructDefinition}}
    {{.InMappingDeclarations}}

    constructor() {
        {{.InMappingConstructorInit}}
    }

    function run() public view returns (bool) {
        // EIP-712 Domain context (eip712_* prefix)
        string memory eip712_primaryType = {{.PrimaryType}};
        string memory eip712_domainName = {{.DomainName}};
        string memory eip712_domainVersion = {{.DomainVersion}};
        uint256 eip712_domainChainId = {{.DomainChainId}};
        address eip712_domainContract = {{.DomainContract}};

        // Signing context (ctx_* prefix)
        address ctx_signer = {{.Signer}};
        uint256 ctx_chainId = {{.ChainID}};

        // EIP-712 Message struct instance (access fields via structName.field)
        {{.StructInstance}}

        // Suppress unused variable warnings
        bytes memory _eip712_primaryType = bytes(eip712_primaryType);
        bytes memory _eip712_domainName = bytes(eip712_domainName);
        bytes memory _eip712_domainVersion = bytes(eip712_domainVersion);
        eip712_domainChainId; eip712_domainContract; ctx_signer; ctx_chainId;
        _eip712_primaryType; _eip712_domainName; _eip712_domainVersion;

        // User-defined validation logic
        {{.Expression}}

        // If we reach here, all require() passed
        return true;
    }
}
`

// solidityBatchTypedDataTestTemplate is for batch testing multiple typed data rules in a single contract
// This significantly reduces compilation time by compiling once instead of N times
const solidityBatchTypedDataTestTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BatchRuleEvaluatorTest {
    {{.TestFunctions}}
}
`

// solidityTypedDataFunctionsTemplate is for EIP-712 typed data validation using struct-based functions
// Context variables use prefixes to avoid conflicts with user-defined field names:
// - eip712_* : EIP-712 domain context
// - ctx_* : Signing context
const solidityTypedDataFunctionsTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
    {{.InMappingDeclarations}}

    // EIP-712 Domain context (eip712_* prefix)
    string public eip712_primaryType;
    string public eip712_domainName;
    string public eip712_domainVersion;
    uint256 public eip712_domainChainId;
    address public eip712_domainContract;

    // Signing context (ctx_* prefix)
    address public ctx_signer;
    uint256 public ctx_chainId;

    // EIP-712 Message encoded as bytes for struct decoding
    bytes public messageData;

    constructor() {
        eip712_primaryType = {{.PrimaryType}};
        eip712_domainName = {{.DomainName}};
        eip712_domainVersion = {{.DomainVersion}};
        eip712_domainChainId = {{.DomainChainId}};
        eip712_domainContract = {{.DomainContract}};
        ctx_signer = {{.Signer}};
        ctx_chainId = {{.ChainID}};
        messageData = {{.MessageData}};
        {{.InMappingConstructorInit}}
    }

    // User-defined structs and validation functions
    {{.Functions}}

    function run() public returns (bool) {
        // Call the validate function with decoded message
        _validateMessage();
        return true;
    }

    function _validateMessage() internal virtual {
        // Override in user functions if needed
    }
}
`
