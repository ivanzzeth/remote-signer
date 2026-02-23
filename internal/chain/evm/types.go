package evm

// EVM sign types (match ethsig interfaces)
const (
	SignTypeHash        = "hash"
	SignTypeRawMessage  = "raw_message"
	SignTypeEIP191      = "eip191"
	SignTypePersonal    = "personal"
	SignTypeTypedData   = "typed_data"
	SignTypeTransaction = "transaction"
)

// TransactionType represents the Ethereum transaction type
type TransactionType string

const (
	TransactionTypeLegacy  TransactionType = "legacy"
	TransactionTypeEIP2930 TransactionType = "eip2930"
	TransactionTypeEIP1559 TransactionType = "eip1559"
)

// EVMSignPayload is the payload for EVM sign requests
type EVMSignPayload struct {
	// For hash signing
	Hash string `json:"hash,omitempty"` // 0x prefixed, 32 bytes

	// For raw message signing
	RawMessage []byte `json:"raw_message,omitempty"`

	// For EIP-191/Personal signing
	Message string `json:"message,omitempty"`

	// For EIP-712 typed data signing
	TypedData *TypedDataPayload `json:"typed_data,omitempty"`

	// For transaction signing
	Transaction *TransactionPayload `json:"transaction,omitempty"`
}

// TypedDataPayload represents EIP-712 typed data
type TypedDataPayload struct {
	Types       map[string][]TypedDataField `json:"types"`
	PrimaryType string                      `json:"primaryType"`
	Domain      TypedDataDomain             `json:"domain"`
	Message     map[string]interface{}      `json:"message"`
}

// TypedDataField represents a field in EIP-712 typed data
type TypedDataField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// TypedDataDomain represents the domain of EIP-712 typed data
type TypedDataDomain struct {
	Name              string `json:"name,omitempty"`
	Version           string `json:"version,omitempty"`
	ChainId           string `json:"chainId,omitempty"` // decimal string
	VerifyingContract string `json:"verifyingContract,omitempty"`
	Salt              string `json:"salt,omitempty"`
}

// TransactionPayload represents an Ethereum transaction
type TransactionPayload struct {
	To        *string `json:"to,omitempty"` // nil for contract creation
	Value     string  `json:"value"`        // wei as decimal string
	Data      string  `json:"data,omitempty"` // 0x-prefixed hex string
	Nonce     *uint64 `json:"nonce,omitempty"`
	Gas       uint64  `json:"gas"`
	GasPrice  string  `json:"gasPrice,omitempty"`  // for legacy tx
	GasTipCap string  `json:"gasTipCap,omitempty"` // for EIP-1559
	GasFeeCap string  `json:"gasFeeCap,omitempty"` // for EIP-1559
	TxType    string  `json:"txType"`              // "legacy", "eip2930", "eip1559"
}

// EVM-specific rule configs

// AddressListConfig defines addresses for whitelist/blocklist rules
// When mode=whitelist: transactions TO these addresses are allowed
// When mode=blocklist: transactions TO these addresses are blocked
type AddressListConfig struct {
	Addresses []string `json:"addresses"` // 0x prefixed
}

// ContractMethodConfig defines allowed contract methods
type ContractMethodConfig struct {
	Contract   string   `json:"contract"`    // 0x prefixed
	MethodSigs []string `json:"method_sigs"` // 4-byte hex, 0x prefixed
}

// ValueLimitConfig defines value limits
type ValueLimitConfig struct {
	MaxValue string `json:"max_value"` // wei as decimal string
}

// SolidityExpressionConfig holds the Solidity code for rule evaluation
// Supports multiple modes:
//  1. Expression mode: require() statements with context variables (for transactions)
//  2. Function mode: define functions that auto-match transaction selectors
//  3. TypedDataExpression mode: require() statements for EIP-712 typed data validation
//  4. TypedDataFunctions mode: struct-based functions for EIP-712 validation
type SolidityExpressionConfig struct {
	// Expression is the Solidity code containing require() statements (Mode 1)
	// Available variables:
	//   - address to       (transaction recipient)
	//   - uint256 value    (transaction value in wei)
	//   - bytes4 selector  (method selector, first 4 bytes of data)
	//   - bytes data       (full calldata)
	//   - uint256 chainId  (chain ID)
	//   - address signer   (signing address)
	// Example: require(value <= 1 ether, "exceeds limit");
	Expression string `json:"expression,omitempty"`

	// Functions contains user-defined Solidity functions (Mode 2)
	// When the transaction selector matches a function, it's called automatically
	// with decoded parameters. Context variables available as txTo, txValue, etc.
	// Example:
	//   function transfer(address to, uint256 amount) external {
	//       require(amount <= 10000e6, "exceeds 10k limit");
	//   }
	Functions string `json:"functions,omitempty"`

	// TypedDataExpression is Solidity code for EIP-712 typed data validation (Mode 3)
	// Available variables:
	//   - string eip712_primaryType       (primary type name, e.g., "Permit")
	//   - string eip712_domainName        (domain name)
	//   - string eip712_domainVersion     (domain version)
	//   - uint256 eip712_domainChainId    (domain chain ID)
	//   - address eip712_domainContract   (verifying contract address)
	//   - Plus message fields as defined by TypedDataTypes (or inferred from request)
	// Example: require(value <= 1000000e6, "permit value exceeds 1M limit");
	TypedDataExpression string `json:"typed_data_expression,omitempty"`

	// TypedDataStruct defines the expected EIP-712 message structure using Solidity struct syntax
	// When specified, the rule will:
	//   1. Only match requests where primaryType matches the struct name (or TypedDataPrimaryType if set)
	//   2. Generate a struct instance variable with lowercase name (e.g., Order -> order)
	//   3. Access fields using struct.field syntax (e.g., order.taker, order.feeRateBps)
	// Example:
	//   typed_data_struct: |
	//     struct Order {
	//         uint256 salt;
	//         address maker;
	//         address taker;
	//         uint256 feeRateBps;
	//     }
	//   typed_data_expression: |
	//     require(order.taker == address(0), "taker must be zero address");
	//     require(order.feeRateBps <= 1000, "fee exceeds 10%");
	TypedDataStruct string `json:"typed_data_struct,omitempty"`

	// TypedDataPrimaryType specifies the expected EIP-712 primaryType to match
	// If not set but TypedDataStruct is defined, uses the struct name as primaryType
	// The lowercase form of this name is used as the struct instance variable name
	// Example: "Order" -> instance variable "order" accessible in expressions
	TypedDataPrimaryType string `json:"typed_data_primary_type,omitempty"`

	// TypedDataFunctions contains struct definitions and validation functions (Mode 4)
	// Define structs matching EIP-712 types and functions to validate them
	// Example:
	//   struct Permit { address owner; address spender; uint256 value; ... }
	//   function validatePermit(Permit memory permit) external { ... }
	TypedDataFunctions string `json:"typed_data_functions,omitempty"`

	// SignTypeFilter restricts this rule to specific sign types
	// If empty, applies to all sign types (default behavior for transaction rules)
	// Common values: "transaction", "typed_data", "personal", "eip191"
	SignTypeFilter string `json:"sign_type_filter,omitempty"`

	// InMappingArrays supplies address lists for in(expr, varName): varName -> []address.
	// When rule body contains in(txTo, allowed_safe_addresses), generate allowed_safe_addresses_mapping
	// and set InMappingArrays["allowed_safe_addresses"] to the list. O(1) lookup instead of expanded OR chain.
	InMappingArrays map[string][]string `json:"in_mapping_arrays,omitempty"`

	// Description explains what the rule validates
	Description string `json:"description,omitempty"`

	// ABISignature defines custom ABI decoding (optional, only for Expression mode)
	// Format: "functionName(type1,type2,...)"
	ABISignature string `json:"abi_signature,omitempty"`

	// TestCases defines validation cases to verify rule correctness
	// Each test case is executed during rule creation/update to ensure validity
	TestCases []SolidityTestCase `json:"test_cases"`
}

// SolidityTestCase defines a test case for validating a Solidity rule
type SolidityTestCase struct {
	// Name describes what this test case validates
	Name string `json:"name"`

	// Input defines the transaction context for this test
	Input SolidityTestInput `json:"input"`

	// ExpectPass indicates whether the rule should pass (true) or revert (false)
	ExpectPass bool `json:"expect_pass"`

	// ExpectReason is the expected revert reason (only used when ExpectPass is false)
	// If empty, any revert is accepted; if set, must match the revert message
	ExpectReason string `json:"expect_reason,omitempty"`
}

// SolidityTestInput defines the transaction context for a test case
type SolidityTestInput struct {
	// Transaction context fields (for transaction rules)
	To       string `json:"to,omitempty"`       // recipient address, 0x-prefixed
	Value    string `json:"value,omitempty"`    // value in wei (decimal string)
	Selector string `json:"selector,omitempty"` // method selector, 0x-prefixed 4 bytes
	Data     string `json:"data,omitempty"`     // full calldata, 0x-prefixed hex
	ChainID  string `json:"chain_id,omitempty"` // chain ID (decimal string)
	Signer   string `json:"signer,omitempty"`   // signer address, 0x-prefixed

	// EIP-712 typed data fields (for typed_data rules)
	TypedData *TypedDataTestInput `json:"typed_data,omitempty"`
}

// TypedDataTestInput defines EIP-712 typed data for test cases
type TypedDataTestInput struct {
	// PrimaryType is the primary type name (e.g., "Permit")
	PrimaryType string `json:"primaryType,omitempty"`

	// Domain contains the EIP-712 domain parameters
	Domain *TypedDataDomainInput `json:"domain,omitempty"`

	// Message contains the typed data message fields
	// Keys are field names, values are field values (as strings)
	Message map[string]interface{} `json:"message,omitempty"`
}

// TypedDataDomainInput defines the EIP-712 domain for test cases
type TypedDataDomainInput struct {
	Name              string `json:"name,omitempty"`
	Version           string `json:"version,omitempty"`
	ChainID           string `json:"chainId,omitempty"`
	VerifyingContract string `json:"verifyingContract,omitempty"`
	Salt              string `json:"salt,omitempty"`
}
