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
	Data      []byte  `json:"data,omitempty"`
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
type SolidityExpressionConfig struct {
	// Expression is the Solidity code containing require() statements
	// Available variables:
	//   - address to       (transaction recipient)
	//   - uint256 value    (transaction value in wei)
	//   - bytes4 selector  (method selector, first 4 bytes of data)
	//   - bytes data       (full calldata)
	//   - uint256 chainId  (chain ID)
	//   - address signer   (signing address)
	Expression string `json:"expression"`

	// Description explains what the rule validates
	Description string `json:"description,omitempty"`

	// ABISignature defines custom ABI decoding (optional)
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
	To       string `json:"to,omitempty"`        // recipient address, 0x-prefixed
	Value    string `json:"value,omitempty"`     // value in wei (decimal string)
	Selector string `json:"selector,omitempty"`  // method selector, 0x-prefixed 4 bytes
	Data     string `json:"data,omitempty"`      // full calldata, 0x-prefixed hex
	ChainID  string `json:"chain_id,omitempty"`  // chain ID (decimal string)
	Signer   string `json:"signer,omitempty"`    // signer address, 0x-prefixed
}
