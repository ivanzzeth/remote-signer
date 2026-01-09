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
