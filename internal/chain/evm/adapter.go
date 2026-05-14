package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig/eip712"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// Payload size limits for validation
const (
	maxTransactionDataSize = 128 * 1024   // 128 KB
	maxMessageSize         = 1024 * 1024  // 1 MB
	maxRawMessageSize      = 256 * 1024   // 256 KB
	maxPayloadSize         = 2 * 1024 * 1024 // 2 MB (basic check: whole payload)
)

// EVMAdapter implements types.ChainAdapter for EVM chains
type EVMAdapter struct {
	signerRegistry *SignerRegistry
	rpcProvider    *RPCProvider // optional: for nonce auto-fetch
}

// Compile-time check that EVMAdapter implements ChainAdapter
var _ types.ChainAdapter = (*EVMAdapter)(nil)

// NewEVMAdapter creates a new EVM chain adapter
func NewEVMAdapter(registry *SignerRegistry) (*EVMAdapter, error) {
	if registry == nil {
		return nil, fmt.Errorf("signer registry is required")
	}
	return &EVMAdapter{signerRegistry: registry}, nil
}

// SetRPCProvider sets the optional RPC provider for nonce auto-fetch.
func (a *EVMAdapter) SetRPCProvider(rpc *RPCProvider) {
	a.rpcProvider = rpc
}

// Type returns the chain type this adapter handles
func (a *EVMAdapter) Type() types.ChainType {
	return types.ChainTypeEVM
}

// ValidateBasicRequest validates request format and size only (chain_id, signer_address, sign_type, payload size).
// Does not check signer existence or payload semantics. Used so that only well-formed requests are persisted for audit.
func (a *EVMAdapter) ValidateBasicRequest(chainID, signerAddress, signType string, payload []byte) error {
	if chainID == "" {
		return fmt.Errorf("chain_id is required")
	}
	if _, err := strconv.ParseUint(chainID, 10, 64); err != nil {
		return fmt.Errorf("invalid chain_id: must be a positive decimal integer")
	}
	if signerAddress == "" {
		return fmt.Errorf("signer_address is required")
	}
	if !validate.IsValidEthereumAddress(signerAddress) {
		return fmt.Errorf("invalid signer_address: must be 0x followed by 40 hex characters")
	}
	if signType == "" {
		return fmt.Errorf("sign_type is required")
	}
	if !validate.ValidSignTypes[signType] {
		return fmt.Errorf("invalid sign_type: must be one of hash, raw_message, eip191, personal, typed_data, transaction")
	}
	if len(payload) == 0 {
		return fmt.Errorf("payload is required")
	}
	if len(payload) > maxPayloadSize {
		return fmt.Errorf("payload exceeds maximum size of %d bytes", maxPayloadSize)
	}

	// Payload format: valid JSON and required top-level field present for sign_type
	var p EVMSignPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("invalid payload: not valid JSON: %w", err)
	}
	switch signType {
	case SignTypeHash:
		if p.Hash == "" {
			return fmt.Errorf("invalid payload: hash is required for sign_type %s", signType)
		}
	case SignTypeRawMessage:
		if len(p.RawMessage) == 0 {
			return fmt.Errorf("invalid payload: raw_message is required for sign_type %s", signType)
		}
	case SignTypeEIP191, SignTypePersonal:
		if p.Message == "" {
			return fmt.Errorf("invalid payload: message is required for sign_type %s", signType)
		}
	case SignTypeTypedData:
		if p.TypedData == nil {
			return fmt.Errorf("invalid payload: typed_data is required for sign_type %s", signType)
		}
	case SignTypeTransaction:
		if p.Transaction == nil {
			return fmt.Errorf("invalid payload: transaction is required for sign_type %s", signType)
		}
	}
	return nil
}

// ValidatePayload validates the EVM-specific payload
func (a *EVMAdapter) ValidatePayload(ctx context.Context, signType string, payload []byte) error {
	var p EVMSignPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("invalid EVM payload JSON: %w", err)
	}

	switch signType {
	case SignTypeHash:
		if p.Hash == "" {
			return fmt.Errorf("hash is required for sign type 'hash'")
		}
		if !strings.HasPrefix(p.Hash, "0x") || len(p.Hash) != 66 {
			return fmt.Errorf("hash must be 0x-prefixed 32-byte hex string")
		}
		// Validate hex characters after "0x" prefix
		if _, err := hex.DecodeString(p.Hash[2:]); err != nil {
			return fmt.Errorf("hash contains invalid hex characters")
		}

	case SignTypeRawMessage:
		if len(p.RawMessage) == 0 {
			return fmt.Errorf("raw_message is required for sign type 'raw_message'")
		}
		if len(p.RawMessage) > maxRawMessageSize {
			return fmt.Errorf("raw_message exceeds maximum size of %d bytes", maxRawMessageSize)
		}

	case SignTypeEIP191, SignTypePersonal:
		if p.Message == "" {
			return fmt.Errorf("message is required for sign type '%s'", signType)
		}
		if len(p.Message) > maxMessageSize {
			return fmt.Errorf("message exceeds maximum size of %d bytes", maxMessageSize)
		}

	case SignTypeTypedData:
		if p.TypedData == nil {
			return fmt.Errorf("typed_data is required for sign type 'typed_data'")
		}
		if p.TypedData.PrimaryType == "" {
			return fmt.Errorf("typed_data.primaryType is required")
		}
		if len(p.TypedData.Types) == 0 {
			return fmt.Errorf("typed_data.types is required")
		}

	case SignTypeTransaction:
		if p.Transaction == nil {
			return fmt.Errorf("transaction is required for sign type 'transaction'")
		}
		// Validate 'to' address format (if provided) early to prevent
		// invalid hex from reaching the Solidity evaluator's template
		if p.Transaction.To != nil && *p.Transaction.To != "" {
			if !common.IsHexAddress(*p.Transaction.To) {
				return fmt.Errorf("invalid 'to' address: %s", *p.Transaction.To)
			}
		}
		if p.Transaction.Gas == 0 {
			return fmt.Errorf("transaction.gas is required")
		}
		dataBytes, err := decodeHexData(p.Transaction.Data)
		if err != nil {
			return fmt.Errorf("invalid transaction data hex: %w", err)
		}
		if len(dataBytes) > maxTransactionDataSize {
			return fmt.Errorf("transaction data exceeds maximum size of %d bytes", maxTransactionDataSize)
		}
		switch p.Transaction.TxType {
		case string(TransactionTypeLegacy):
			if p.Transaction.GasPrice == "" {
				return fmt.Errorf("gasPrice is required for legacy transactions")
			}
		case string(TransactionTypeEIP1559):
			if p.Transaction.GasFeeCap == "" || p.Transaction.GasTipCap == "" {
				return fmt.Errorf("gasFeeCap and gasTipCap are required for EIP-1559 transactions")
			}
		case string(TransactionTypeEIP2930):
			if p.Transaction.GasPrice == "" {
				return fmt.Errorf("gasPrice is required for EIP-2930 transactions")
			}
		default:
			return fmt.Errorf("unsupported transaction type: %s", p.Transaction.TxType)
		}

	default:
		return fmt.Errorf("unsupported sign type: %s", signType)
	}

	return nil
}

// Sign performs the actual signing operation
func (a *EVMAdapter) Sign(ctx context.Context, signerAddress string, signType string, chainID string, payload []byte) (*types.SignResult, error) {
	signer, err := a.signerRegistry.GetSigner(signerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer: %w", err)
	}

	var p EVMSignPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	var signature []byte
	var signedData []byte

	switch signType {
	case SignTypeHash:
		hashBytes, err := hexToHash(p.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid hash: %w", err)
		}
		signature, err = signer.SignHash(hashBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to sign hash: %w", err)
		}

	case SignTypeRawMessage:
		signature, err = signer.SignRawMessage(p.RawMessage)
		if err != nil {
			return nil, fmt.Errorf("failed to sign raw message: %w", err)
		}

	case SignTypeEIP191:
		signature, err = signer.SignEIP191Message(p.Message)
		if err != nil {
			return nil, fmt.Errorf("failed to sign EIP-191 message: %w", err)
		}

	case SignTypePersonal:
		signature, err = signer.PersonalSign(p.Message)
		if err != nil {
			return nil, fmt.Errorf("failed to sign personal message: %w", err)
		}

	case SignTypeTypedData:
		typedData, err := convertToEIP712TypedData(p.TypedData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert typed data: %w", err)
		}
		signature, err = signer.SignTypedData(typedData)
		if err != nil {
			return nil, fmt.Errorf("failed to sign typed data: %w", err)
		}

	case SignTypeTransaction:
		chainIDBig, err := parseChainID(chainID)
		if err != nil {
			return nil, fmt.Errorf("invalid chain ID: %w", err)
		}
		// Auto-fetch nonce from chain when not specified
		if p.Transaction.Nonce == nil && a.rpcProvider != nil {
			fetchedNonce, nonceErr := a.rpcProvider.GetTransactionCount(ctx, chainID, signerAddress)
			if nonceErr != nil {
				return nil, fmt.Errorf("failed to auto-fetch nonce: %w", nonceErr)
			}
			p.Transaction.Nonce = &fetchedNonce
		}
		tx, err := convertToEthTransaction(p.Transaction, chainIDBig)
		if err != nil {
			return nil, fmt.Errorf("failed to convert transaction: %w", err)
		}
		signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction: %w", err)
		}
		signedData, err = signedTx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal signed transaction: %w", err)
		}
		// Extract signature from signed tx
		v, r, s := signedTx.RawSignatureValues()
		signature = encodeSignature(r, s, v)

	default:
		return nil, fmt.Errorf("unsupported sign type: %s", signType)
	}

	return &types.SignResult{
		Signature:  signature,
		SignedData: signedData,
		SignerUsed: signerAddress,
	}, nil
}

// ParsePayload parses the payload for rule evaluation
func (a *EVMAdapter) ParsePayload(ctx context.Context, signType string, payload []byte) (*types.ParsedPayload, error) {
	var p EVMSignPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	result := &types.ParsedPayload{RawData: payload}

	switch signType {
	case SignTypeTransaction:
		if p.Transaction != nil {
			result.Recipient = p.Transaction.To
			result.Value = &p.Transaction.Value

			dataHex := strings.TrimPrefix(p.Transaction.Data, "0x")
			if len(dataHex) >= 8 { // 4 bytes = 8 hex chars
				sig := "0x" + dataHex[:8]
				result.MethodSig = &sig
				result.Contract = p.Transaction.To
			}

			// Set RawData to the decoded transaction calldata (not the full JSON payload)
			dataBytes, err := decodeHexData(p.Transaction.Data)
			if err == nil && len(dataBytes) > 0 {
				result.RawData = dataBytes
			}
		}

	case SignTypePersonal, SignTypeEIP191:
		// Extract message for personal sign / EIP-191
		if p.Message != "" {
			result.Message = &p.Message
		}
	}

	return result, nil
}

// ListSigners returns available signers for this chain
func (a *EVMAdapter) ListSigners(ctx context.Context) ([]types.SignerInfo, error) {
	return a.signerRegistry.ListSigners(), nil
}

// HasSigner checks if a signer exists
func (a *EVMAdapter) HasSigner(ctx context.Context, address string) bool {
	return a.signerRegistry.HasSigner(address)
}

// Helper functions

// decodeHexData decodes a 0x-prefixed hex string into raw bytes.
// Returns nil for empty or "0x" input.
func decodeHexData(hexStr string) ([]byte, error) {
	if hexStr == "" || hexStr == "0x" {
		return nil, nil
	}
	return hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
}

func hexToHash(hexStr string) (common.Hash, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return common.Hash{}, err
	}
	if len(bytes) != 32 {
		return common.Hash{}, fmt.Errorf("expected 32 bytes, got %d", len(bytes))
	}
	return common.BytesToHash(bytes), nil
}

func parseChainID(chainID string) (*big.Int, error) {
	if chainID == "" {
		return nil, fmt.Errorf("chain ID is required")
	}
	id := new(big.Int)
	if _, ok := id.SetString(chainID, 10); !ok {
		return nil, fmt.Errorf("invalid chain ID: %s", chainID)
	}
	if id.Sign() <= 0 {
		return nil, fmt.Errorf("chain ID must be a positive integer: %s", chainID)
	}
	return id, nil
}

func convertToEIP712TypedData(payload *TypedDataPayload) (eip712.TypedData, error) {
	if payload == nil {
		return eip712.TypedData{}, fmt.Errorf("typed data payload is nil")
	}

	types := make(eip712.Types)
	for name, fields := range payload.Types {
		typeFields := make([]eip712.Type, len(fields))
		for i, f := range fields {
			typeFields[i] = eip712.Type{Name: f.Name, Type: f.Type}
		}
		types[name] = typeFields
	}

	domain := eip712.TypedDataDomain{
		Name:              payload.Domain.Name,
		Version:           payload.Domain.Version,
		ChainId:           payload.Domain.ChainId,
		VerifyingContract: payload.Domain.VerifyingContract,
		Salt:              payload.Domain.Salt,
	}

	return eip712.TypedData{
		Types:       types,
		PrimaryType: payload.PrimaryType,
		Domain:      domain,
		Message:     payload.Message,
	}, nil
}

func convertToEthTransaction(payload *TransactionPayload, chainID *big.Int) (*ethtypes.Transaction, error) {
	if payload == nil {
		return nil, fmt.Errorf("transaction payload is nil")
	}

	var to *common.Address
	if payload.To != nil && *payload.To != "" {
		if !common.IsHexAddress(*payload.To) {
			return nil, fmt.Errorf("invalid 'to' address: %s", *payload.To)
		}
		addr := common.HexToAddress(*payload.To)
		to = &addr
	}

	value, err := parseNonNegativeBigInt(payload.Value, "value")
	if err != nil {
		return nil, err
	}

	dataBytes, err := decodeHexData(payload.Data)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction data hex: %w", err)
	}

	var tx *ethtypes.Transaction

	switch payload.TxType {
	case string(TransactionTypeLegacy):
		gasPrice, err := parseNonNegativeBigInt(payload.GasPrice, "gasPrice")
		if err != nil {
			return nil, err
		}
		var nonce uint64
		if payload.Nonce != nil {
			nonce = *payload.Nonce
		}
		tx = ethtypes.NewTx(&ethtypes.LegacyTx{
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      payload.Gas,
			To:       to,
			Value:    value,
			Data:     dataBytes,
		})

	case string(TransactionTypeEIP1559):
		gasTipCap, err := parseNonNegativeBigInt(payload.GasTipCap, "gasTipCap")
		if err != nil {
			return nil, err
		}
		gasFeeCap, err := parseNonNegativeBigInt(payload.GasFeeCap, "gasFeeCap")
		if err != nil {
			return nil, err
		}
		var nonce uint64
		if payload.Nonce != nil {
			nonce = *payload.Nonce
		}
		tx = ethtypes.NewTx(&ethtypes.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       payload.Gas,
			To:        to,
			Value:     value,
			Data:      dataBytes,
		})

	case string(TransactionTypeEIP2930):
		gasPrice, err := parseNonNegativeBigInt(payload.GasPrice, "gasPrice")
		if err != nil {
			return nil, err
		}
		var nonce uint64
		if payload.Nonce != nil {
			nonce = *payload.Nonce
		}
		tx = ethtypes.NewTx(&ethtypes.AccessListTx{
			ChainID:  chainID,
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      payload.Gas,
			To:       to,
			Value:    value,
			Data:     dataBytes,
		})

	default:
		return nil, fmt.Errorf("unsupported transaction type: %s", payload.TxType)
	}

	return tx, nil
}

// parseNonNegativeBigInt parses a decimal or hex (0x-prefixed) string as a non-negative big.Int.
// Returns error if the string is not a valid integer or is negative.
func parseNonNegativeBigInt(s string, fieldName string) (*big.Int, error) {
	if s == "" {
		return new(big.Int), nil
	}
	v := new(big.Int)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		// Parse as hex
		if _, ok := v.SetString(s[2:], 16); !ok {
			return nil, fmt.Errorf("invalid %s (hex): %s", fieldName, s)
		}
	} else {
		// Parse as decimal
		if _, ok := v.SetString(s, 10); !ok {
			return nil, fmt.Errorf("invalid %s: %s", fieldName, s)
		}
	}
	if v.Sign() < 0 {
		return nil, fmt.Errorf("%s must not be negative: %s", fieldName, s)
	}
	return v, nil
}

func encodeSignature(r, s, v *big.Int) []byte {
	sig := make([]byte, 65)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	// v is typically 27 or 28, or 0/1 for EIP-155
	if v.Cmp(big.NewInt(27)) >= 0 {
		sig[64] = byte(v.Uint64() - 27) // #nosec G115 -- v >= 27 checked above
	} else {
		sig[64] = byte(v.Uint64()) // #nosec G115 -- v is ECDSA recovery ID (0-3)
	}

	return sig
}
