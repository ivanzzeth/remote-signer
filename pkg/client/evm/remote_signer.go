package evm

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig"
	"github.com/ivanzzeth/ethsig/eip712"
)

// RemoteSigner implements ethsig signer interfaces by making remote calls to the signing service.
type RemoteSigner struct {
	sign    *SignService
	address common.Address
	chainID string
}

// Ensure RemoteSigner implements all ethsig interfaces.
var (
	_ ethsig.AddressGetter     = (*RemoteSigner)(nil)
	_ ethsig.RawMessageSigner  = (*RemoteSigner)(nil)
	_ ethsig.HashSigner        = (*RemoteSigner)(nil)
	_ ethsig.EIP191Signer      = (*RemoteSigner)(nil)
	_ ethsig.PersonalSigner    = (*RemoteSigner)(nil)
	_ ethsig.TypedDataSigner   = (*RemoteSigner)(nil)
	_ ethsig.TransactionSigner = (*RemoteSigner)(nil)
)

// NewRemoteSigner creates a new RemoteSigner that uses the given SignService.
func NewRemoteSigner(sign *SignService, address common.Address, chainID string) *RemoteSigner {
	return &RemoteSigner{
		sign:    sign,
		address: address,
		chainID: chainID,
	}
}

// GetAddress returns the signer's address.
func (s *RemoteSigner) GetAddress() common.Address {
	return s.address
}

// SignRawMessage signs raw message bytes.
func (s *RemoteSigner) SignRawMessage(raw []byte) ([]byte, error) {
	return s.SignRawMessageWithContext(context.Background(), raw)
}

// SignRawMessageWithContext signs raw message bytes with context.
func (s *RemoteSigner) SignRawMessageWithContext(ctx context.Context, raw []byte) ([]byte, error) {
	payload := RawMessagePayload{RawMessage: raw}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := s.sign.Execute(ctx, &SignRequest{
		ChainID:       s.chainID,
		SignerAddress: s.address.Hex(),
		SignType:      SignTypeRawMessage,
		Payload:       payloadBytes,
	})
	if err != nil {
		return nil, err
	}
	return decodeSignature(resp.Signature)
}

// SignHash signs pre-hashed data (32 bytes).
func (s *RemoteSigner) SignHash(hashedData common.Hash) ([]byte, error) {
	return s.SignHashWithContext(context.Background(), hashedData)
}

// SignHashWithContext signs pre-hashed data with context.
func (s *RemoteSigner) SignHashWithContext(ctx context.Context, hashedData common.Hash) ([]byte, error) {
	payload := HashPayload{Hash: hashedData.Hex()}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := s.sign.Execute(ctx, &SignRequest{
		ChainID:       s.chainID,
		SignerAddress: s.address.Hex(),
		SignType:      SignTypeHash,
		Payload:       payloadBytes,
	})
	if err != nil {
		return nil, err
	}
	return decodeSignature(resp.Signature)
}

// SignEIP191Message signs an EIP-191 formatted message.
func (s *RemoteSigner) SignEIP191Message(message string) ([]byte, error) {
	return s.SignEIP191MessageWithContext(context.Background(), message)
}

// SignEIP191MessageWithContext signs an EIP-191 formatted message with context.
func (s *RemoteSigner) SignEIP191MessageWithContext(ctx context.Context, message string) ([]byte, error) {
	payload := MessagePayload{Message: message}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := s.sign.Execute(ctx, &SignRequest{
		ChainID:       s.chainID,
		SignerAddress: s.address.Hex(),
		SignType:      SignTypeEIP191,
		Payload:       payloadBytes,
	})
	if err != nil {
		return nil, err
	}
	return decodeSignature(resp.Signature)
}

// PersonalSign signs data using personal_sign (EIP-191 0x45).
func (s *RemoteSigner) PersonalSign(data string) ([]byte, error) {
	return s.PersonalSignWithContext(context.Background(), data)
}

// PersonalSignWithContext signs data using personal_sign with context.
func (s *RemoteSigner) PersonalSignWithContext(ctx context.Context, data string) ([]byte, error) {
	payload := MessagePayload{Message: data}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := s.sign.Execute(ctx, &SignRequest{
		ChainID:       s.chainID,
		SignerAddress: s.address.Hex(),
		SignType:      SignTypePersonal,
		Payload:       payloadBytes,
	})
	if err != nil {
		return nil, err
	}
	return decodeSignature(resp.Signature)
}

// SignTypedData signs EIP-712 typed data.
func (s *RemoteSigner) SignTypedData(typedData eip712.TypedData) ([]byte, error) {
	return s.SignTypedDataWithContext(context.Background(), typedData)
}

// SignTypedDataWithContext signs EIP-712 typed data with context.
func (s *RemoteSigner) SignTypedDataWithContext(ctx context.Context, typedData eip712.TypedData) ([]byte, error) {
	clientTypedData := convertToClientTypedData(typedData)
	payload := TypedDataPayload{TypedData: clientTypedData}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := s.sign.Execute(ctx, &SignRequest{
		ChainID:       s.chainID,
		SignerAddress: s.address.Hex(),
		SignType:      SignTypeTypedData,
		Payload:       payloadBytes,
	})
	if err != nil {
		return nil, err
	}
	return decodeSignature(resp.Signature)
}

// SignTransactionWithChainID signs an Ethereum transaction with explicit chain ID.
func (s *RemoteSigner) SignTransactionWithChainID(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return s.SignTransactionWithChainIDAndContext(context.Background(), tx, chainID)
}

// SignTransactionWithChainIDAndContext signs an Ethereum transaction with context.
func (s *RemoteSigner) SignTransactionWithChainIDAndContext(ctx context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	txType := "legacy"
	switch tx.Type() {
	case types.AccessListTxType:
		txType = "eip2930"
	case types.DynamicFeeTxType:
		txType = "eip1559"
	}

	txPayload := &Transaction{
		Value:  tx.Value().String(),
		Gas:    tx.Gas(),
		TxType: txType,
	}

	if tx.To() != nil {
		to := tx.To().Hex()
		txPayload.To = &to
	}

	if len(tx.Data()) > 0 {
		txPayload.Data = "0x" + hex.EncodeToString(tx.Data())
	}

	nonce := tx.Nonce()
	txPayload.Nonce = &nonce

	switch txType {
	case "legacy":
		txPayload.GasPrice = tx.GasPrice().String()
	case "eip1559":
		txPayload.GasTipCap = tx.GasTipCap().String()
		txPayload.GasFeeCap = tx.GasFeeCap().String()
	case "eip2930":
		txPayload.GasPrice = tx.GasPrice().String()
	}

	payload := TransactionPayload{Transaction: txPayload}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	reqChainID := s.chainID
	if chainID != nil {
		reqChainID = chainID.String()
	}

	resp, err := s.sign.Execute(ctx, &SignRequest{
		ChainID:       reqChainID,
		SignerAddress: s.address.Hex(),
		SignType:      SignTypeTransaction,
		Payload:       payloadBytes,
	})
	if err != nil {
		return nil, err
	}

	if resp.SignedData == "" {
		return nil, fmt.Errorf("no signed transaction data in response")
	}

	signedTxBytes, err := decodeHexOrBase64(resp.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed transaction: %w", err)
	}

	var signedTx types.Transaction
	if err := signedTx.UnmarshalBinary(signedTxBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed transaction: %w", err)
	}

	return &signedTx, nil
}

// Close is a no-op for RemoteSigner.
func (s *RemoteSigner) Close() error {
	return nil
}

func convertToClientTypedData(td eip712.TypedData) *TypedData {
	clientTypes := make(map[string][]TypedDataField)
	for name, fields := range td.Types {
		clientFields := make([]TypedDataField, len(fields))
		for i, f := range fields {
			clientFields[i] = TypedDataField{Name: f.Name, Type: f.Type}
		}
		clientTypes[name] = clientFields
	}

	clientDomain := TypedDataDomain{
		Name:              td.Domain.Name,
		Version:           td.Domain.Version,
		ChainId:           td.Domain.ChainId,
		VerifyingContract: td.Domain.VerifyingContract,
		Salt:              td.Domain.Salt,
	}

	return &TypedData{
		Types:       clientTypes,
		PrimaryType: td.PrimaryType,
		Domain:      clientDomain,
		Message:     td.Message,
	}
}

func decodeSignature(sig string) ([]byte, error) {
	if sig == "" {
		return nil, fmt.Errorf("empty signature")
	}
	return decodeHexOrBase64(sig)
}

func decodeHexOrBase64(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") {
		return hex.DecodeString(s[2:])
	}
	if isHex(s) {
		return hex.DecodeString(s)
	}
	return base64.StdEncoding.DecodeString(s)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0 && len(s)%2 == 0
}
