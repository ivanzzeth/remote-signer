package evm

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ErrFromNotDerivable is returned when transaction.from cannot be set (e.g. missing signer).
var ErrFromNotDerivable = fmt.Errorf("from address not derivable")

// BuildRuleInput builds a normalized RuleInput from a sign request and parsed payload.
// For transaction sign_type, from is set from req.SignerAddress (checksum).
// Returns ErrFromNotDerivable if from is required but cannot be derived.
func BuildRuleInput(req *types.SignRequest, parsed *types.ParsedPayload) (*RuleInput, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}

	chainID, err := parseChainIDForRuleInput(req.ChainID)
	if err != nil {
		return nil, err
	}

	signer := common.HexToAddress(req.SignerAddress).Hex()

	signType := mapEVMSignTypeToRuleInput(req.SignType)

	out := &RuleInput{
		SignType: signType,
		ChainID:  chainID,
		Signer:    signer,
	}

	var p EVMSignPayload
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			return nil, fmt.Errorf("invalid payload JSON: %w", err)
		}
	}

	switch req.SignType {
	case SignTypeTransaction:
		if p.Transaction == nil {
			return nil, fmt.Errorf("transaction payload missing")
		}
		if req.SignerAddress == "" || !common.IsHexAddress(req.SignerAddress) {
			return nil, ErrFromNotDerivable
		}
		from := signer
		to := ""
		if p.Transaction.To != nil {
			to = common.HexToAddress(*p.Transaction.To).Hex()
		}
		valueHex := toHexWei(p.Transaction.Value)
		gasStr := ""
		if p.Transaction.Gas > 0 {
			gasStr = strconv.FormatUint(p.Transaction.Gas, 10)
		}
		methodID := ""
		if parsed != nil && parsed.MethodSig != nil {
			methodID = *parsed.MethodSig
		}
		out.Transaction = &RuleInputTransaction{
			From:     from,
			To:       to,
			Value:    valueHex,
			Data:     normalizeHex(p.Transaction.Data),
			Gas:      gasStr,
			MethodID: methodID,
		}
	case SignTypeTypedData:
		if p.TypedData == nil {
			return nil, fmt.Errorf("typed_data payload missing")
		}
		out.TypedData = &RuleInputTypedData{
			Types:       p.TypedData.Types,
			PrimaryType: p.TypedData.PrimaryType,
			Domain:      p.TypedData.Domain,
			Message:     p.TypedData.Message,
		}
	case SignTypePersonal, SignTypeEIP191:
		if p.Message == "" {
			return nil, fmt.Errorf("message payload missing")
		}
		out.PersonalSign = &RuleInputPersonalSign{Message: p.Message}
	default:
		// hash, raw_message: no transaction/typed_data/personal_sign; RuleInput has sign_type, chain_id, signer only
	}

	return out, nil
}

func parseChainIDForRuleInput(chainID string) (int64, error) {
	if chainID == "" {
		return 0, fmt.Errorf("chain_id is required")
	}
	n, err := strconv.ParseInt(chainID, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid chain_id: %s", chainID)
	}
	return n, nil
}

func mapEVMSignTypeToRuleInput(signType string) string {
	switch signType {
	case SignTypeTransaction:
		return "transaction"
	case SignTypeTypedData:
		return "typed_data"
	case SignTypePersonal, SignTypeEIP191:
		return "personal_sign"
	default:
		return signType
	}
}

// toHexWei converts decimal wei string to 0x-prefixed hex (for RuleInput value).
func toHexWei(dec string) string {
	if dec == "" {
		return "0x0"
	}
	var b big.Int
	if _, ok := b.SetString(dec, 10); !ok {
		return "0x0"
	}
	return "0x" + b.Text(16)
}

func normalizeHex(s string) string {
	if s == "" {
		return "0x"
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	return "0x" + s
}
