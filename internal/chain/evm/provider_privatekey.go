package evm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// PrivateKeyProvider loads signers from hex private keys (env vars or direct values).
type PrivateKeyProvider struct {
	registry *SignerRegistry
}

// NewPrivateKeyProvider creates a PrivateKeyProvider and loads all configured keys into the registry.
func NewPrivateKeyProvider(registry *SignerRegistry, configs []PrivateKeyConfig) (*PrivateKeyProvider, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}

	p := &PrivateKeyProvider{registry: registry}

	for _, pk := range configs {
		if !pk.Enabled {
			continue
		}

		keyHex := resolvePrivateKey(pk.KeyEnvVar)
		if keyHex == "" {
			return nil, fmt.Errorf("private key is empty for signer %s (check key_env value or environment variable)", pk.Address)
		}

		privKeySigner, err := ethsig.NewEthPrivateKeySignerFromPrivateKeyHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to create private key signer for %s: %w", pk.Address, err)
		}

		expectedAddr := common.HexToAddress(pk.Address)
		actualAddr := privKeySigner.GetAddress()
		if actualAddr != expectedAddr {
			return nil, fmt.Errorf("address mismatch for %s: expected %s, got %s", pk.Address, expectedAddr.Hex(), actualAddr.Hex())
		}

		signer := ethsig.NewSigner(privKeySigner)
		if err := registry.RegisterSigner(actualAddr.Hex(), signer, types.SignerInfo{
			Address: actualAddr.Hex(),
			Type:    string(types.SignerTypePrivateKey),
			Enabled: true,
		}); err != nil {
			return nil, fmt.Errorf("failed to register private key signer %s: %w", pk.Address, err)
		}
	}

	return p, nil
}

func (p *PrivateKeyProvider) Type() types.SignerType {
	return types.SignerTypePrivateKey
}

func (p *PrivateKeyProvider) Close() error {
	return nil
}
