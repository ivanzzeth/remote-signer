// Package evm provides EVM-specific client services for the remote-signer.
package evm

import (
	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// Service groups all EVM-related sub-services.
type Service struct {
	Sign      *SignService
	Requests  *RequestService
	Rules     *RuleService
	Signers   *SignerService
	HDWallets *HDWalletService
	Guard     *GuardService
}

// NewService creates a new EVM service group.
func NewService(t *transport.Transport) *Service {
	sign := &SignService{transport: t}
	return &Service{
		Sign:      sign,
		Requests:  &RequestService{transport: t},
		Rules:     &RuleService{transport: t},
		Signers:   &SignerService{transport: t},
		HDWallets: &HDWalletService{transport: t, sign: sign},
		Guard:     &GuardService{transport: t},
	}
}
