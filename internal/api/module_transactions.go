package api

import (
	"log/slog"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/ports"
)

// transactionsModule serves the read-only view of on-chain transactions the
// daemon recorded.
//
// Registered independently of the RPC proxy: an operator who does not broadcast
// through the daemon may still want to see rows an older build wrote.
// Authenticated rather than permissioned — visibility is enforced inside the
// handler by joining sign_request.api_key_id against the caller, which is a
// per-row decision a route cannot make.
type transactionsModule struct {
	h *evmhandler.TransactionsHandler
}

func NewTransactionsModule(repo ports.TransactionRepository, log *slog.Logger) (Module, error) {
	if repo == nil {
		return nil, nil
	}
	h, err := evmhandler.NewTransactionsHandler(repo, log)
	if err != nil {
		return nil, err
	}
	return &transactionsModule{h: h}, nil
}

func (m *transactionsModule) Name() string { return "transactions" }

func (m *transactionsModule) Routes(reg RouteRegistrar) {
	const why = "read-only and per-row: the handler joins sign_request.api_key_id against the caller, so a " +
		"non-admin sees only transactions its own sign requests produced. Which rows a caller may see is not a " +
		"decision a route can make, and there is no read_transactions permission to name — every authenticated " +
		"role is allowed to look at its own."
	reg.Handle("GET /api/v1/evm/transactions", AuthenticatedOnly(why), m.h)
	reg.Handle("GET /api/v1/evm/transactions/", AuthenticatedOnly(why), m.h)
}
