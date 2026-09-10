package api

import (
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/bootstrap"
	"github.com/ivanzzeth/remote-signer/internal/core/ports"
)

// bootstrapModule serves the first-run admin-keystore setup.
//
// ⚠️ Unauthenticated by design: it exists precisely because no API key exists
// yet. The window closes on its own — the handler returns 410 once an admin
// key is present — so the security property is in the handler's state check,
// not in a permission.
type bootstrapModule struct {
	h *handler.BootstrapHandler
}

// newBootstrapModule returns nil when the daemon cannot bootstrap: an embedded
// or test build without a creator has nothing to serve, and saying so here
// beats a nil check at the route.
func NewBootstrapModule(repo ports.APIKeyRepository, creator bootstrap.AdminCreator, log *slog.Logger) Module {
	if repo == nil || creator == nil {
		return nil
	}
	return &bootstrapModule{h: handler.NewBootstrapHandler(repo, creator, log)}
}

func (m *bootstrapModule) Name() string { return "bootstrap" }

func (m *bootstrapModule) Routes(reg RouteRegistrar) {
	const why = "first run: the api_keys table is empty, so there is no public key to verify a signed request " +
		"against and requiring auth here would be a deadlock. The window closes on its own — the handler returns " +
		"410 Gone once an admin key exists — so the security property lives in that state check, not in a " +
		"permission. The module is nil when no AdminCreator is wired, so a daemon that pre-seeds admin out of " +
		"band never serves these at all."
	reg.Handle("GET /api/v1/bootstrap/status", Public(why), http.HandlerFunc(m.h.ServeStatus))
	reg.Handle("POST /api/v1/bootstrap/admin", Public(why), http.HandlerFunc(m.h.ServeAdmin))
}
