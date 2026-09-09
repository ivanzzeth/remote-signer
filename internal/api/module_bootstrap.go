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
	reg.Public("GET /api/v1/bootstrap/status", http.HandlerFunc(m.h.ServeStatus))
	reg.Public("POST /api/v1/bootstrap/admin", http.HandlerFunc(m.h.ServeAdmin))
}
