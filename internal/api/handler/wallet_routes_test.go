//go:build integration

// Package handler_test holds the wallet handler's route-level tests.
//
// # Why these live in an external test package (proposal §2.4, step S2)
//
// S3 splits WalletHandler into one route per method and sub-path and moves it
// onto r.PathValue. §2.4's argument is that the test entry point must move
// first, while the handler is still unchanged, and that the suite be recorded as
// green across that move: after S3 lands, any test difference is then caused by
// the decomposition, and not by the harness having moved at the same time.
//
// ⛔ The tempting way to do this — build an http.ServeMux in the fixture and
// register "/api/v1/wallets" and "/api/v1/wallets/" by hand — creates a second
// source of truth for the route table. It drifts from router.go silently: the
// tests stay green while exercising routes the daemon does not serve. So the
// patterns come from the production registration instead, api.walletsModule's
// Routes(), reached through the exported api.Module / api.RouteRegistrar pair.
//
// ⚠️ Which is why this is `package handler_test` and not `package handler`:
// internal/api imports internal/api/handler (router.go:13), so an in-package
// test file cannot import internal/api back — that is an import cycle. An
// external test package can, because nothing imports it. The cost is that these
// tests can only use exported identifiers, and the two that matter are:
//
//   - the wallet DTOs are unexported, so the response shapes are mirrored below
//     as *Wire structs. ⚠️ A mirror can drift; what stops it here is that these
//     are the JSON field names a client parses, so a drift breaks the same
//     assertion a real client would break on. Exporting the DTOs is S3's job
//     (proposal §3.3), and doing it here would be a production change under a
//     test refactor.
//   - tests that call WalletHandler's unexported methods directly
//     (createWallet, addMember, …) cannot move and did not: they stayed in
//     wallet_coverage_test.go and wallet_test.go as `package handler`. They were
//     never route tests — they bypass both the mux and the handler's own
//     dispatch — so routing them through a mux is not a thing that could be done
//     to them.
//
// ⚠️ What these tests still do NOT exercise: the middleware chain. The routes
// register as Permitted(PermManageWallets), whose chain begins with
// AuthMiddleware, which refuses any request lacking X-API-Key-ID / X-Timestamp /
// X-Signature (middleware/auth.go:62-69). Every test below injects its API key
// through the request context instead, as they always have. So the test
// registrar drops the RouteAuth it is handed and registers the bare handler:
// what moved is dispatch, and nothing here asserts anything about authorization.
// ⛔ Do not read a green run as evidence that a wallet route is correctly
// permissioned — that lives in the archcheck route-auth gates and their
// baselines.
package handler_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------- wire shapes ----------
//
// Mirrors of handler/wallet.go's unexported walletResponse / walletListResponse
// / membersListResponse, by JSON tag.

type walletWire struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerID     string `json:"owner_id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type walletListWire struct {
	Wallets []walletWire `json:"wallets"`
	Total   int          `json:"total"`
	HasMore bool         `json:"has_more"`
}

type memberWire struct {
	WalletID      string `json:"wallet_id"`
	SignerAddress string `json:"signer_address"`
	AddedAt       string `json:"added_at"`
}

type membersListWire struct {
	Members []memberWire `json:"members"`
}

// ---------- the registrar ----------

// muxRegistrar satisfies api.RouteRegistrar by putting each pattern into a bare
// mux. ⚠️ It drops the api.RouteAuth on purpose; see the package comment. The
// patterns themselves are not this type's to choose — they arrive from
// walletsModule.Routes(), which is the same call setupRoutes makes.
type muxRegistrar struct{ mux *http.ServeMux }

func (m muxRegistrar) Handle(pattern string, _ api.RouteAuth, h http.Handler) {
	m.mux.Handle(pattern, h)
}

// walletMux registers the production wallet routes over an otherwise empty mux.
//
// ⭐ An empty mux is deliberate: a path no wallet pattern claims must reach
// nothing at all, which is exactly the property direct h.ServeHTTP dispatch
// could not have. TestWalletRoutes_UnclaimedPathNoLongerReachesTheHandler pins
// it.
func walletMux(
	t *testing.T,
	repo storage.WalletRepository,
	ownershipRepo storage.SignerOwnershipRepository,
	accessRepo storage.SignerAccessRepository,
) http.Handler {
	t.Helper()

	mod, err := api.NewWalletsModule(repo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, mod, "NewWalletsModule returned no module, so no wallet pattern would be registered "+
		"and every request below would 404 for a reason that has nothing to do with what is under test")

	mux := http.NewServeMux()
	mod.Routes(muxRegistrar{mux: mux})
	return mux
}

// walletTestDB is the in-memory schema every wallet test runs against.
func walletTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.Wallet{},
		&types.WalletMember{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
	))
	return db
}

// TestWalletRoutes_RegistersExactlyTheProductionPatterns is the one assertion
// that would notice the harness quietly registering nothing, or registering
// something else. ⚠️ It does not say these two patterns are *right* — it says
// the mux the tests below drive is the mux walletsModule builds, which is the
// only reason a green run here means anything about the daemon.
//
// ⛔ If S3 changes this list, that is the change, not a number to update: every
// test in this package then routes through the new patterns, and a difference in
// results is the decomposition's, which is the whole point of doing S2 first.
func TestWalletRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	repo, ownershipRepo, accessRepo := walletRepos(t, walletTestDB(t))
	mod, err := api.NewWalletsModule(repo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, mod)

	var got []string
	mod.Routes(recordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got = append(got, pattern+" → "+auth.String())
	}})

	// ⛔ The auth half is here because S2 was allowed to move these registrations
	// and forbidden to change what they decide. Both were
	// Permitted(PermManageWallets) inline in setupRoutes; if either had silently
	// become AuthenticatedOnly on the way into the module, nothing else in this
	// package would notice — none of these tests goes through the middleware
	// chain at all.
	assert.Equal(t, []string{
		"/api/v1/wallets → permitted(manage_wallets)",
		"/api/v1/wallets/ → permitted(manage_wallets)",
	}, got)
	assert.Equal(t, "wallets", mod.Name())
}

// recordingRegistrar captures what a module registers without a mux.
type recordingRegistrar struct {
	record func(pattern string, auth api.RouteAuth)
}

func (r recordingRegistrar) Handle(pattern string, auth api.RouteAuth, _ http.Handler) {
	r.record(pattern, auth)
}

// TestWalletRoutes_UnclaimedPathNoLongerReachesTheHandler is the evidence that
// step S2 actually changed something, run as a controlled pair: the same request
// dispatched directly at the handler and dispatched through the mux.
//
// ⭐ WalletHandler.ServeHTTP never looks at the path at all — it switches on the
// method — so called directly it answers 200 with a wallet listing for *any*
// path whatsoever, including one no wallet route claims. That is what every test
// in this package was doing before S2: asserting a status code the URL had no
// influence over. Through the mux the same request reaches nothing and gets the
// mux's own 404.
//
// ⚠️ The `direct` arm below is the last h.ServeHTTP call in the wallet family
// and it is deliberate: it is the control, not the harness. Delete it and this
// test degrades to "a 404 came back", which a mux with no routes at all would
// also satisfy.
func TestWalletRoutes_UnclaimedPathNoLongerReachesTheHandler(t *testing.T) {
	const unclaimed = "/api/v1/wallets-archive"

	repo, ownershipRepo, accessRepo := walletRepos(t, walletTestDB(t))
	h, err := handler.NewWalletHandler(repo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)
	mux := walletMux(t, repo, ownershipRepo, accessRepo)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, unclaimed, nil)
		return req.WithContext(context.WithValue(context.Background(),
			middleware.APIKeyContextKey, &types.APIKey{ID: "user-1", Role: types.RoleDev, Enabled: true}))
	}

	direct := httptest.NewRecorder()
	h.ServeHTTP(direct, newReq())
	require.Equal(t, http.StatusOK, direct.Code,
		"premise of this test: dispatched directly, the handler serves %s as though it were /api/v1/wallets. "+
			"If that stops being true the control arm is gone and the routed arm proves nothing on its own", unclaimed)
	require.Contains(t, direct.Body.String(), `"wallets"`)

	routed := httptest.NewRecorder()
	mux.ServeHTTP(routed, newReq())
	assert.Equal(t, http.StatusNotFound, routed.Code,
		"%s is claimed by no wallet pattern, so it must reach no wallet handler", unclaimed)
	assert.NotContains(t, routed.Body.String(), `"wallets"`,
		"the mux answered, but with the handler's listing — a pattern is claiming more than it should")
}

// walletRepos builds the three repositories the wallet routes need.
func walletRepos(t *testing.T, db *gorm.DB) (
	storage.WalletRepository,
	storage.SignerOwnershipRepository,
	storage.SignerAccessRepository,
) {
	t.Helper()
	repo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	return repo, ownershipRepo, accessRepo
}
