package evm

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------- the request family's route-test fixture ----------
//
// ⚠️ Exported, and in `package evm` rather than `package evm_test`, for the same
// reason MockSignerManager is: the route tests live in the external test package
// (they import internal/api, which imports this one), and an external test file
// can only reach exported identifiers — but it *can* reach ones declared in this
// package's own _test.go files, which is where a fixture belongs.
//
// ⭐ Every spy here records an *effect*, not a status. That is the whole point:
// the method guards the decomposition removed used to be asserted by "the handler
// answered 405", and a handler that changes a row and *then* writes 405 passes
// that check. What replaces it is "ProcessApproval was never called".

// RequestRouteID is a request id shaped like a real one — internal/core/service
// mints uuid.New().String() and nothing else creates one, so it never contains a
// '/'. ⭐ Written as a UUID rather than "req-1" so the route tests exercise the
// id shape clients actually send.
const RequestRouteID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"

// requestRouteSigner owns the request in the fixture.
const requestRouteSigner = "0x1111111111111111111111111111111111111111"

// RequestRouteAdminKey holds every permission the request routes ask for and owns
// the fixture's signer, so a request that reaches a handler gets all the way
// through. ⛔ Without that, a refusal could be a 403 the test mistakes for "the
// route did not match".
func RequestRouteAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
}

// RequestRouteFixture holds the six handlers requestsModule wraps, over one spy
// sign service and two spy repositories.
type RequestRouteFixture struct {
	List       *ListHandler
	Detail     *RequestHandler
	Approval   *ApprovalHandler
	Batch      *BatchApprovalHandler
	Preview    *PreviewRuleHandler
	Simulation *RequestSimulationHandler

	approved  []string
	previewed []string
	fetched   []string
	simsRead  []string
}

// NewRequestRouteFixture builds all six handlers. Each spy answers successfully,
// so any request that reaches a handler produces a visible effect.
func NewRequestRouteFixture(t *testing.T) *RequestRouteFixture {
	t.Helper()
	fx := &RequestRouteFixture{}

	svc := &mockSignService{
		getRequestFn: func(_ context.Context, id types.SignRequestID) (*types.SignRequest, error) {
			fx.fetched = append(fx.fetched, string(id))
			req := makeSignRequest(string(id), types.StatusAuthorizing)
			req.APIKeyID = RequestRouteAdminKey().ID
			req.SignerAddress = requestRouteSigner
			return req, nil
		},
		listRequestsFn: func(_ context.Context, _ storage.RequestFilter) ([]*types.SignRequest, error) {
			return []*types.SignRequest{makeSignRequest(RequestRouteID, types.StatusAuthorizing)}, nil
		},
		countRequestsFn: func(_ context.Context, _ storage.RequestFilter) (int, error) { return 1, nil },
		processApprovalFn: func(_ context.Context, id types.SignRequestID, _ *service.ApprovalRequest) (*service.ApprovalResponse, error) {
			fx.approved = append(fx.approved, string(id))
			return &service.ApprovalResponse{SignResponse: &service.SignResponse{
				RequestID: id, Status: types.StatusCompleted, Signature: []byte{0xde, 0xad},
			}}, nil
		},
		previewRuleFn: func(_ context.Context, id types.SignRequestID, _ *rule.RuleGenerateOptions) (*types.Rule, error) {
			fx.previewed = append(fx.previewed, string(id))
			return &types.Rule{ID: "rule_preview", Name: "preview"}, nil
		},
	}

	access := newFlexAccessService(t, map[string]string{requestRouteSigner: RequestRouteAdminKey().ID})

	var err error
	fx.List, err = NewListHandler(svc, newMockRuleRepo(), slog.Default())
	require.NoError(t, err)
	fx.Detail, err = NewRequestHandler(svc, newMockRuleRepo(), slog.Default())
	require.NoError(t, err)
	fx.Approval, err = NewApprovalHandler(svc, access, slog.Default(), nil)
	require.NoError(t, err)
	fx.Batch, err = NewBatchApprovalHandler(svc, access, slog.Default())
	require.NoError(t, err)
	fx.Preview, err = NewPreviewRuleHandler(svc, slog.Default())
	require.NoError(t, err)
	fx.Simulation, err = NewRequestSimulationHandler(
		&requestRouteSimRepo{fx: fx}, &requestRouteRequestRepo{fx: fx}, slog.Default())
	require.NoError(t, err)

	return fx
}

// Approved returns the request ids ProcessApproval was called with, in order.
func (f *RequestRouteFixture) Approved() []string { return f.approved }

// Previewed returns the request ids PreviewRuleForRequest was called with.
func (f *RequestRouteFixture) Previewed() []string { return f.previewed }

// Fetched returns the request ids GetRequest was called with.
func (f *RequestRouteFixture) Fetched() []string { return f.fetched }

// SimulationsRead returns the request ids the simulation repository was asked for.
func (f *RequestRouteFixture) SimulationsRead() []string { return f.simsRead }

// Touched reports whether any endpoint did anything at all — read or write. ⭐ The
// assertion for a shape that must reach no handler: "nothing ran" is stronger than
// "the status was 404", and it is the one that would catch a handler that mutates
// before refusing.
func (f *RequestRouteFixture) Touched() bool {
	return len(f.approved) > 0 || len(f.previewed) > 0 || len(f.fetched) > 0 || len(f.simsRead) > 0
}

// ---------- spy repositories for the simulation endpoint ----------
//
// ⚠️ Each embeds the interface it satisfies, so only the methods the handler calls
// need writing and any other call panics rather than answering something made up.

type requestRouteSimRepo struct {
	storage.RequestSimulationRepository
	fx *RequestRouteFixture
}

func (r *requestRouteSimRepo) GetByRequestID(_ context.Context, id string) (*types.RequestSimulation, error) {
	r.fx.simsRead = append(r.fx.simsRead, id)
	return &types.RequestSimulation{
		SignRequestID: id, ChainID: "1", Decision: "allow", Success: true,
		SimulatedAt: time.Now(), UpdatedAt: time.Now(),
	}, nil
}

type requestRouteRequestRepo struct {
	storage.RequestRepository
	fx *RequestRouteFixture
}

func (r *requestRouteRequestRepo) Get(_ context.Context, id types.SignRequestID) (*types.SignRequest, error) {
	req := makeSignRequest(string(id), types.StatusAuthorizing)
	req.APIKeyID = RequestRouteAdminKey().ID
	return req, nil
}
