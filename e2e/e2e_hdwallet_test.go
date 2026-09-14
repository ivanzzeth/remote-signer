//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// HD Wallet Management Tests
// =============================================================================

func TestHDWallet_CreateAndList(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Skipping: HD wallet creation test not supported with external server")
	}

	ctx := context.Background()

	// Create a new HD wallet
	resp, err := adminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password:    "test-hd-wallet-password-e2e",
		EntropyBits: 128,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.PrimaryAddress, "HD wallet should have a primary address")
	assert.NotEmpty(t, resp.BasePath, "HD wallet should have a base path")
	assert.GreaterOrEqual(t, resp.DerivedCount, 1, "Should have at least the primary address derived")

	// List HD wallets
	listResp, err := adminClient.EVM.HDWallets.List(ctx)
	require.NoError(t, err)
	require.NotNil(t, listResp)
	assert.GreaterOrEqual(t, len(listResp.Wallets), 1, "Should have at least one HD wallet")

	// Verify the newly created wallet is in the list
	found := false
	for _, w := range listResp.Wallets {
		if w.PrimaryAddress == resp.PrimaryAddress {
			found = true
			assert.Equal(t, resp.BasePath, w.BasePath)
			break
		}
	}
	assert.True(t, found, "Newly created HD wallet should appear in the list")

	// Verify the primary address appears in signers list
	signersResp, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Type:  "hd_wallet",
		Limit: 100,
	})
	require.NoError(t, err)

	foundSigner := false
	for _, s := range signersResp.Signers {
		if s.Address == resp.PrimaryAddress {
			foundSigner = true
			assert.Equal(t, "hd_wallet", s.Type)
			assert.True(t, s.Enabled)
			break
		}
	}
	assert.True(t, foundSigner, "Primary address should appear in signers list")
}

func TestHDWallet_DeriveAddresses(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Skipping: HD wallet derive test not supported with external server")
	}

	ctx := context.Background()

	// Create a new HD wallet for this test
	createResp, err := adminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password:    "test-derive-password-e2e",
		EntropyBits: 128,
	})
	require.NoError(t, err)
	primaryAddr := createResp.PrimaryAddress

	// Derive a single address at index 1
	idx := uint32(1)
	deriveResp, err := adminClient.EVM.HDWallets.DeriveAddress(ctx, primaryAddr, &evm.DeriveAddressRequest{
		Index: &idx,
	})
	require.NoError(t, err)
	require.NotNil(t, deriveResp)
	assert.Len(t, deriveResp.Derived, 1, "Should derive exactly 1 address")
	assert.NotEqual(t, primaryAddr, deriveResp.Derived[0].Address, "Derived address should differ from primary")
	assert.Equal(t, "hd_wallet", deriveResp.Derived[0].Type)

	// Derive a batch of addresses (indices 2-4)
	start := uint32(2)
	count := uint32(3)
	batchResp, err := adminClient.EVM.HDWallets.DeriveAddress(ctx, primaryAddr, &evm.DeriveAddressRequest{
		Start: &start,
		Count: &count,
	})
	require.NoError(t, err)
	require.NotNil(t, batchResp)
	assert.Len(t, batchResp.Derived, 3, "Should derive exactly 3 addresses")

	// All derived addresses should be unique
	addrSet := map[string]bool{primaryAddr: true, deriveResp.Derived[0].Address: true}
	for _, d := range batchResp.Derived {
		assert.False(t, addrSet[d.Address], "Derived address should be unique: %s", d.Address)
		addrSet[d.Address] = true
	}

	// List derived addresses
	listResp, err := adminClient.EVM.HDWallets.ListDerived(ctx, primaryAddr)
	require.NoError(t, err)
	require.NotNil(t, listResp)
	assert.GreaterOrEqual(t, len(listResp.Derived), 5, "Should have at least 5 derived addresses (0-4)")
}

func TestHDWallet_DerivedAddressCanSign(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Skipping: HD wallet signing test not supported with external server")
	}

	ctx := context.Background()

	// Create HD wallet
	createResp, err := adminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password:    "test-sign-password-e2e",
		EntropyBits: 128,
	})
	require.NoError(t, err)
	primaryAddr := createResp.PrimaryAddress

	// First, create a signer restriction whitelist rule for this address
	signerRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name: "E2E HD wallet signer allow",
		Type: "signer_restriction",
		Mode: "whitelist",
		Config: map[string]interface{}{
			"allowed_signers": []string{primaryAddr},
		},
		Enabled: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if delErr := adminClient.EVM.Rules.Delete(context.Background(), signerRule.ID); delErr != nil {
			t.Logf("Warning: failed to cleanup HD wallet signer rule: %v", delErr)
		}
	})

	// Sign a personal message with the primary address
	payload, err := json.Marshal(map[string]interface{}{"message": "Hello from HD wallet"})
	require.NoError(t, err)

	signResp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: primaryAddr,
		SignType:      "personal",
		Payload:       payload,
	})
	require.NoError(t, err)
	require.NotNil(t, signResp)
	assert.Equal(t, "completed", signResp.Status)
	assert.NotEmpty(t, signResp.Signature)
}

func TestHDWallet_NonAdminCannotCreate(t *testing.T) {
	ensureGuardResumed(t)
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to create HD wallets
	_, err := nonAdminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password: "should-fail",
	})
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

// TestHDWallet_NonAdminCannotList now asserts what its name has always claimed.
//
// ⭐ 2026-09-14. Until the HD-wallet routes were given permissions, this test
// asserted the opposite of its own name: the strategy key listed successfully
// and saw an empty array, because GET /api/v1/evm/hd-wallets carried no
// permission at all and listWallets merely filtered the rows by
// ownership+access. The body had been relaxed to describe that reality.
//
// ⛔ The route now carries PermReadHDWallets, which strategy does not hold, so
// the refusal happens in middleware before the handler runs. That is a stricter
// answer than "200 with nothing in it", not a weaker one — an empty list still
// confirms the endpoint exists and is reachable, which is exactly what a
// sign-only role should not learn from this surface.
//
// ⚠️ The capability a strategy key actually needs is not lost: an HD wallet it
// has been granted access to still appears in GET /api/v1/evm/signers with
// type=hd_wallet, which is gated on read_signers (strategy holds it) and scoped
// by the same access set.
func TestHDWallet_NonAdminCannotList(t *testing.T) {
	ensureGuardResumed(t)
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	_, err := nonAdminClient.EVM.HDWallets.List(ctx)
	require.Error(t, err, "strategy holds neither read_hd_wallets nor create_hd_wallet")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode, "strategy must be refused the HD wallet listing")
}

func TestHDWallet_ValidationErrors(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Skipping: HD wallet validation test not supported with external server")
	}

	ctx := context.Background()

	// Missing password
	_, err := adminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password: "",
	})
	require.Error(t, err)

	// Derive from non-existent wallet
	idx := uint32(0)
	_, err = adminClient.EVM.HDWallets.DeriveAddress(ctx, "0x0000000000000000000000000000000000000000", &evm.DeriveAddressRequest{
		Index: &idx,
	})
	require.Error(t, err)
}

// TestHDWallet_StrategyKeyIsRefusedTheWholeSurface is the negative verification
// for the slice that gave the four HD-wallet routes a permission.
//
// ⛔ Before that slice every route here was AuthenticatedOnly, so a strategy key
// — which holds neither read_hd_wallets nor create_hd_wallet — reached all four.
// This walks all four and asserts by EFFECT where an effect exists: after the
// refused create, the admin key lists the wallets and the count is unchanged.
//
// ⚠️ The control arm matters as much as the refusals. A strategy key that could
// not talk to the daemon at all would satisfy every 403 below, so the test first
// proves the key works by calling an endpoint strategy IS entitled to
// (GET /api/v1/evm/signers, gated on read_signers) — which is also the migration
// path this narrowing relies on being open.
//
// # ⛔ What this test does NOT prove, measured rather than assumed
//
// Each arm was checked by reverting its route to AuthenticatedOnly and re-running:
//
//	list     → FAILS without the permission.  ✅ this test guards it
//	derive   → FAILS without the permission.  ✅ (only because of the grant below)
//	derived  → FAILS without the permission.  ✅ (same reason)
//	create   → still PASSES without it.       ⛔ this test does NOT guard create
//
// ⛔ The create arm is over-determined and cannot be fixed here: hdwallet.go:228
// refuses a non-admin with its own 403 before anything else, so the route
// permission and the handler check are indistinguishable from outside. That is
// not a defect in the permission — create_hd_wallet is granted to admin alone,
// so the two agree exactly by construction — it is the reason the route-level
// assertion TestHDWalletRoutes_RegistersExactlyTheProductionPatterns is what
// actually stands guard over that one line. ⚠️ Do not read this test's green as
// evidence that POST /api/v1/evm/hd-wallets is permissioned.
func TestHDWallet_StrategyKeyIsRefusedTheWholeSurface(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	stratClient := createRoleClient(t, "strategy", "e2e-hdw-perm-strategy")

	// ---------- control arm ----------
	if _, err := stratClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{Limit: 10}); err != nil {
		t.Fatalf("premise of this test: a strategy key holds read_signers and can reach the daemon. "+
			"It could not (%v), so every 403 below proves nothing — and the migration path this "+
			"narrowing depends on would be shut too", err)
	}

	before, err := adminClient.EVM.HDWallets.List(ctx)
	require.NoError(t, err)

	// ---------- list ----------
	_, err = stratClient.EVM.HDWallets.List(ctx)
	expectAPIError(t, err, 403, "strategy holds no read_hd_wallets: listing must be refused")

	// ---------- create ----------
	_, err = stratClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password: "strategy-must-not-create",
	})
	expectAPIError(t, err, 403, "strategy holds no create_hd_wallet: creation must be refused")

	after, err := adminClient.EVM.HDWallets.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, len(before.Wallets), len(after.Wallets),
		"⛔ the 403 was cosmetic: an HD wallet was created anyway (%d → %d)",
		len(before.Wallets), len(after.Wallets))

	// ---------- derive / derived, against a wallet this key HAS access to ----------
	//
	// ⛔ The access grant is the whole point of this half, and without it this
	// section proves nothing. Measured: with derive left un-permissioned
	// (AuthenticatedOnly) and no grant, a strategy key still gets 403 — from
	// resolveAccessibleWallet's CheckAccess, not from RBAC. The two refusals are
	// indistinguishable by status code, so the 403s below would have been
	// over-determined and the test would pass with the hole wide open.
	//
	// ⭐ Granting access removes the resource-scoped refusal, so the route
	// permission is the only thing left that can answer 403. It is also the exact
	// scenario that made this narrowing a real decision rather than a formality:
	// a strategy key that legitimately has access to an HD wallet.
	created, err := adminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password: "e2e-hdw-perm-fixture",
	})
	require.NoError(t, err)

	require.NoError(t, adminClient.EVM.Signers.GrantAccess(ctx, created.PrimaryAddress,
		&evm.GrantAccessRequest{APIKeyID: "e2e-hdw-perm-strategy"}),
		"premise: the admin owns this wallet and can grant the strategy key access to it")
	t.Cleanup(func() {
		_ = adminClient.EVM.Signers.RevokeAccess(context.Background(), created.PrimaryAddress, "e2e-hdw-perm-strategy")
	})

	// ⭐ The migration path, asserted rather than asserted-about: with that grant
	// the strategy key still reaches the wallet through the signers surface,
	// which is gated on read_signers. If this ever stops being true the
	// narrowing above stops being safe.
	signers, err := stratClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{Type: "hd_wallet", Limit: 100})
	require.NoError(t, err, "strategy must still be able to list signers it has access to")
	foundViaSigners := false
	for _, s := range signers.Signers {
		if s.Address == created.PrimaryAddress {
			foundViaSigners = true
			break
		}
	}
	assert.True(t, foundViaSigners,
		"⛔ the documented migration path is shut: a strategy key with access to %s cannot find it "+
			"through GET /api/v1/evm/signers either, so closing the HD-wallet routes removed the "+
			"capability rather than moving it", created.PrimaryAddress)

	// ⚠️ A freshly created wallet already has its primary derived at index 0, so
	// the effect assertion is a before/after count, not a zero.
	derivedBefore, err := adminClient.EVM.HDWallets.ListDerived(ctx, created.PrimaryAddress)
	require.NoError(t, err)

	idx := uint32(7)
	_, err = stratClient.EVM.HDWallets.DeriveAddress(ctx, created.PrimaryAddress, &evm.DeriveAddressRequest{
		Index: &idx,
	})
	expectAPIError(t, err, 403, "strategy holds no read_hd_wallets: derive must be refused")

	_, err = stratClient.EVM.HDWallets.ListDerived(ctx, created.PrimaryAddress)
	expectAPIError(t, err, 403, "strategy holds no read_hd_wallets: listing derived must be refused")

	derivedAfter, err := adminClient.EVM.HDWallets.ListDerived(ctx, created.PrimaryAddress)
	require.NoError(t, err)
	assert.Equal(t, len(derivedBefore.Derived), len(derivedAfter.Derived),
		"⛔ the 403 was cosmetic: the strategy key's derive produced an address anyway (%d → %d)",
		len(derivedBefore.Derived), len(derivedAfter.Derived))
}
