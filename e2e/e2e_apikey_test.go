//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
)

// =============================================================================
// API Key List Tests
// =============================================================================

func TestAPIKey_List(t *testing.T) {
	ctx := context.Background()

	resp, err := adminClient.APIKeys.List(ctx, &apikeys.ListFilter{
		Limit: 100,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// At least the admin and non-admin test keys should exist
	assert.GreaterOrEqual(t, resp.Total, 1, "Should have at least the admin API key")
	assert.GreaterOrEqual(t, len(resp.Keys), 1, "Should return at least one key")

	// Verify the admin key is in the list
	found := false
	for _, key := range resp.Keys {
		if key.ID == adminAPIKeyID {
			found = true
			assert.Equal(t, "admin", key.Role, "Admin key should have role=admin")
			assert.True(t, key.Enabled, "Admin key should be enabled")
			assert.NotEmpty(t, key.ID, "Key should have an ID")
			break
		}
	}
	assert.True(t, found, "Admin API key should be in the list")
}

func TestAPIKey_List_FilterBySource(t *testing.T) {
	ctx := context.Background()

	// List with source="config" filter
	resp, err := adminClient.APIKeys.List(ctx, &apikeys.ListFilter{
		Source: "config",
		Limit:  100,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// All returned keys should have source="config"
	for _, key := range resp.Keys {
		assert.Equal(t, "config", key.Source,
			"All keys returned with source=config filter should have source=config, got key %s with source=%s",
			key.ID, key.Source)
	}

	// List with source="api" filter
	respAPI, err := adminClient.APIKeys.List(ctx, &apikeys.ListFilter{
		Source: "api",
		Limit:  100,
	})
	require.NoError(t, err)
	require.NotNil(t, respAPI)

	for _, key := range respAPI.Keys {
		assert.Equal(t, "api", key.Source,
			"All keys returned with source=api filter should have source=api, got key %s with source=%s",
			key.ID, key.Source)
	}
}

func TestAPIKey_List_Pagination(t *testing.T) {
	ctx := context.Background()

	// List with limit=1
	resp, err := adminClient.APIKeys.List(ctx, &apikeys.ListFilter{
		Limit: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.LessOrEqual(t, len(resp.Keys), 1, "Should return at most 1 key")

	// If there are more keys, pagination should work
	if resp.Total > 1 {
		// Get next page
		resp2, err := adminClient.APIKeys.List(ctx, &apikeys.ListFilter{
			Offset: 1,
			Limit:  1,
		})
		require.NoError(t, err)
		require.NotNil(t, resp2)
		assert.LessOrEqual(t, len(resp2.Keys), 1, "Second page should return at most 1 key")

		// Should have different keys
		if len(resp.Keys) > 0 && len(resp2.Keys) > 0 {
			assert.NotEqual(t, resp.Keys[0].ID, resp2.Keys[0].ID,
				"Page 2 should have a different key than page 1")
		}
	}
}

// =============================================================================
// API Key Get Tests
// =============================================================================

func TestAPIKey_Get(t *testing.T) {
	ctx := context.Background()

	// Get the admin key by ID
	key, err := adminClient.APIKeys.Get(ctx, adminAPIKeyID)
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Equal(t, adminAPIKeyID, key.ID)
	assert.Equal(t, "admin", key.Role, "Admin key should have role=admin")
	assert.True(t, key.Enabled, "Admin key should be enabled")
	assert.NotZero(t, key.CreatedAt, "CreatedAt should be set")
	assert.NotZero(t, key.UpdatedAt, "UpdatedAt should be set")
}

func TestAPIKey_Get_NotFound(t *testing.T) {
	ctx := context.Background()

	_, err := adminClient.APIKeys.Get(ctx, "nonexistent-key-id-e2e-12345")
	require.Error(t, err, "Should return error for non-existent key")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 404, apiErr.StatusCode, "Should return 404 for non-existent key")
}

// =============================================================================
// API Key Create Tests
// =============================================================================

func TestAPIKey_Create_ReadonlyMode(t *testing.T) {
	// In the default e2e test server, APIKeysAPIReadonly is false (not set in
	// RouterConfig). If the server is configured with readonly mode, create
	// should fail with 403. We detect this by attempting a create and checking
	// the result.
	if useExternalServer {
		t.Log("External server mode: checking if API key management is readonly")
	}

	ctx := context.Background()

	// Generate a throwaway Ed25519 key for the create request
	pubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	req := &apikeys.CreateRequest{
		ID:              "e2e-readonly-test-key",
		Name:            "E2E Readonly Test",
		PublicKey:       hex.EncodeToString(pubKey),
		Role:            "strategy",

	}

	key, createErr := adminClient.APIKeys.Create(ctx, req)

	if createErr != nil {
		// If readonly mode, expect 403
		apiErr, ok := createErr.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Log("API key management is readonly (403 Forbidden) - this is expected in readonly mode")
			return
		}
		// Other errors are unexpected
		require.NoError(t, createErr, "Unexpected error creating API key")
	}

	// If create succeeded, clean up
	require.NotNil(t, key)
	assert.Equal(t, "e2e-readonly-test-key", key.ID)
	assert.Equal(t, "api", key.Source, "API-created key should have source=api")

	// Clean up: delete the key we just created
	delErr := adminClient.APIKeys.Delete(ctx, key.ID)
	require.NoError(t, delErr, "Failed to clean up created API key")
}

func TestAPIKey_Create_And_Get(t *testing.T) {
	ctx := context.Background()

	// Generate a throwaway Ed25519 key
	pubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	req := &apikeys.CreateRequest{
		ID:              "e2e-create-get-test-key",
		Name:            "E2E Create Get Test",
		PublicKey:       hex.EncodeToString(pubKey),
		Role:            "strategy",
		RateLimit:       200,

	}

	created, err := adminClient.APIKeys.Create(ctx, req)
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Skip("Skipping: API key management is readonly")
		}
		require.NoError(t, err)
	}
	require.NotNil(t, created)

	// Cleanup deferred
	t.Cleanup(func() {
		delErr := adminClient.APIKeys.Delete(context.Background(), created.ID)
		if delErr != nil {
			t.Logf("Warning: failed to clean up API key %s: %v", created.ID, delErr)
		}
	})

	assert.Equal(t, "e2e-create-get-test-key", created.ID)
	assert.Equal(t, "E2E Create Get Test", created.Name)
	assert.Equal(t, "api", created.Source, "API-created key should have source=api")
	assert.True(t, created.Enabled, "Newly created key should be enabled")
	assert.Equal(t, "strategy", created.Role, "Key should have role=strategy")

	// Now fetch it back
	fetched, err := adminClient.APIKeys.Get(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, fetched)

	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, created.Name, fetched.Name)
	assert.Equal(t, created.Source, fetched.Source)
	assert.Equal(t, created.Role, fetched.Role)
	assert.Equal(t, created.Enabled, fetched.Enabled)
}

// =============================================================================
// API Key Update Tests
// =============================================================================

func TestAPIKey_Update_ConfigSource(t *testing.T) {
	ctx := context.Background()

	// Find a config-sourced key to attempt an update
	resp, err := adminClient.APIKeys.List(ctx, &apikeys.ListFilter{
		Source: "config",
		Limit:  1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	if len(resp.Keys) == 0 {
		t.Skip("Skipping: no config-sourced API keys available to test update protection")
	}

	configKey := resp.Keys[0]
	newName := "Should Not Update"
	_, err = adminClient.APIKeys.Update(ctx, configKey.ID, &apikeys.UpdateRequest{
		Name: &newName,
	})
	require.Error(t, err, "Should not be able to update a config-sourced key")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "Updating config-sourced key should return 403")
}

func TestAPIKey_Update_APISource(t *testing.T) {
	ctx := context.Background()

	// Create a key to update
	pubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	created, err := adminClient.APIKeys.Create(ctx, &apikeys.CreateRequest{
		ID:              "e2e-update-test-key",
		Name:            "E2E Update Test Original",
		PublicKey:       hex.EncodeToString(pubKey),
		Role:            "strategy",

	})
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Skip("Skipping: API key management is readonly")
		}
		require.NoError(t, err)
	}
	require.NotNil(t, created)

	t.Cleanup(func() {
		delErr := adminClient.APIKeys.Delete(context.Background(), created.ID)
		if delErr != nil {
			t.Logf("Warning: failed to clean up API key %s: %v", created.ID, delErr)
		}
	})

	// Update the name
	newName := "E2E Update Test Modified"
	updated, err := adminClient.APIKeys.Update(ctx, created.ID, &apikeys.UpdateRequest{
		Name: &newName,
	})
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "E2E Update Test Modified", updated.Name)

	// Verify via Get
	fetched, err := adminClient.APIKeys.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "E2E Update Test Modified", fetched.Name)
}

// =============================================================================
// API Key Delete Tests
// =============================================================================

func TestAPIKey_Delete_ConfigSource(t *testing.T) {
	ctx := context.Background()

	// Find a config-sourced key to attempt deletion
	resp, err := adminClient.APIKeys.List(ctx, &apikeys.ListFilter{
		Source: "config",
		Limit:  1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	if len(resp.Keys) == 0 {
		t.Skip("Skipping: no config-sourced API keys available to test delete protection")
	}

	configKey := resp.Keys[0]
	err = adminClient.APIKeys.Delete(ctx, configKey.ID)
	require.Error(t, err, "Should not be able to delete a config-sourced key")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "Deleting config-sourced key should return 403")
}

func TestAPIKey_Delete_APISource(t *testing.T) {
	ctx := context.Background()

	// Create a key to delete
	pubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	created, err := adminClient.APIKeys.Create(ctx, &apikeys.CreateRequest{
		ID:              "e2e-delete-test-key",
		Name:            "E2E Delete Test",
		PublicKey:       hex.EncodeToString(pubKey),
		Role:            "strategy",

	})
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Skip("Skipping: API key management is readonly")
		}
		require.NoError(t, err)
	}
	require.NotNil(t, created)

	// Delete the key
	err = adminClient.APIKeys.Delete(ctx, created.ID)
	require.NoError(t, err, "Should be able to delete an API-sourced key")

	// Verify it's gone
	_, err = adminClient.APIKeys.Get(ctx, created.ID)
	require.Error(t, err, "Deleted key should not be found")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 404, apiErr.StatusCode, "Deleted key should return 404")
}

func TestAPIKey_Delete_NotFound(t *testing.T) {
	ctx := context.Background()

	err := adminClient.APIKeys.Delete(ctx, "nonexistent-key-id-e2e-99999")

	// Depending on readonly mode, we get 403 or 404
	require.Error(t, err, "Deleting non-existent key should return an error")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	// 404 if not readonly, 403 if readonly
	assert.Contains(t, []int{403, 404}, apiErr.StatusCode,
		"Expected 403 (readonly) or 404 (not found), got %d", apiErr.StatusCode)
}

// =============================================================================
// Non-Admin Access Tests
// =============================================================================

func TestAPIKey_NonAdminCannotList(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to list API keys (routes require admin)
	_, err := nonAdminClient.APIKeys.List(ctx, &apikeys.ListFilter{
		Limit: 10,
	})
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

func TestAPIKey_NonAdminCannotGet(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	_, err := nonAdminClient.APIKeys.Get(ctx, adminAPIKeyID)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

func TestAPIKey_NonAdminCannotCreate(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	pubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	_, err = nonAdminClient.APIKeys.Create(ctx, &apikeys.CreateRequest{
		ID:              "e2e-nonadmin-create-attempt",
		Name:            "Should Not Be Created",
		PublicKey:       hex.EncodeToString(pubKey),
		Role:            "strategy",

	})
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

func TestAPIKey_NonAdminCannotDelete(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	err := nonAdminClient.APIKeys.Delete(ctx, adminAPIKeyID)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "Expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}
