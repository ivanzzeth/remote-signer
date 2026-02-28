//go:build e2e
package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestPagination_RequestsCursorBased(t *testing.T) {
	ctx := context.Background()

	// Create multiple sign requests to test pagination
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	// Create at least 5 requests for pagination testing
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("Pagination test message %d", i)
		_, err := signer.PersonalSign(msg)
		require.NoError(t, err)
		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Test pagination with small limit (2 items per page)
	limit := 2

	// Fetch first page
	page1, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		Limit: limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)
	assert.LessOrEqual(t, len(page1.Requests), limit)

	// If there are more items, test cursor-based pagination
	if page1.HasMore {
		assert.NotNil(t, page1.NextCursor, "NextCursor should be set when HasMore is true")
		assert.NotNil(t, page1.NextCursorID, "NextCursorID should be set when HasMore is true")

		// Fetch second page using cursor
		page2, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
			Limit:    limit,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err)
		require.NotNil(t, page2)

		// Ensure page 2 has different items than page 1
		if len(page1.Requests) > 0 && len(page2.Requests) > 0 {
			assert.NotEqual(t, page1.Requests[0].ID, page2.Requests[0].ID,
				"Page 2 should have different items than page 1")
		}

		// If there's a third page, verify continued pagination
		if page2.HasMore && page2.NextCursor != nil {
			page3, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
				Limit:    limit,
				Cursor:   page2.NextCursor,
				CursorID: page2.NextCursorID,
			})
			require.NoError(t, err)
			require.NotNil(t, page3)

			// Ensure page 3 has different items
			if len(page2.Requests) > 0 && len(page3.Requests) > 0 {
				assert.NotEqual(t, page2.Requests[0].ID, page3.Requests[0].ID,
					"Page 3 should have different items than page 2")
			}
		}
	}
}

func TestPagination_RequestsWithStatusFilter(t *testing.T) {
	ctx := context.Background()

	// Test pagination with status filter
	limit := 5
	page1, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		Status: "completed",
		Limit:  limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)

	// All returned requests should have "completed" status
	for _, req := range page1.Requests {
		assert.Equal(t, "completed", req.Status)
	}

	// If there are more pages, verify filter is maintained
	if page1.HasMore && page1.NextCursor != nil {
		page2, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
			Status:   "completed",
			Limit:    limit,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err)

		// All page 2 requests should also be "completed"
		for _, req := range page2.Requests {
			assert.Equal(t, "completed", req.Status)
		}
	}
}

func TestPagination_AuditCursorBased(t *testing.T) {
	ctx := context.Background()

	// Create some sign requests to generate audit records
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("Audit pagination test %d", i)
		_, _ = signer.PersonalSign(msg)
		time.Sleep(10 * time.Millisecond)
	}

	// Test pagination with small limit
	limit := 2

	// Fetch first page
	page1, err := adminClient.Audit.List(ctx, &audit.ListFilter{
		Limit: limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)
	assert.LessOrEqual(t, len(page1.Records), limit)

	// If there are more items, test cursor-based pagination
	if page1.HasMore {
		assert.NotNil(t, page1.NextCursor, "NextCursor should be set when HasMore is true")
		assert.NotNil(t, page1.NextCursorID, "NextCursorID should be set when HasMore is true")

		// Fetch second page using cursor
		page2, err := adminClient.Audit.List(ctx, &audit.ListFilter{
			Limit:    limit,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err)
		require.NotNil(t, page2)

		// Ensure page 2 has different items than page 1
		if len(page1.Records) > 0 && len(page2.Records) > 0 {
			assert.NotEqual(t, page1.Records[0].ID, page2.Records[0].ID,
				"Page 2 should have different audit records than page 1")
		}
	}
}

func TestPagination_AuditWithEventTypeFilter(t *testing.T) {
	ctx := context.Background()

	// Test pagination with event type filter
	limit := 5
	page1, err := adminClient.Audit.List(ctx, &audit.ListFilter{
		EventType: "sign_complete",
		Limit:     limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)

	// All returned records should have the filtered event type
	for _, record := range page1.Records {
		assert.Equal(t, "sign_complete", record.EventType)
	}
}

func TestPagination_TotalCountConsistency(t *testing.T) {
	ctx := context.Background()

	// Get all requests in one large page
	largePage, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		Limit: 100,
	})
	require.NoError(t, err)

	// Get total from small page
	smallPage, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		Limit: 2,
	})
	require.NoError(t, err)

	// Total should be the same regardless of page size
	assert.Equal(t, largePage.Total, smallPage.Total,
		"Total count should be consistent across different page sizes")
}

func TestPagination_EmptyPage(t *testing.T) {
	ctx := context.Background()

	// Test with a filter that returns no results. Use a signer address that no test uses.
	// NOTE: 0x0 is used by JS client e2e; 0x..0002 by config-driven negative test cases.
	page, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		SignerAddress: "0x000000000000000000000000000000000000fF99",
		Limit:         10,
	})
	require.NoError(t, err)
	require.NotNil(t, page)

	// Should have no results but not error
	assert.Empty(t, page.Requests)
	assert.False(t, page.HasMore)
	assert.Nil(t, page.NextCursor)
	assert.Nil(t, page.NextCursorID)
}

func TestPagination_CursorURLEncoding(t *testing.T) {
	ctx := context.Background()

	// Create requests to ensure we have data
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("URL encoding test %d", i)
		_, _ = signer.PersonalSign(msg)
		time.Sleep(10 * time.Millisecond)
	}

	// Get first page
	page1, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		Limit: 1,
	})
	require.NoError(t, err)

	if page1.HasMore && page1.NextCursor != nil {
		// The cursor value typically contains timestamp with ':' characters
		// This tests that URL encoding is working correctly
		cursor := *page1.NextCursor
		t.Logf("Cursor value: %s", cursor)

		// Using the cursor should work (URL encoding is handled by client)
		page2, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
			Limit:    1,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err, "Cursor with special characters should work when URL-encoded")
		require.NotNil(t, page2)

		// Page 2 should have different data
		if len(page1.Requests) > 0 && len(page2.Requests) > 0 {
			assert.NotEqual(t, page1.Requests[0].ID, page2.Requests[0].ID,
				"URL-encoded cursor should fetch different page")
		}
	}
}

// =============================================================================
// Signer Management Tests
// =============================================================================
