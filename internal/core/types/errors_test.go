package types

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TypedError.Error()
// ---------------------------------------------------------------------------

func TestTypedError_Error_WithCause(t *testing.T) {
	cause := errors.New("db connection failed")
	te := &TypedError{
		Code:    ErrorCodeInternalError,
		Message: "could not fetch record",
		Cause:   cause,
	}
	expected := fmt.Sprintf("%s: %s: %v", ErrorCodeInternalError, "could not fetch record", cause)
	assert.Equal(t, expected, te.Error())
}

func TestTypedError_Error_WithoutCause(t *testing.T) {
	te := &TypedError{
		Code:    ErrorCodeUnauthorized,
		Message: "invalid token",
		Cause:   nil,
	}
	expected := fmt.Sprintf("%s: %s", ErrorCodeUnauthorized, "invalid token")
	assert.Equal(t, expected, te.Error())
}

// ---------------------------------------------------------------------------
// TypedError.Unwrap()
// ---------------------------------------------------------------------------

func TestTypedError_Unwrap_ReturnsCause(t *testing.T) {
	cause := errors.New("root cause")
	te := &TypedError{Cause: cause}
	assert.Equal(t, cause, te.Unwrap())
}

func TestTypedError_Unwrap_NilCause(t *testing.T) {
	te := &TypedError{Cause: nil}
	assert.Nil(t, te.Unwrap())
}

// ---------------------------------------------------------------------------
// NewTypedError()
// ---------------------------------------------------------------------------

func TestNewTypedError(t *testing.T) {
	cause := errors.New("timeout")
	te := NewTypedError(ErrorCodeTimeout, "request timed out", cause)

	require.NotNil(t, te)
	assert.Equal(t, ErrorCodeTimeout, te.Code)
	assert.Equal(t, "request timed out", te.Message)
	assert.Equal(t, cause, te.Cause)
}

func TestNewTypedError_NilCause(t *testing.T) {
	te := NewTypedError(ErrorCodeForbidden, "access denied", nil)

	require.NotNil(t, te)
	assert.Equal(t, ErrorCodeForbidden, te.Code)
	assert.Equal(t, "access denied", te.Message)
	assert.Nil(t, te.Cause)
}

// ---------------------------------------------------------------------------
// TypedError satisfies the error interface and supports errors.Is via Unwrap
// ---------------------------------------------------------------------------

func TestTypedError_ErrorsIs_ViaUnwrap(t *testing.T) {
	te := NewTypedError(ErrorCodeSignerNotFound, "signer missing", ErrSignerNotFound)
	assert.True(t, errors.Is(te, ErrSignerNotFound))
	assert.False(t, errors.Is(te, ErrNotFound))
}

// ---------------------------------------------------------------------------
// IsNotFound
// ---------------------------------------------------------------------------

func TestIsNotFound_DirectMatch(t *testing.T) {
	assert.True(t, IsNotFound(ErrNotFound))
}

func TestIsNotFound_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrNotFound)
	assert.True(t, IsNotFound(wrapped))
}

func TestIsNotFound_DifferentError(t *testing.T) {
	assert.False(t, IsNotFound(ErrUnauthorized))
}

func TestIsNotFound_NilError(t *testing.T) {
	assert.False(t, IsNotFound(nil))
}

// ---------------------------------------------------------------------------
// IsUnauthorized
// ---------------------------------------------------------------------------

func TestIsUnauthorized_DirectMatch(t *testing.T) {
	assert.True(t, IsUnauthorized(ErrUnauthorized))
}

func TestIsUnauthorized_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrUnauthorized)
	assert.True(t, IsUnauthorized(wrapped))
}

func TestIsUnauthorized_DifferentError(t *testing.T) {
	assert.False(t, IsUnauthorized(ErrForbidden))
}

func TestIsUnauthorized_NilError(t *testing.T) {
	assert.False(t, IsUnauthorized(nil))
}

// ---------------------------------------------------------------------------
// IsForbidden
// ---------------------------------------------------------------------------

func TestIsForbidden_DirectMatch(t *testing.T) {
	assert.True(t, IsForbidden(ErrForbidden))
}

func TestIsForbidden_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrForbidden)
	assert.True(t, IsForbidden(wrapped))
}

func TestIsForbidden_DifferentError(t *testing.T) {
	assert.False(t, IsForbidden(ErrNotFound))
}

func TestIsForbidden_NilError(t *testing.T) {
	assert.False(t, IsForbidden(nil))
}

// ---------------------------------------------------------------------------
// IsRateLimited
// ---------------------------------------------------------------------------

func TestIsRateLimited_DirectMatch(t *testing.T) {
	assert.True(t, IsRateLimited(ErrRateLimited))
}

func TestIsRateLimited_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrRateLimited)
	assert.True(t, IsRateLimited(wrapped))
}

func TestIsRateLimited_DifferentError(t *testing.T) {
	assert.False(t, IsRateLimited(ErrInternalError))
}

func TestIsRateLimited_NilError(t *testing.T) {
	assert.False(t, IsRateLimited(nil))
}

// ---------------------------------------------------------------------------
// IsSignerNotFound
// ---------------------------------------------------------------------------

func TestIsSignerNotFound_DirectMatch(t *testing.T) {
	assert.True(t, IsSignerNotFound(ErrSignerNotFound))
}

func TestIsSignerNotFound_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrSignerNotFound)
	assert.True(t, IsSignerNotFound(wrapped))
}

func TestIsSignerNotFound_DifferentError(t *testing.T) {
	assert.False(t, IsSignerNotFound(ErrNotFound))
}

func TestIsSignerNotFound_NilError(t *testing.T) {
	assert.False(t, IsSignerNotFound(nil))
}

// ---------------------------------------------------------------------------
// IsPendingApproval
// ---------------------------------------------------------------------------

func TestIsPendingApproval_DirectMatch(t *testing.T) {
	assert.True(t, IsPendingApproval(ErrPendingApproval))
}

func TestIsPendingApproval_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrPendingApproval)
	assert.True(t, IsPendingApproval(wrapped))
}

func TestIsPendingApproval_DifferentError(t *testing.T) {
	assert.False(t, IsPendingApproval(ErrForbidden))
}

func TestIsPendingApproval_NilError(t *testing.T) {
	assert.False(t, IsPendingApproval(nil))
}
