package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateSignerRequest_Validate(t *testing.T) {
	tests := []struct {
		name        string
		req         CreateSignerRequest
		expectError error
	}{
		{
			name: "valid keystore request",
			req: CreateSignerRequest{
				Type: SignerTypeKeystore,
				Keystore: &CreateKeystoreParams{
					Password: "test-password",
				},
			},
			expectError: nil,
		},
		{
			name: "missing type",
			req: CreateSignerRequest{
				Keystore: &CreateKeystoreParams{
					Password: "test-password",
				},
			},
			expectError: ErrMissingSignerType,
		},
		{
			name: "unsupported type",
			req: CreateSignerRequest{
				Type: SignerType("unknown"),
			},
			expectError: ErrUnsupportedSignerType,
		},
		{
			name: "keystore type without params",
			req: CreateSignerRequest{
				Type: SignerTypeKeystore,
			},
			expectError: ErrMissingKeystoreParams,
		},
		{
			name: "keystore type with empty password",
			req: CreateSignerRequest{
				Type: SignerTypeKeystore,
				Keystore: &CreateKeystoreParams{
					Password: "",
				},
			},
			expectError: ErrEmptyPassword,
		},
		{
			name: "private key type not supported via API",
			req: CreateSignerRequest{
				Type: SignerTypePrivateKey,
			},
			expectError: ErrPrivateKeyCreationNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.expectError == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.expectError)
			}
		})
	}
}

func TestSignerType_Constants(t *testing.T) {
	assert.Equal(t, SignerType("private_key"), SignerTypePrivateKey)
	assert.Equal(t, SignerType("keystore"), SignerTypeKeystore)
}

func TestSignerFilter_Defaults(t *testing.T) {
	filter := SignerFilter{}
	assert.Nil(t, filter.Type)
	assert.Equal(t, 0, filter.Offset)
	assert.Equal(t, 0, filter.Limit)
}

func TestSignerListResult_Fields(t *testing.T) {
	result := SignerListResult{
		Signers: []SignerInfo{
			{Address: "0x123", Type: "keystore", Enabled: true},
		},
		Total:   10,
		HasMore: true,
	}

	assert.Len(t, result.Signers, 1)
	assert.Equal(t, 10, result.Total)
	assert.True(t, result.HasMore)
}
