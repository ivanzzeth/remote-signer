package types

import (
	"encoding/json"
	"strings"
	"time"
)

// SignerOwnershipStatus represents the status of signer ownership.
type SignerOwnershipStatus string

const (
	SignerOwnershipActive          SignerOwnershipStatus = "active"
	SignerOwnershipPendingApproval SignerOwnershipStatus = "pending_approval"
)

// SignerOwnership tracks which API key owns a signer address.
// Signers live in-memory (ethsig Registry), so this table provides
// persistent ownership metadata keyed by address.
type SignerOwnership struct {
	SignerAddress string                `json:"signer_address" gorm:"primaryKey;type:varchar(42)"`
	OwnerID       string                `json:"owner_id" gorm:"type:varchar(64);not null;index"`
	SignerType    SignerType            `json:"signer_type" gorm:"type:varchar(20);not null;default:'keystore'"`
	Status        SignerOwnershipStatus `json:"status" gorm:"type:varchar(20);not null;default:'active'"`
	DisplayName   string                `json:"display_name" gorm:"type:varchar(256);not null;default:''"`
	TagsJSON      string                `json:"-" gorm:"column:tags;type:text"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

// TableName specifies the table name for GORM.
func (SignerOwnership) TableName() string {
	return "signer_ownership"
}

// Tags returns parsed tag labels from the stored JSON column.
func (o *SignerOwnership) Tags() []string {
	return ParseSignerTagsJSON(o.TagsJSON)
}

// FormatSignerTagsJSON encodes tag labels for persistent storage (JSON array).
func FormatSignerTagsJSON(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ParseSignerTagsJSON decodes the tags column; invalid JSON yields nil.
func ParseSignerTagsJSON(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(s), &tags); err != nil {
		return nil
	}
	return tags
}

// SignerLabelPatch is a partial update for human-readable signer labels (owner-only via API).
// A nil field means "leave unchanged". For PATCH, at least one field must be non-nil.
type SignerLabelPatch struct {
	DisplayName *string   `json:"display_name"`
	Tags        *[]string `json:"tags"`
}

// SignerAccess grants an API key access to a signer that it does not own.
type SignerAccess struct {
	ID            string    `json:"id" gorm:"primaryKey;type:varchar(128)"`
	SignerAddress string    `json:"signer_address" gorm:"type:varchar(42);not null;uniqueIndex:idx_signer_access_addr_key"`
	APIKeyID      string    `json:"api_key_id" gorm:"type:varchar(64);not null;uniqueIndex:idx_signer_access_addr_key"`
	GrantedBy     string    `json:"granted_by" gorm:"type:varchar(64);not null"`
	WalletID      string    `json:"wallet_id,omitempty" gorm:"type:varchar(255);index"`
	CreatedAt     time.Time `json:"created_at"`
}

// TableName specifies the table name for GORM.
func (SignerAccess) TableName() string {
	return "signer_access"
}
