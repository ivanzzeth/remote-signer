package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// WalletRepository defines the interface for wallet persistence.
type WalletRepository interface {
	Create(ctx context.Context, wallet *types.Wallet) error
	Get(ctx context.Context, id string) (*types.Wallet, error)
	Update(ctx context.Context, wallet *types.Wallet) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter types.WalletFilter) (*types.WalletListResult, error)

	AddMember(ctx context.Context, member *types.WalletMember) error
	RemoveMember(ctx context.Context, walletID, signerAddress string) error
	ListMembers(ctx context.Context, walletID string) ([]types.WalletMember, error)
	IsMember(ctx context.Context, walletID, signerAddress string) (bool, error)

	// GetWalletsForSigner returns all wallets that contain the given signer.
	GetWalletsForSigner(ctx context.Context, signerAddress string) ([]types.Wallet, error)
	// GetWalletsForSigners returns signer-address to wallets mapping in batch.
	GetWalletsForSigners(ctx context.Context, signerAddresses []string) (map[string][]types.Wallet, error)
}

// GormWalletRepository implements WalletRepository using GORM.
type GormWalletRepository struct {
	db *gorm.DB
}

// NewGormWalletRepository creates a new GORM-based wallet repository.
func NewGormWalletRepository(db *gorm.DB) (*GormWalletRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormWalletRepository{db: db}, nil
}

func (r *GormWalletRepository) Create(ctx context.Context, wallet *types.Wallet) error {
	if wallet == nil {
		return fmt.Errorf("wallet cannot be nil")
	}
	if wallet.ID == "" {
		wallet.ID = uuid.New().String()
	}
	now := time.Now()
	if wallet.CreatedAt.IsZero() {
		wallet.CreatedAt = now
	}
	wallet.UpdatedAt = now
	return r.db.WithContext(ctx).Create(wallet).Error
}

func (r *GormWalletRepository) Get(ctx context.Context, id string) (*types.Wallet, error) {
	var wallet types.Wallet
	err := r.db.WithContext(ctx).First(&wallet, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	return &wallet, nil
}

func (r *GormWalletRepository) Update(ctx context.Context, wallet *types.Wallet) error {
	if wallet == nil {
		return fmt.Errorf("wallet cannot be nil")
	}
	wallet.UpdatedAt = time.Now()
	result := r.db.WithContext(ctx).Model(&types.Wallet{}).
		Where("id = ?", wallet.ID).
		Updates(map[string]interface{}{
			"name":        wallet.Name,
			"description": wallet.Description,
			"updated_at":  wallet.UpdatedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("failed to update wallet: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormWalletRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete all members first (CASCADE)
		if err := tx.Where("wallet_id = ?", id).Delete(&types.WalletMember{}).Error; err != nil {
			return fmt.Errorf("failed to delete wallet members: %w", err)
		}

		// Clean up stale signer_access rows that reference this wallet via wallet_id
		if err := tx.Where("wallet_id = ?", id).Delete(&types.SignerAccess{}).Error; err != nil {
			return fmt.Errorf("failed to clean up signer access for wallet: %w", err)
		}

		// Delete the wallet itself
		result := tx.Delete(&types.Wallet{}, "id = ?", id)
		if result.Error != nil {
			return fmt.Errorf("failed to delete wallet: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return types.ErrNotFound
		}
		return nil
	})
}

func (r *GormWalletRepository) List(ctx context.Context, filter types.WalletFilter) (*types.WalletListResult, error) {
	query := r.db.WithContext(ctx).Model(&types.Wallet{})

	if filter.OwnerID != "" {
		query = query.Where("owner_id = ?", filter.OwnerID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count wallets: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	query = query.Order("created_at DESC")
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	query = query.Limit(limit + 1) // fetch one extra to determine HasMore

	var wallets []types.Wallet
	if err := query.Find(&wallets).Error; err != nil {
		return nil, fmt.Errorf("failed to list wallets: %w", err)
	}

	hasMore := len(wallets) > limit
	if hasMore {
		wallets = wallets[:limit]
	}

	return &types.WalletListResult{
		Wallets: wallets,
		Total:   int(total),
		HasMore: hasMore,
	}, nil
}

func (r *GormWalletRepository) AddMember(ctx context.Context, member *types.WalletMember) error {
	if member == nil {
		return fmt.Errorf("member cannot be nil")
	}
	// Disallow nested wallets: signer address cannot point to another wallet ID.
	var nestedCount int64
	if err := r.db.WithContext(ctx).Model(&types.Wallet{}).Where("id = ?", member.SignerAddress).Count(&nestedCount).Error; err != nil {
		return fmt.Errorf("failed to check nested wallet membership: %w", err)
	}
	if nestedCount > 0 {
		return fmt.Errorf("nested wallets are not allowed")
	}

	if member.AddedAt.IsZero() {
		member.AddedAt = time.Now()
	}
	return r.db.WithContext(ctx).Create(member).Error
}

func (r *GormWalletRepository) RemoveMember(ctx context.Context, walletID, signerAddress string) error {
	result := r.db.WithContext(ctx).
		Where("wallet_id = ? AND signer_address = ?", walletID, signerAddress).
		Delete(&types.WalletMember{})
	if result.Error != nil {
		return fmt.Errorf("failed to remove member: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormWalletRepository) ListMembers(ctx context.Context, walletID string) ([]types.WalletMember, error) {
	var members []types.WalletMember
	err := r.db.WithContext(ctx).
		Where("wallet_id = ?", walletID).
		Order("added_at ASC").
		Find(&members).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	return members, nil
}

func (r *GormWalletRepository) IsMember(ctx context.Context, walletID, signerAddress string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.WalletMember{}).
		Where("wallet_id = ? AND signer_address = ?", walletID, signerAddress).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check membership: %w", err)
	}
	return count > 0, nil
}

func (r *GormWalletRepository) GetWalletsForSigner(ctx context.Context, signerAddress string) ([]types.Wallet, error) {
	var wallets []types.Wallet
	err := r.db.WithContext(ctx).
		Joins("JOIN wallet_members ON wallet_members.wallet_id = wallets.id").
		Where("wallet_members.signer_address = ?", signerAddress).
		Find(&wallets).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get wallets for signer: %w", err)
	}
	return wallets, nil
}

func (r *GormWalletRepository) GetWalletsForSigners(ctx context.Context, signerAddresses []string) (map[string][]types.Wallet, error) {
	result := make(map[string][]types.Wallet)
	if len(signerAddresses) == 0 {
		return result, nil
	}
	type row struct {
		SignerAddress string
		WalletID      string
		Name          string
		Description   string
		OwnerID       string
		CreatedAt     time.Time
		UpdatedAt     time.Time
	}
	rows := make([]row, 0)
	err := r.db.WithContext(ctx).
		Table("wallet_members").
		Select("wallet_members.signer_address, wallets.id as wallet_id, wallets.name, wallets.description, wallets.owner_id, wallets.created_at, wallets.updated_at").
		Joins("JOIN wallets ON wallet_members.wallet_id = wallets.id").
		Where("wallet_members.signer_address IN ?", signerAddresses).
		Order("wallets.created_at DESC").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("failed to batch get wallets for signers: %w", err)
	}
	for _, r := range rows {
		w := types.Wallet{
			ID:          r.WalletID,
			Name:        r.Name,
			Description: r.Description,
			OwnerID:     r.OwnerID,
			CreatedAt:   r.CreatedAt,
			UpdatedAt:   r.UpdatedAt,
		}
		result[r.SignerAddress] = append(result[r.SignerAddress], w)
	}
	return result, nil
}
