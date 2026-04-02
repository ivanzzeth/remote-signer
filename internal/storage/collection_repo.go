package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// CollectionRepository defines the interface for wallet collection persistence.
type CollectionRepository interface {
	Create(ctx context.Context, collection *types.WalletCollection) error
	Get(ctx context.Context, id string) (*types.WalletCollection, error)
	Update(ctx context.Context, collection *types.WalletCollection) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter types.CollectionFilter) (*types.CollectionListResult, error)

	AddMember(ctx context.Context, member *types.CollectionMember) error
	RemoveMember(ctx context.Context, collectionID, walletID string) error
	ListMembers(ctx context.Context, collectionID string) ([]types.CollectionMember, error)
	IsMember(ctx context.Context, collectionID, walletID string) (bool, error)

	// GetCollectionsForWallet returns all collections that contain the given wallet_id.
	GetCollectionsForWallet(ctx context.Context, walletID string) ([]types.WalletCollection, error)

	// IsCollection returns true if the given ID is a wallet_collection ID.
	IsCollection(ctx context.Context, id string) (bool, error)
}

// GormCollectionRepository implements CollectionRepository using GORM.
type GormCollectionRepository struct {
	db *gorm.DB
}

// NewGormCollectionRepository creates a new GORM-based collection repository.
func NewGormCollectionRepository(db *gorm.DB) (*GormCollectionRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormCollectionRepository{db: db}, nil
}

func (r *GormCollectionRepository) Create(ctx context.Context, collection *types.WalletCollection) error {
	if collection == nil {
		return fmt.Errorf("collection cannot be nil")
	}
	if collection.ID == "" {
		collection.ID = uuid.New().String()
	}
	now := time.Now()
	if collection.CreatedAt.IsZero() {
		collection.CreatedAt = now
	}
	collection.UpdatedAt = now
	return r.db.WithContext(ctx).Create(collection).Error
}

func (r *GormCollectionRepository) Get(ctx context.Context, id string) (*types.WalletCollection, error) {
	var collection types.WalletCollection
	err := r.db.WithContext(ctx).First(&collection, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get collection: %w", err)
	}
	return &collection, nil
}

func (r *GormCollectionRepository) Update(ctx context.Context, collection *types.WalletCollection) error {
	if collection == nil {
		return fmt.Errorf("collection cannot be nil")
	}
	collection.UpdatedAt = time.Now()
	result := r.db.WithContext(ctx).Model(&types.WalletCollection{}).
		Where("id = ?", collection.ID).
		Updates(map[string]interface{}{
			"name":        collection.Name,
			"description": collection.Description,
			"updated_at":  collection.UpdatedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("failed to update collection: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormCollectionRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete all members first (CASCADE)
		if err := tx.Where("collection_id = ?", id).Delete(&types.CollectionMember{}).Error; err != nil {
			return fmt.Errorf("failed to delete collection members: %w", err)
		}

		// Clean up stale signer_access rows that reference this collection via wallet_id
		if err := tx.Where("wallet_id = ?", id).Delete(&types.SignerAccess{}).Error; err != nil {
			return fmt.Errorf("failed to clean up signer access for collection: %w", err)
		}

		// Delete the collection itself
		result := tx.Delete(&types.WalletCollection{}, "id = ?", id)
		if result.Error != nil {
			return fmt.Errorf("failed to delete collection: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return types.ErrNotFound
		}
		return nil
	})
}

func (r *GormCollectionRepository) List(ctx context.Context, filter types.CollectionFilter) (*types.CollectionListResult, error) {
	query := r.db.WithContext(ctx).Model(&types.WalletCollection{})

	if filter.OwnerID != "" {
		query = query.Where("owner_id = ?", filter.OwnerID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count collections: %w", err)
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

	var collections []types.WalletCollection
	if err := query.Find(&collections).Error; err != nil {
		return nil, fmt.Errorf("failed to list collections: %w", err)
	}

	hasMore := len(collections) > limit
	if hasMore {
		collections = collections[:limit]
	}

	return &types.CollectionListResult{
		Collections: collections,
		Total:       int(total),
		HasMore:     hasMore,
	}, nil
}

func (r *GormCollectionRepository) AddMember(ctx context.Context, member *types.CollectionMember) error {
	if member == nil {
		return fmt.Errorf("member cannot be nil")
	}

	// Enforce depth limit: wallet_id must not itself be a collection
	var count int64
	if err := r.db.WithContext(ctx).Model(&types.WalletCollection{}).Where("id = ?", member.WalletID).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check nested collection: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("nested collections are not allowed: wallet_id %q is itself a collection", member.WalletID)
	}

	if member.AddedAt.IsZero() {
		member.AddedAt = time.Now()
	}
	return r.db.WithContext(ctx).Create(member).Error
}

func (r *GormCollectionRepository) RemoveMember(ctx context.Context, collectionID, walletID string) error {
	result := r.db.WithContext(ctx).
		Where("collection_id = ? AND wallet_id = ?", collectionID, walletID).
		Delete(&types.CollectionMember{})
	if result.Error != nil {
		return fmt.Errorf("failed to remove member: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormCollectionRepository) ListMembers(ctx context.Context, collectionID string) ([]types.CollectionMember, error) {
	var members []types.CollectionMember
	err := r.db.WithContext(ctx).
		Where("collection_id = ?", collectionID).
		Order("added_at ASC").
		Find(&members).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	return members, nil
}

func (r *GormCollectionRepository) IsMember(ctx context.Context, collectionID, walletID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.CollectionMember{}).
		Where("collection_id = ? AND wallet_id = ?", collectionID, walletID).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check membership: %w", err)
	}
	return count > 0, nil
}

func (r *GormCollectionRepository) GetCollectionsForWallet(ctx context.Context, walletID string) ([]types.WalletCollection, error) {
	var collections []types.WalletCollection
	err := r.db.WithContext(ctx).
		Joins("JOIN collection_members ON collection_members.collection_id = wallet_collections.id").
		Where("collection_members.wallet_id = ?", walletID).
		Find(&collections).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get collections for wallet: %w", err)
	}
	return collections, nil
}

func (r *GormCollectionRepository) IsCollection(ctx context.Context, id string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.WalletCollection{}).Where("id = ?", id).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check collection: %w", err)
	}
	return count > 0, nil
}
