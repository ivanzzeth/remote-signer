package settings

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// ErrNotFound signals a missing system_settings row. Callers should treat this
// as "use defaults" rather than propagating the error.
var ErrNotFound = errors.New("setting not found")

// Store abstracts the persistence layer for the system_settings table so the
// Manager can be tested against a fake.
type Store interface {
	Get(ctx context.Context, key Group) (*Setting, error)
	Put(ctx context.Context, key Group, valueJSON string, updatedBy string) error
	List(ctx context.Context) ([]*Setting, error)
}

// GormStore is the production implementation backed by GORM.
type GormStore struct {
	db *gorm.DB
}

// NewGormStore returns a store bound to db. The caller is responsible for
// AutoMigrate; storage.NewDB handles that.
func NewGormStore(db *gorm.DB) (*GormStore, error) {
	if db == nil {
		return nil, fmt.Errorf("settings: nil db")
	}
	return &GormStore{db: db}, nil
}

// Get returns the row for key or ErrNotFound when absent.
func (s *GormStore) Get(ctx context.Context, key Group) (*Setting, error) {
	var row Setting
	err := s.db.WithContext(ctx).First(&row, "key = ?", string(key)).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("settings get %s: %w", key, err)
	}
	return &row, nil
}

// Put upserts key with the given JSON blob and audit metadata.
func (s *GormStore) Put(ctx context.Context, key Group, valueJSON string, updatedBy string) error {
	row := Setting{
		Key:       string(key),
		ValueJSON: valueJSON,
		UpdatedAt: time.Now(),
		UpdatedBy: updatedBy,
	}
	// GORM's Save upserts on primary key; explicit to keep behaviour stable
	// across dialects.
	if err := s.db.WithContext(ctx).Save(&row).Error; err != nil {
		return fmt.Errorf("settings put %s: %w", key, err)
	}
	return nil
}

// List returns every settings row. Manager uses this to seed all snapshots in
// one query during the periodic refresh.
func (s *GormStore) List(ctx context.Context) ([]*Setting, error) {
	var rows []*Setting
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("settings list: %w", err)
	}
	return rows, nil
}
