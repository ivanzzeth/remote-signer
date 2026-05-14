package service

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func setupWalletAccessRepos(t *testing.T) (*SignerAccessService, storage.WalletRepository) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=private"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.APIKey{}, &types.SignerOwnership{}, &types.SignerAccess{}, &types.Wallet{}, &types.WalletMember{}))

	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	walletRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, logger)
	require.NoError(t, err)
	svc.SetWalletRepo(walletRepo)
	return svc, walletRepo
}

func TestCheckAccess_ViaWalletOwnership(t *testing.T) {
	ctx := context.Background()
	svc, walletRepo := setupWalletAccessRepos(t)

	ownerRepo := svc.ownershipRepo
	require.NoError(t, ownerRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0x1111111111111111111111111111111111111111",
		OwnerID:       "other-owner",
		Status:        types.SignerOwnershipActive,
	}))

	w := &types.Wallet{Name: "team-wallet", OwnerID: "wallet-owner"}
	require.NoError(t, walletRepo.Create(ctx, w))
	require.NoError(t, walletRepo.AddMember(ctx, &types.WalletMember{
		WalletID:      w.ID,
		SignerAddress: "0x1111111111111111111111111111111111111111",
	}))

	ok, err := svc.CheckAccess(ctx, "wallet-owner", "0x1111111111111111111111111111111111111111")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCheckAccess_ViaWalletGrant(t *testing.T) {
	ctx := context.Background()
	svc, walletRepo := setupWalletAccessRepos(t)

	ownerRepo := svc.ownershipRepo
	accessRepo := svc.accessRepo
	require.NoError(t, ownerRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0x2222222222222222222222222222222222222222",
		OwnerID:       "other-owner",
		Status:        types.SignerOwnershipActive,
	}))

	w := &types.Wallet{Name: "shared-wallet", OwnerID: "wallet-owner"}
	require.NoError(t, walletRepo.Create(ctx, w))
	require.NoError(t, walletRepo.AddMember(ctx, &types.WalletMember{
		WalletID:      w.ID,
		SignerAddress: "0x2222222222222222222222222222222222222222",
	}))
	require.NoError(t, accessRepo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0x2222222222222222222222222222222222222222",
		APIKeyID:      "grantee",
		GrantedBy:     "wallet-owner",
		WalletID:      w.ID,
	}))

	ok, err := svc.CheckAccess(ctx, "grantee", "0x2222222222222222222222222222222222222222")
	require.NoError(t, err)
	assert.True(t, ok)
}

