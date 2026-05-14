// Package server provides the daemon entrypoint for `remote-signer server start`.
// run_setup.go contains helpers extracted from Run() for the signer,
// blocklist, simulation, auth, IP whitelist, and security alerts setup steps.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/blocklist"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/logger"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// initEVMSigners initializes the EVM signer registry, providers, signer
// manager, signer ownership sync, and EVM adapter. Returns the signer
// manager and the EVM adapter.
func initEVMSigners(cfg *config.Config, repos *repoBundle, auditLogger *audit.AuditLogger, log *slog.Logger) (evm.SignerManager, *evm.EVMAdapter, error) {
	evmRegistry := evm.NewEmptySignerRegistry()

	hasStdinKeystores := false
	for _, ks := range cfg.Chains.EVM.Signers.Keystores {
		if ks.Enabled && ks.PasswordStdin {
			hasStdinKeystores = true
			break
		}
	}
	if !hasStdinKeystores {
		for _, hw := range cfg.Chains.EVM.Signers.HDWallets {
			if hw.Enabled && hw.PasswordStdin {
				hasStdinKeystores = true
				break
			}
		}
	}

	pwProvider, err := evm.NewCompositePasswordProvider(hasStdinKeystores)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create password provider: %w", err)
	}

	if err := os.MkdirAll(cfg.Chains.EVM.KeystoreDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed to create keystore directory %s: %w", cfg.Chains.EVM.KeystoreDir, err)
	}
	if err := os.MkdirAll(cfg.Chains.EVM.HDWalletDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed to create HD wallet directory %s: %w", cfg.Chains.EVM.HDWalletDir, err)
	}

	pkProvider, err := evm.NewPrivateKeyProvider(evmRegistry, cfg.Chains.EVM.Signers.PrivateKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create private key provider: %w", err)
	}
	evmRegistry.RegisterProvider(pkProvider)

	ksProvider, err := evm.NewKeystoreProvider(evmRegistry, cfg.Chains.EVM.Signers.Keystores, cfg.Chains.EVM.KeystoreDir, pwProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create keystore provider: %w", err)
	}
	evmRegistry.RegisterProvider(ksProvider)

	hdProvider, err := evm.NewHDWalletProvider(evmRegistry, cfg.Chains.EVM.Signers.HDWallets, cfg.Chains.EVM.HDWalletDir, pwProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HD wallet provider: %w", err)
	}
	evmRegistry.RegisterProvider(hdProvider)

	signerMgrImpl, err := evm.NewSignerManager(evmRegistry)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create EVM signer manager: %w", err)
	}
	if cfg.Security.AutoLockTimeout > 0 {
		signerMgrImpl.SetAutoLockTimeout(cfg.Security.AutoLockTimeout)
	}

	if err := signerMgrImpl.DiscoverLockedSigners(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("failed to discover locked signers: %w", err)
	}

	if err := config.SyncSignerOwnership(context.Background(), signerMgrImpl, repos.signerOwnershipRepo, repos.apiKeyRepo, log); err != nil {
		return nil, nil, fmt.Errorf("failed to sync signer ownership: %w", err)
	}

	if cfg.Chains.EVM.MaterialCheck.Enabled {
		checker, checkerErr := service.NewSignerMaterialChecker(
			signerMgrImpl,
			repos.signerRepo,
			cfg.Chains.EVM.KeystoreDir,
			cfg.Chains.EVM.HDWalletDir,
			cfg.Chains.EVM.MaterialCheck.Interval,
			log,
		)
		if checkerErr != nil {
			return nil, nil, fmt.Errorf("failed to create signer material checker: %w", checkerErr)
		}
		if cfg.Chains.EVM.MaterialCheck.StartupCheck {
			if runErr := checker.RunOnce(context.Background()); runErr != nil {
				return nil, nil, fmt.Errorf("startup signer material check failed: %w", runErr)
			}
		}
		checkerCtx, checkerCancel := context.WithCancel(context.Background())
		defer checkerCancel()
		go checker.Start(checkerCtx)
	}

	if evmRegistry.SignerCount() == 0 && evmRegistry.TotalCount() == 0 {
		log.Warn("No signers configured. Add signers via TUI or API after startup.")
	}

	evmAdapter, err := evm.NewEVMAdapter(evmRegistry)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create EVM adapter: %w", err)
	}

	lockedCount := evmRegistry.TotalCount() - evmRegistry.SignerCount()
	logger.EVM().Info().Int("unlocked", evmRegistry.SignerCount()).Int("locked", lockedCount).Int("total", evmRegistry.TotalCount()).Msg("EVM adapter registered")
	if evmRegistry.SignerCount() > 0 {
		logger.EVM().Warn().Int("unlocked_count", evmRegistry.SignerCount()).Msg("signer state after startup: some signers unlocked; with empty config expect all locked")
	}
	logger.EVM().Info().Msg("EVM signer manager initialized")

	return signerMgrImpl, evmAdapter, nil
}

// initDynamicBlocklist creates and starts the dynamic blocklist syncer
// (OFAC, scam DBs, etc.) and returns the evaluator for registration.
func initDynamicBlocklist(cfg *config.Config, log *slog.Logger) (*blocklist.Evaluator, error) {
	blCfg := blocklist.Config{
		Enabled:      cfg.DynamicBlocklist.Enabled,
		SyncInterval: cfg.DynamicBlocklist.SyncInterval,
		FailMode:     cfg.DynamicBlocklist.FailMode,
		CacheFile:    cfg.DynamicBlocklist.CacheFile,
	}
	for _, src := range cfg.DynamicBlocklist.Sources {
		blCfg.Sources = append(blCfg.Sources, blocklist.SourceConfig{
			Name: src.Name, Type: src.Type, URL: src.URL, JSONPath: src.JSONPath,
		})
	}
	dynBlocklist, err := blocklist.NewDynamicBlocklist(blCfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic blocklist: %w", err)
	}
	syncInterval := 1 * time.Hour
	if blCfg.SyncInterval != "" {
		parsed, err := time.ParseDuration(blCfg.SyncInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid dynamic_blocklist.sync_interval: %w", err)
		}
		syncInterval = parsed
	}
	const minSyncInterval = 1 * time.Minute
	if syncInterval < minSyncInterval {
		return nil, fmt.Errorf("dynamic_blocklist.sync_interval must be >= 1m (got %s)", syncInterval)
	}
	if err := dynBlocklist.Start(context.Background(), syncInterval); err != nil {
		return nil, fmt.Errorf("failed to start dynamic blocklist: %w", err)
	}
	defer dynBlocklist.Stop()
	blEval, err := blocklist.NewEvaluator(dynBlocklist)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic blocklist evaluator: %w", err)
	}
	log.Info("Dynamic blocklist registered", "sources", len(blCfg.Sources), "sync_interval", syncInterval, "fail_mode", blCfg.FailMode)
	return blEval, nil
}

// initAuthAndIPWhitelist sets up the auth verifier, nonce store, and IP whitelist.
// It returns the nonceStore so the caller can defer Close().
func initAuthAndIPWhitelist(cfg *config.Config, apiKeyRepo storage.APIKeyRepository, log *slog.Logger) (*auth.Verifier, *middleware.IPWhitelist, *storage.InMemoryNonceStore, error) {
	nonceStore, err := storage.NewInMemoryNonceStore(time.Minute)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create nonce store: %w", err)
	}
	nonceRequired := true
	if cfg.Security.NonceRequired != nil {
		nonceRequired = *cfg.Security.NonceRequired
	}
	authVerifier, err := auth.NewVerifierWithNonceStore(apiKeyRepo, nonceStore, auth.Config{
		MaxRequestAge: cfg.Security.MaxRequestAge,
		NonceRequired: nonceRequired,
	})
	if err != nil {
		nonceStore.Close()
		return nil, nil, nil, fmt.Errorf("failed to create auth verifier: %w", err)
	}
	var ipWhitelist *middleware.IPWhitelist
	if cfg.Security.IPWhitelist.Enabled {
		ipWhitelist, err = middleware.NewIPWhitelist(cfg.Security.IPWhitelist, log)
		if err != nil {
			nonceStore.Close()
			return nil, nil, nil, fmt.Errorf("failed to create IP whitelist: %w", err)
		}
		log.Info("IP whitelist enabled",
			"allowed_count", len(cfg.Security.IPWhitelist.AllowedIPs),
			"trust_proxy", cfg.Security.IPWhitelist.TrustProxy,
		)
	}
	log.Info("API lockdown settings",
		"rules_api_readonly", cfg.Security.IsRulesAPIReadonly(),
		"signers_api_readonly", cfg.Security.IsSignersAPIReadonly(),
		"api_keys_api_readonly", cfg.Security.IsAPIKeysAPIReadonly(),
	)
	return authVerifier, ipWhitelist, nonceStore, nil
}

// initSecurityAlerts creates the security alert service and wires alert callbacks
// on the audit logger and signer manager. Returns the alert service, or nil if
// notifications are disabled.
func initSecurityAlerts(cfg *config.Config, notifyService *notify.NotifyService, auditLogger *audit.AuditLogger, evmSignerManager evm.SignerManager, ipWhitelist *middleware.IPWhitelist, log *slog.Logger) (*middleware.SecurityAlertService, error) {
	if notifyService == nil {
		return nil, nil
	}
	securityAlertService, err := middleware.NewSecurityAlertService(notifyService, &cfg.NotifyChannel, log, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to create security alert service: %w", err)
	}
	stopAlertCleanup := make(chan struct{})
	securityAlertService.StartCleanupRoutine(5*time.Minute, stopAlertCleanup)
	// Note: caller must close stopAlertCleanup (currently done inline in Run)
	_ = stopAlertCleanup
	if ipWhitelist != nil {
		ipWhitelist.SetAlertService(securityAlertService)
	}
	log.Info("Security alert service enabled (real-time alerts for unauthorized access)")

	if impl, ok := evmSignerManager.(*evm.SignerManagerImpl); ok {
		impl.SetOnAutoLock(func(address string) {
			auditLogger.LogSignerAutoLocked(context.Background(), address)
			securityAlertService.Alert(middleware.AlertSignerAutoLocked, address,
				fmt.Sprintf("[Remote Signer] SIGNER AUTO-LOCKED\n\nAddress: %s\nReason: unlock timeout (%s)\nTime: %s\n\nUnlock again via POST /api/v1/evm/signers/%s/unlock",
					address, cfg.Security.AutoLockTimeout, time.Now().UTC().Format(time.RFC3339), address))
		})
	}
	auditLogger.SetOnLogFailure(func(eventType types.AuditEventType, logErr error) {
		securityAlertService.Alert(middleware.AlertAuditDBFailure, "audit_db",
			fmt.Sprintf("[Remote Signer] AUDIT DB FAILURE\n\nEvent: %s\nError: %s\nTime: %s\n\nAudit records may be lost. Check database connectivity.",
				eventType, logErr.Error(), time.Now().UTC().Format(time.RFC3339)))
	})
	auditLogger.SetOnHighRiskOperation(func(eventType types.AuditEventType, apiKeyID, source, detail string) {
		alertType := auditEventToAlertType(eventType)
		who := apiKeyID
		if who == "" {
			who = "system"
		}
		securityAlertService.Alert(alertType, source,
			fmt.Sprintf("[Remote Signer] ADMIN OPERATION\n\nOperation: %s\nAPI Key: %s\nSource IP: %s\nDetail: %s\nTime: %s\n\nIf you did not initiate this, investigate immediately.",
				eventType, who, source, detail, time.Now().UTC().Format(time.RFC3339)))
	})
	return securityAlertService, nil
}

// initSimulation creates the RPC simulation engine for eth_simulateV1.
func initSimulation(cfg *config.Config, log *slog.Logger) (simulation.Simulator, error) {
	rpcGatewayURL := cfg.Chains.EVM.RPCGateway.BaseURL
	simCfg := simulation.RPCSimulatorConfig{
		RPCGatewayURL: rpcGatewayURL,
		RPCGatewayKey: cfg.Chains.EVM.RPCGateway.APIKey,
		Timeout:       cfg.Chains.EVM.Simulation.Timeout,
	}
	sim, err := simulation.NewRPCSimulator(simCfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC simulation engine: %w", err)
	}
	log.Info("simulation engine initialized (rpc/eth_simulateV1)",
		"gateway", rpcGatewayURL,
		"timeout", cfg.Chains.EVM.Simulation.Timeout,
	)
	return sim, nil
}
