// Package server provides the daemon entrypoint for `remote-signer server start`.
// run_init.go contains helpers extracted from Run() for initialization steps:
// logging, settings, templates, rules, and repository init.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/statemachine"
	"github.com/ivanzzeth/remote-signer/internal/logger"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// repoBundle bundles all repository instances created during startup.
type repoBundle struct {
	requestRepo         storage.RequestRepository
	ruleRepo            storage.RuleRepository
	apiKeyRepo          storage.APIKeyRepository
	auditRepo           storage.AuditRepository
	signerOwnershipRepo storage.SignerOwnershipRepository
	signerRepo          storage.SignerRepository
	signerAccessRepo    storage.SignerAccessRepository
	walletRepo          storage.WalletRepository
	templateRepo        storage.TemplateRepository
	budgetRepo          storage.BudgetRepository
}

// loadEnvFile loads a .env file for development. It is a no-op when the file
// does not exist; errors from a present file are fatal.
func loadEnvFile(path string) {
	if err := godotenv.Load(path); err != nil {
		if _, statErr := os.Stat(path); statErr == nil {
			fmt.Fprintf(os.Stderr, "failed to load .env file: %v\n", err)
		}
	}
}

// initLogging initializes both zerolog (notify module) and slog (application).
func initLogging(level string, pretty bool) *slog.Logger {
	zerologLevel, err := parseZerologLevel(level)
	if err != nil {
		zerologLevel, _ = parseZerologLevel("info")
	}
	logger.Init(zerologLevel, pretty)

	slogLevel, err := parseSlogLevel(level)
	if err != nil {
		slogLevel = slog.LevelInfo
	}
	var slogHandler slog.Handler
	if pretty {
		slogHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel})
	} else {
		slogHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel})
	}
	return slog.New(slogHandler)
}

// initRepositories creates every storage repository from the DB handle.
func initRepositories(db *gorm.DB, log *slog.Logger) (*repoBundle, error) {
	requestRepo, err := storage.NewGormRequestRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create request repository: %w", err)
	}
	ruleRepo, err := storage.NewGormRuleRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule repository: %w", err)
	}
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create apikey repository: %w", err)
	}
	auditRepo, err := storage.NewGormAuditRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit repository: %w", err)
	}
	signerOwnershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer ownership repository: %w", err)
	}
	signerRepo, err := storage.NewGormSignerRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer repository: %w", err)
	}
	signerAccessRepo, err := storage.NewGormSignerAccessRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer access repository: %w", err)
	}
	walletRepo, err := storage.NewGormWalletRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet repository: %w", err)
	}
	templateRepo, err := storage.NewGormTemplateRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create template repository: %w", err)
	}
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create budget repository: %w", err)
	}
	return &repoBundle{
		requestRepo:         requestRepo,
		ruleRepo:            ruleRepo,
		apiKeyRepo:          apiKeyRepo,
		auditRepo:           auditRepo,
		signerOwnershipRepo: signerOwnershipRepo,
		signerRepo:          signerRepo,
		signerAccessRepo:    signerAccessRepo,
		walletRepo:          walletRepo,
		templateRepo:        templateRepo,
		budgetRepo:          budgetRepo,
	}, nil
}

// initTemplates initializes the template initializer, merges templates_dir
// entries, and syncs all templates from config into the DB.
func initTemplates(cfg *config.Config, configPath string, templateRepo storage.TemplateRepository, auditLogger *audit.AuditLogger, log *slog.Logger) (*config.TemplateInitializer, []config.TemplateConfig, error) {
	templateInit, err := config.NewTemplateInitializer(templateRepo, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create template initializer: %w", err)
	}
	templateInit.SetConfigDir(filepath.Dir(configPath))
	templateInit.SetAuditLogger(auditLogger)

	allTemplates := cfg.Templates
	if cfg.TemplatesDir != "" {
		dirTemplates, dirErr := config.LoadTemplatesFromDir(cfg.TemplatesDir, filepath.Dir(configPath), log)
		if dirErr != nil {
			// A missing/broken templates_dir is a config issue, not a
			// data-corruption fatal. Common on a fresh install where the
			// default config.yaml ships with `templates_dir: rules/templates`
			// but the operator hasn't copied the repo's rules/ into their
			// daemon home yet. Warn and continue with whatever inline
			// cfg.Templates already had — daemon boots, operator can fix
			// the path later via config.
			log.Warn("templates_dir unusable — skipping directory load",
				"dir", cfg.TemplatesDir,
				"error", dirErr,
			)
		} else {
			allTemplates = append(allTemplates, dirTemplates...)
			log.Info("templates_dir expanded", "dir", cfg.TemplatesDir, "count", len(dirTemplates))
		}
	}
	if err := templateInit.SyncFromConfig(context.Background(), allTemplates); err != nil {
		return nil, nil, fmt.Errorf("failed to sync templates from config: %w", err)
	}
	return templateInit, allTemplates, nil
}

// initRules initializes the rule initializer, expands template instance rules
// and file-type rules, and validates delegation targets.
func initRules(
	cfg *config.Config,
	configPath string,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	templateRepo storage.TemplateRepository,
	templateInit *config.TemplateInitializer,
	allTemplates []config.TemplateConfig,
	auditLogger *audit.AuditLogger,
	log *slog.Logger,
) (*config.RuleInitializer, []config.RuleConfig, []config.RuleConfig, error) {
	ruleInit, err := config.NewRuleInitializer(ruleRepo, log)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create rule initializer: %w", err)
	}
	ruleInit.SetConfigDir(filepath.Dir(configPath))
	ruleInit.SetAuditLogger(auditLogger)
	ruleInit.SetTemplateRepo(templateRepo)
	ruleInit.SetBudgetRepo(budgetRepo)

	loadedTemplates, err := templateInit.GetLoadedTemplates(allTemplates)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get loaded templates: %w", err)
	}
	expandedRules, err := config.ExpandInstanceRules(cfg.Rules, loadedTemplates)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to expand instance rules: %w", err)
	}
	if err := ruleInit.SyncFromConfig(context.Background(), expandedRules); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sync rules from config: %w", err)
	}
	expandedRulesWithFiles, err := config.ExpandFileRules(expandedRules, filepath.Dir(configPath), log)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to expand file rules for validation: %w", err)
	}
	if err := config.ValidateDelegationTargets(expandedRulesWithFiles); err != nil {
		return nil, nil, nil, fmt.Errorf("delegation target validation failed: %w", err)
	}
	return ruleInit, expandedRules, expandedRulesWithFiles, nil
}

// registerEVMStandardEvaluators registers the standard set of EVM evaluators
// on the rule engine (address list, contract method, value limit, signer
// restriction, sign type restriction, message pattern, internal transfer).
func registerEVMStandardEvaluators(eng *rule.WhitelistRuleEngine) {
	eng.RegisterEvaluator(&evm.AddressListEvaluator{})
	eng.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	eng.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	eng.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.MessagePatternEvaluator{})
}

// initRPCProvider creates the RPC provider, token metadata cache, wires JS
// evaluator and EVM adapter, and returns the decimals querier.
func initRPCProvider(cfg *config.Config, jsEval *evm.JSRuleEvaluator, evmAdapter *evm.EVMAdapter, budgetChecker *rule.BudgetChecker, log *slog.Logger) (*evm.RPCProvider, rule.DecimalsQuerier, error) {
	cacheTTL := cfg.Chains.EVM.RPCGateway.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	rpcProvider, err := evm.NewRPCProvider(cfg.Chains.EVM.RPCGateway.BaseURL, cfg.Chains.EVM.RPCGateway.APIKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create RPC provider: %w", err)
	}
	metadataCache, err := evm.NewTokenMetadataCache(nil, rpcProvider, cacheTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create token metadata cache: %w", err)
	}
	jsEval.SetRPCProvider(rpcProvider, metadataCache)
	if evmAdapter != nil {
		evmAdapter.SetRPCProvider(rpcProvider)
	}
	decimalsQuerier, err := evm.NewDecimalsQuerierAdapter(metadataCache)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create decimals querier: %w", err)
	}
	budgetChecker.SetDecimalsQuerier(decimalsQuerier)
	log.Info("RPC provider configured for JS sandbox and budget decimals auto-query",
		"base_url", cfg.Chains.EVM.RPCGateway.BaseURL, "cache_ttl", cacheTTL)
	return rpcProvider, decimalsQuerier, nil
}

// resolveLegacyPresetsDir resolves the legacy presets directory path relative
// to the config file directory. The result is only used as a placeholder;
// preset access now goes through the DB-backed repository.
func resolveLegacyPresetsDir(cfg *config.Config, configPath string) string {
	if cfg.Presets == nil || cfg.Presets.Dir == "" {
		return ""
	}
	presetsDir := cfg.Presets.Dir
	if !filepath.IsAbs(presetsDir) {
		presetsDir = filepath.Join(filepath.Dir(configPath), presetsDir)
	}
	abs, err := filepath.Abs(presetsDir)
	if err != nil {
		return presetsDir
	}
	return abs
}

// notifyResult bundles the notification service and notifier created at startup.
type notifyResult struct {
	service  *notify.NotifyService
	notifier service.Notifier
}

// initNotificationService starts the notification service (or a no-op notifier
// when notifications are disabled).
func initNotificationService(ctx context.Context, cfg *config.Config, log *slog.Logger) (*notifyResult, error) {
	if !notifyEnabled(&cfg.Notify) {
		notifier, err := service.NewNoopNotifier()
		if err != nil {
			return nil, fmt.Errorf("failed to create noop notifier: %w", err)
		}
		log.Info("Notification service disabled")
		return &notifyResult{notifier: notifier}, nil
	}
	notifyService, err := notify.NewNotifyService(&cfg.Notify)
	if err != nil {
		return nil, fmt.Errorf("failed to create notify service: %w", err)
	}
	notifyService.Start(ctx)
	notifier, err := service.NewNotifyServiceNotifier(service.NotifyServiceNotifierConfig{
		NotifyService: notifyService,
		Channels:      &cfg.NotifyChannel,
		Priority:      1,
		Sound:         "persistent",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create notifier: %w", err)
	}
	log.Info("Notification service started")
	return &notifyResult{service: notifyService, notifier: notifier}, nil
}

// initSignService creates the sign service, rule generator, approval service,
// and optional manual approval guard.
func initSignService(
	chainRegistry *chain.Registry,
	ruleRepo storage.RuleRepository,
	requestRepo storage.RequestRepository,
	ruleEngine rule.RuleEngine,
	stateMachine *statemachine.StateMachine,
	cfg *config.Config,
	notifier service.Notifier,
	notifyService *notify.NotifyService,
	log *slog.Logger,
) (*service.SignService, *service.ManualApprovalGuard, error) {
	ruleGenerator, err := rule.NewDefaultRuleGenerator()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create rule generator: %w", err)
	}
	approvalService, err := service.NewApprovalService(ruleRepo, ruleGenerator, notifier, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create approval service: %w", err)
	}
	signService, err := service.NewSignService(chainRegistry, requestRepo, ruleEngine, stateMachine, approvalService, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sign service: %w", err)
	}
	var approvalGuard *service.ManualApprovalGuard
	if cfg.Security.ApprovalGuard.Enabled {
		approvalGuard, err = service.NewManualApprovalGuard(service.ManualApprovalGuardConfig{
			Window:                cfg.Security.ApprovalGuard.Window,
			RejectionThresholdPct: cfg.Security.ApprovalGuard.RejectionThresholdPct,
			MinSamples:            cfg.Security.ApprovalGuard.MinSamples,
			ResumeAfter:           cfg.Security.ApprovalGuard.ResumeAfter,
			NotifySvc:             notifyService,
			Channel:               &cfg.NotifyChannel,
			Logger:                log,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create approval guard: %w", err)
		}
		signService.SetApprovalGuard(approvalGuard)
		log.Info("approval guard enabled",
			"window", cfg.Security.ApprovalGuard.Window,
			"rejection_threshold_pct", cfg.Security.ApprovalGuard.RejectionThresholdPct,
			"min_samples", cfg.Security.ApprovalGuard.MinSamples,
			"resume_after", cfg.Security.ApprovalGuard.ResumeAfter,
		)
	}
	signService.SetManualApprovalEnabled(cfg.Security.ManualApprovalEnabled)
	if cfg.Security.ManualApprovalEnabled {
		log.Info("manual approval enabled: requests with no whitelist match will go to pending approval")
	} else {
		log.Info("manual approval disabled: requests with no whitelist match will be rejected (403)")
	}
	return signService, approvalGuard, nil
}
