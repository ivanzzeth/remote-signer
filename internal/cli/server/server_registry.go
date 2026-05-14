package server

import (
	"context"
	"fmt"
	"log/slog"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/registry"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// syncRegistries runs the v0.3 file-based Template + Preset Registry
// sync at startup. It is non-fatal on a missing root (fresh installs
// have no rules/ tree yet) but returns errors from parse/Upsert failures
// so a broken YAML doesn't go silent.
//
// Template root resolution mirrors the legacy templates_dir handling:
// relative paths anchor against the config file's directory so an
// operator-installed config.yaml that references "rules/templates"
// keeps working. Preset root follows the same rule against cfg.Presets.Dir.
//
// The legacy TemplateInitializer (above) keeps running in parallel for
// inline cfg.Templates entries. Their rows live under Source=config so
// they don't collide with Registry's Source=file rows; the two prune
// loops are independent.
func syncRegistries(ctx context.Context, db *gorm.DB, cfg *config.Config, configPath string, log *slog.Logger) error {
	tmplReg, presetReg, err := buildRegistries(db, cfg, configPath, log)
	if err != nil {
		return err
	}
	if _, err := runRegistrySync(ctx, tmplReg, "template", log); err != nil {
		return err
	}
	if _, err := runRegistrySync(ctx, presetReg, "preset", log); err != nil {
		return err
	}
	return nil
}

// buildRegistries constructs Template + Preset Registry instances bound
// to the live db handle and the configured source roots. Used both at
// boot (one-shot sync) and by the runtime refresh handler so the
// handler doesn't need to re-resolve paths or re-wire repositories on
// every POST /api/v1/registry/refresh.
func buildRegistries(db *gorm.DB, cfg *config.Config, configPath string, log *slog.Logger) (*registry.TemplateRegistry, *registry.PresetRegistry, error) {
	tmplRoot := absDirRelativeToConfig(cfg.TemplatesDir, configPath)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	if err != nil {
		return nil, nil, fmt.Errorf("template repo: %w", err)
	}
	tmplReg := registry.NewTemplateRegistry(tmplRepo, registry.NewFileTemplateSource(tmplRoot), log)

	var presetRoot string
	if cfg.Presets != nil && cfg.Presets.Dir != "" {
		presetRoot = absDirRelativeToConfig(cfg.Presets.Dir, configPath)
	}
	presetRepo, err := storage.NewGormPresetRepository(db)
	if err != nil {
		return nil, nil, fmt.Errorf("preset repo: %w", err)
	}
	presetReg := registry.NewPresetRegistry(presetRepo, registry.NewFilePresetSource(presetRoot), log)
	return tmplReg, presetReg, nil
}

// runRegistrySync is the small adapter that lets Sync return work for
// either kind through the same code path. The kind label is just for
// log + error wording — the algorithm is identical.
func runRegistrySync(ctx context.Context, r interface {
	Sync(ctx context.Context) (registry.SyncReport, error)
}, kind string, log *slog.Logger) (registry.SyncReport, error) {
	rep, err := r.Sync(ctx)
	if err != nil {
		return rep, fmt.Errorf("%s registry sync: %w", kind, err)
	}
	for _, e := range rep.Errors {
		log.Error(kind+" parse error", "id", e.ID, "path", e.Path, "err", e.Err)
	}
	return rep, nil
}
