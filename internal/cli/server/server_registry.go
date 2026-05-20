// Package server provides the daemon entrypoint for remote-signer server.
// This file handles v0.3 file-based Template + Preset Registry sync at startup.
package server

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"gorm.io/gorm"

	remotesigner "github.com/ivanzzeth/remote-signer"
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
//
// Source resolution per kind:
//
//  1. cfg.TemplatesDir / cfg.Presets.Dir points at an existing on-disk
//     directory → walk that. Operator's own catalogue wins.
//  2. otherwise fall back to the rules embedded into the binary
//     (`remotesigner.EmbeddedRules`). Fresh installs work without the
//     operator having to copy any files into ~/.remote-signer/, which
//     is the failure mode that kept the agent preset from auto-
//     bootstrapping on a fresh home.
//
// The legacy TemplateInitializer keeps running in parallel for inline
// cfg.Templates entries. Their rows live under Source=config so they
// don't collide with Registry's Source=file rows; the two prune loops
// are independent.
func buildRegistries(db *gorm.DB, cfg *config.Config, configPath string, log *slog.Logger) (*registry.TemplateRegistry, *registry.PresetRegistry, error) {
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	if err != nil {
		return nil, nil, fmt.Errorf("template repo: %w", err)
	}
	tmplSrc := resolveTemplateSource(cfg, configPath, log)
	tmplReg := registry.NewTemplateRegistry(tmplRepo, tmplSrc, log)

	presetRepo, err := storage.NewGormPresetRepository(db)
	if err != nil {
		return nil, nil, fmt.Errorf("preset repo: %w", err)
	}
	presetSrc := resolvePresetSource(cfg, configPath, log)
	presetReg := registry.NewPresetRegistry(presetRepo, presetSrc, log)
	return tmplReg, presetReg, nil
}

// resolveTemplateSource picks between the operator's on-disk
// templates_dir and the binary's embedded catalogue. Logs which one
// it chose so the startup log makes the source visible without the
// operator having to grep for missing files.
func resolveTemplateSource(cfg *config.Config, configPath string, log *slog.Logger) registry.TemplateSource {
	tmplRoot := absDirRelativeToConfig(cfg.TemplatesDir, configPath)
	if tmplRoot != "" {
		if info, err := os.Stat(tmplRoot); err == nil && info.IsDir() {
			log.Info("templates: using on-disk directory", "dir", tmplRoot)
			return registry.NewFileTemplateSource(tmplRoot)
		}
	}
	log.Info("templates: using embedded catalogue baked into the binary")
	sub, err := fs.Sub(remotesigner.EmbeddedRules, "rules/templates")
	if err != nil {
		// Build-time invariant — `rules/templates` is //go:embed'd in
		// embedded.go at module root. If the subtree is missing the
		// binary was built without it; fall back to a no-op source so
		// the daemon still starts (operator can fix at runtime by
		// pointing templates_dir at a real path).
		log.Warn("embedded rules/templates subtree missing — running with no templates", "error", err)
		return registry.NewFileTemplateSource("")
	}
	return registry.NewFSTemplateSource(sub, ".")
}

// resolvePresetSource is the preset counterpart of resolveTemplateSource.
func resolvePresetSource(cfg *config.Config, configPath string, log *slog.Logger) registry.PresetSource {
	var presetRoot string
	if cfg.Presets != nil && cfg.Presets.Dir != "" {
		presetRoot = absDirRelativeToConfig(cfg.Presets.Dir, configPath)
	}
	if presetRoot != "" {
		if info, err := os.Stat(presetRoot); err == nil && info.IsDir() {
			log.Info("presets: using on-disk directory", "dir", presetRoot)
			return registry.NewFilePresetSource(presetRoot)
		}
	}
	log.Info("presets: using embedded catalogue baked into the binary")
	sub, err := fs.Sub(remotesigner.EmbeddedRules, "rules/presets")
	if err != nil {
		log.Warn("embedded rules/presets subtree missing — running with no presets", "error", err)
		return registry.NewFilePresetSource("")
	}
	return registry.NewFSPresetSource(sub, ".")
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
