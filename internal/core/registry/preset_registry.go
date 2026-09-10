package registry

import (
	"context"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/core/ports"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// PresetRegistry is the preset counterpart to TemplateRegistry. The
// shape is intentionally identical — same Sync semantics, same
// content-hash skip — so operators see consistent boot logs for the
// two catalogues and a future cross-source orchestrator can drive
// both via one loop.
type PresetRegistry struct {
	repo   ports.PresetRepository
	source PresetSource
	log    *slog.Logger
}

func NewPresetRegistry(repo ports.PresetRepository, source PresetSource, log *slog.Logger) *PresetRegistry {
	if log == nil {
		log = slog.Default()
	}
	return &PresetRegistry{repo: repo, source: source, log: log}
}

// Sync mirrors the source into the repository: upsert what the source lists,
// prune the rows it no longer does. The loop is shared with the other
// catalogue — see syncCatalogue for why.
func (r *PresetRegistry) Sync(ctx context.Context) (SyncReport, error) {
	return syncCatalogue(ctx, r.repo, r.source, presetIdent, "preset", r.log)
}

// presetIdent reports the item's ID and source path, and an empty ID for a nil
// entry — which is how a source yielding nil becomes a reported error rather
// than a panic.
func presetIdent(p *types.RulePreset) (string, string) {
	if p == nil {
		return "", ""
	}
	return p.ID, p.SourcePath
}
