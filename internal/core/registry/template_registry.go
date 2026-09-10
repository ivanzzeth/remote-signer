package registry

import (
	"context"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/core/ports"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TemplateRegistry coordinates one TemplateSource against the
// TemplateRepository. Its single Sync entry point is called at boot
// (and later via API) to bring the DB in line with the source.
//
// The Registry is stateless across calls: every Sync re-reads the full
// source list. That keeps the protocol simple at the cost of one
// directory walk per refresh, which is fine for the file-count we
// expect (sub-thousand). Remote sources implementing TemplateSource
// are free to cache internally.
type TemplateRegistry struct {
	repo   ports.TemplateRepository
	source TemplateSource
	log    *slog.Logger
}

// NewTemplateRegistry returns a Registry bound to one source. The
// logger is required; pass slog.Default() if the caller has no
// preference. nil repo or source panics at Sync time, not here, so the
// constructor stays trivial.
func NewTemplateRegistry(repo ports.TemplateRepository, source TemplateSource, log *slog.Logger) *TemplateRegistry {
	if log == nil {
		log = slog.Default()
	}
	return &TemplateRegistry{repo: repo, source: source, log: log}
}

// Sync mirrors the source into the repository: upsert what the source lists,
// prune the rows it no longer does. The loop is shared with the other
// catalogue — see syncCatalogue for why.
func (r *TemplateRegistry) Sync(ctx context.Context) (SyncReport, error) {
	return syncCatalogue(ctx, r.repo, r.source, templateIdent, "template", r.log)
}

// templateIdent reports the item's ID and source path, and an empty ID for a nil
// entry — which is how a source yielding nil becomes a reported error rather
// than a panic.
func templateIdent(t *types.RuleTemplate) (string, string) {
	if t == nil {
		return "", ""
	}
	return t.ID, t.SourcePath
}
