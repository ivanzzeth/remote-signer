package main

// Clean Architecture layers for this repository.
//
// The rule is the dependency rule: an inner layer must not know about an outer
// one. Everything here is stated as "who may this layer import", so a violation
// reads as an arrow pointing the wrong way rather than as a lint code.
//
// ⚠️ Layers are matched by longest prefix, so "internal/core/types" wins over
// "internal/core". A package that matches nothing is unclassified and is only
// reported by -unclassified, never failed on: a new package should not break
// the build before anyone has decided where it belongs.
//
// ⛔ Do not widen a layer's allowlist to make a violation disappear. The
// baseline file exists for that — it records the violation as debt with a
// reason, and the ratchet makes sure the count only goes down.

type layer struct {
	// Name is what shows up in messages.
	Name string
	// Prefixes are import-path suffixes after the module path,
	// e.g. "internal/core/types".
	Prefixes []string
	// MayImport lists the layer names this layer is allowed to depend on.
	// A layer may always import itself.
	MayImport []string
	// Why documents the constraint for whoever hits it.
	Why string
}

// Ordered from innermost to outermost.
var layers = []layer{
	{
		Name:      "domain",
		Prefixes:  []string{"internal/core/types", "internal/ruleconfig", "internal/homepath", "internal/version", "internal/secure", "internal/validate", "internal/logger", "internal/metrics", "internal/bootstrap"},
		MayImport: []string{},
		Why:       "Entities and pure helpers. Depends on nothing of ours: everything else may depend on it, so an import here is a cycle waiting to happen.",
	},
	{
		Name:      "usecase",
		Prefixes:  []string{"internal/core"},
		MayImport: []string{"domain"},
		Why:       "Use cases orchestrate entities through interfaces they declare. Importing an adapter (a chain, a store, a notifier) is the dependency rule inverted — it is what makes a second chain a 30-file edit.",
	},
	{
		Name:      "adapter",
		Prefixes:  []string{"internal/storage", "internal/chain", "internal/audit", "internal/notify", "internal/settings", "internal/simulation", "internal/blocklist", "internal/preset"},
		MayImport: []string{"domain", "usecase"},
		Why:       "Implementations of what the use-case layer declares: databases, chains, transports. They may know the domain; the domain must not know them.",
	},
	{
		Name:      "delivery",
		Prefixes:  []string{"internal/api", "internal/web"},
		MayImport: []string{"domain", "usecase", "adapter"},
		Why:       "HTTP/UI edge. May reach inwards; nothing inner may import it.",
	},
	{
		Name:      "composition",
		Prefixes:  []string{"internal/cli", "internal/config"},
		MayImport: []string{"domain", "usecase", "adapter", "delivery"},
		Why:       "The composition root: it is allowed to know everyone precisely because no one is allowed to know it. ⚠️ internal/config is here because it is one today, not because a package named config should be — half of it is `put this YAML into the database`, which is why nobody dares touch it.",
	},
}
