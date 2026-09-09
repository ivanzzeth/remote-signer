// Package ports declares what the use-case layer needs from the outside world:
// repository interfaces, the query shapes they take, and the sentinel errors
// they return.
//
// # Why this package exists
//
// These interfaces used to live in internal/storage, so every package that
// wanted to talk to a repository imported the adapter that implements it.
// internal/core/{auth,registry,rule,service,statemachine} all did — five
// use-case packages depending on a persistence layer. That is the dependency
// rule inverted: the inner layer knew its outer one, and swapping the store
// meant touching the domain.
//
// The interfaces belong to the caller, not the implementation. They are
// declared here, in the layer that uses them; internal/storage implements them
// and re-exports each one as a type alias, so existing call sites keep
// compiling and there is exactly one definition of each.
//
// # What belongs here
//
//   - repository interfaces (RuleRepository, BudgetRepository, …)
//   - the filter/request structs those methods take
//   - sentinel errors callers match on (ErrBudgetExceeded, ErrStateConflict)
//
// ⛔ What does not: anything that knows about GORM, SQL, a driver, a table name
// or a migration. If a type here would change because the database changed, it
// is in the wrong package.
//
// ⚠️ This package must import nothing but internal/core/types and the standard
// library. cmd/archcheck's `layers` check enforces that — see
// cmd/archcheck/layers.go.
package ports
