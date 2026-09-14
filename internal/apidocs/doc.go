// Package apidocs carries the generated OpenAPI document and nothing else.
//
// # Why the spec is generated from annotations and not from the router
//
// It would be easy to walk a live *api.Router and print its patterns, and it
// would be wrong. NewRouter takes five dependencies that come from the
// composition root and want a database (internal/cli/server/run_router.go), and
// setupRoutes has conditional registrations — so what such a walk produces is
// *one deployment*, not the API. e2e/test_server.go leaves 14 RouterConfig
// fields nil and never registers rpc-proxy, broadcast, batch-sign, ACL,
// registry-refresh or request-simulation at all; a spec built that way would be
// missing them and would look complete. The annotations are static, so the
// document describes the code rather than a wiring.
//
// ⚠️ That also means the document cannot prove it matches the routes. That job
// belongs to gate ⑭ (scripts/check-openapi.sh), which compares the operations
// here against the route table cmd/archcheck extracts from the registration call
// sites — the same AST extraction the route-auth gates use.
//
// # Regenerating
//
//	make openapi     # rewrites openapi.json in place
//
// ⛔ openapi.json is committed on purpose, and §4.2 of the proposal is the
// reason: `go build` does not run code generators, and the //go:embed below
// needs the file at build time. A fresh clone that had to run swag first would
// not compile.
package apidocs

import _ "embed"

//	@title						Remote Signer API
//	@version					1.0
//	@description				Policy-driven signing daemon: the API a client uses to ask for a signature and an operator uses to decide what may be signed.
//	@description
//	@description				⚠️ Authentication is an Ed25519 signature over the request, not a bearer token — see the Ed25519Signature scheme below for what the headers actually carry. OpenAPI has no vocabulary for "signature over method + path + body + timestamp", so a generated client CANNOT authenticate on the strength of this document alone; the signing step stays in the hand-written transport (pkg/client/transport).
//
//	@securityDefinitions.apikey	Ed25519Signature
//	@in							header
//	@name						X-API-Key-ID
//	@description				⚠️ An approximation: four headers are required, not one. X-API-Key-ID names the key; X-Timestamp, X-Nonce and X-Signature carry an Ed25519 signature over the canonical request (internal/api/middleware/auth.go). A client that sends only X-API-Key-ID is rejected with 401.
//
// Spec is the generated OpenAPI 3.1 document. Handed out as bytes rather than a
// parsed structure: every consumer so far writes it somewhere, and parsing it
// here would mean this package chooses a schema library for them.
//
//go:embed openapi.json
var Spec []byte
