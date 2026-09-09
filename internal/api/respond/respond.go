// Package respond writes the two HTTP response shapes this API uses.
//
// It exists because there were 48 copies of these six lines, one per handler,
// and copies drift. Two ways they had already drifted:
//
//   - Argument order. writeJSON existed as (w, body, code) and (w, code, body),
//     writeError as (w, msg, code) and (w, code, msg). Both compile — one
//     parameter is `any` or `string`, the other `int` — so a call in the wrong
//     order ships an error body inside a 200 and no test has to notice.
//   - Encode failures. 19 copies logged them, 14 discarded them with `_ =`.
//     A response that fails half-way through encoding leaves the client with
//     truncated JSON under a 200 status; if nothing logs it, that is invisible
//     from the server side.
//
// Both behaviours are settled here: one order, and the encode error is always
// logged when a logger is available.
//
// ⚠️ Status is written before the body, which means an encode failure cannot
// change it — by then the header is on the wire. That is inherent to streaming
// JSON straight to the ResponseWriter, not something this package chose; the
// log line is the only signal, which is why it is not optional.
package respond

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

const contentTypeJSON = "application/json"

// JSON writes body as JSON under the given status code.
//
// logger may be nil (some handlers predate having one); the encode error is
// then dropped, which is the old `_ =` behaviour and no worse than before.
func JSON(w http.ResponseWriter, body any, code int, logger *slog.Logger) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil && logger != nil {
		logger.Error("failed to encode response", "error", err, "status", code)
	}
}

// Error writes {"error": msg} under the given status code.
//
// The body shape is fixed on purpose: every one of the 48 copies used
// {"error": ...}, and clients parse it.
func Error(w http.ResponseWriter, msg string, code int, logger *slog.Logger) {
	JSON(w, map[string]string{"error": msg}, code, logger)
}
