// Package handler — forced validation policy for preset apply / template instantiate.
package handler

// errSkipValidationForbidden is returned when a client sends skip_validation:true.
//
// # FORCED VALIDATION — DO NOT REVERT
//
// commit 9ca84b1 introduced optional skip_validation (API) and --skip-validation (CLI).
// That bypass let broken templates/presets reach production without running test_cases.
// Malformed signing rules can approve unintended transactions → real fund loss.
//
// Policy:
//   - preset apply and template instantiate MUST always run test_cases
//   - jsEvaluator nil → reject (503), never silently skip
//   - skip_validation:true → reject (400), never honor
//
// If apply fails validation, fix the template test_cases or operator variables.
// Do NOT re-add a skip path "for convenience" or "to unblock e2e".
const errSkipValidationForbidden = "skip_validation is forbidden: preset apply and template instantiate always run test_cases; fix the template or variables instead of bypassing validation (fund-loss risk)"
