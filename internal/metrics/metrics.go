package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ruleEvalDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "remote_signer_rule_evaluation_duration_seconds",
			Help:    "Duration of rule evaluation in seconds",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 14), // 0.01s to ~82s
		},
		[]string{"rule_type"},
	)
	ruleEvalTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "remote_signer_rule_evaluation_total",
			Help: "Total number of rule evaluations by type and outcome",
		},
		[]string{"rule_type", "outcome"},
	)
	signRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "remote_signer_sign_request_duration_seconds",
			Help:    "End-to-end sign request handling duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 14), // 0.01s to ~82s
		},
		[]string{"chain_type", "sign_type", "outcome"},
	)
)

func init() {
	prometheus.MustRegister(ruleEvalDuration, ruleEvalTotal, signRequestDuration)
}

// Outcome for rule evaluation metrics
const (
	OutcomeNoMatch = "no_match" // evaluated, did not match
	OutcomeAllow   = "allow"    // whitelist match (allowed)
	OutcomeBlock   = "block"   // blocklist match (blocked)
	OutcomeError   = "error"   // evaluation error
)

// RecordRuleEvaluation records a rule evaluation for metrics (duration and count by outcome).
// ruleType is the rule type (e.g. evm_solidity_expression); outcome is one of Outcome*.
func RecordRuleEvaluation(ruleType, outcome string, duration time.Duration) {
	ruleEvalDuration.WithLabelValues(ruleType).Observe(duration.Seconds())
	ruleEvalTotal.WithLabelValues(ruleType, outcome).Inc()
}

// Sign request outcome for request-level metrics
const (
	SignOutcomeOK        = "ok"        // 200, signed or pending
	SignOutcomeNotFound  = "not_found" // 404, signer not found
	SignOutcomeRejected  = "rejected"  // 403, manual approval disabled or not authorized
	SignOutcomeError     = "error"     // 500, internal error
)

// RecordSignRequestDuration records the end-to-end duration of a sign request (from handler start to response).
// chainType is e.g. "evm"; signType is e.g. "transaction", "personal"; outcome is one of SignOutcome*.
func RecordSignRequestDuration(chainType, signType, outcome string, duration time.Duration) {
	signRequestDuration.WithLabelValues(chainType, signType, outcome).Observe(duration.Seconds())
}

// Handler returns the HTTP handler for the /metrics endpoint (Prometheus exposition format).
// Bind to the same server port as the API; no authentication required.
func Handler() http.Handler {
	return promhttp.Handler()
}
