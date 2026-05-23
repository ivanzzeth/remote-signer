package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

// Reset Prometheus metrics between tests by creating a fresh registry.
// promhttp.Handler() reads from DefaultGatherer, so both must be replaced.
func resetRegistry() {
	r := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = r
	prometheus.DefaultGatherer = r
	ruleEvalDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "remote_signer_rule_evaluation_duration_seconds",
			Help:    "Duration of rule evaluation in seconds",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 14),
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
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 14),
		},
		[]string{"chain_type", "sign_type", "outcome"},
	)
	simulationRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "remote_signer_simulation_requests_total",
			Help: "Total number of simulation requests by chain_id and status",
		},
		[]string{"chain_id", "status"},
	)
	simulationDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "remote_signer_simulation_duration_seconds",
			Help:    "Duration of simulation requests in seconds",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 14),
		},
		[]string{"chain_id"},
	)
	simulationBatchSize = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "remote_signer_simulation_batch_size",
			Help:    "Number of transactions per batch simulation",
			Buckets: prometheus.LinearBuckets(1, 1, 20),
		},
	)
	prometheus.MustRegister(
		ruleEvalDuration, ruleEvalTotal, signRequestDuration,
		simulationRequestsTotal, simulationDurationSeconds, simulationBatchSize,
	)
}

func TestRecordRuleEvaluation(t *testing.T) {
	resetRegistry()
	RecordRuleEvaluation("evm_solidity", OutcomeAllow, 50*time.Millisecond)
	// No panic = pass
}

func TestRecordRuleEvaluation_AllOutcomes(t *testing.T) {
	resetRegistry()
	RecordRuleEvaluation("evm_js", OutcomeNoMatch, 10*time.Millisecond)
	RecordRuleEvaluation("evm_js", OutcomeAllow, 20*time.Millisecond)
	RecordRuleEvaluation("evm_js", OutcomeBlock, 30*time.Millisecond)
	RecordRuleEvaluation("evm_js", OutcomeError, 40*time.Millisecond)
}

func TestRecordSignRequestDuration(t *testing.T) {
	resetRegistry()
	RecordSignRequestDuration("evm", "transaction", SignOutcomeOK, 100*time.Millisecond)
	RecordSignRequestDuration("evm", "personal", SignOutcomeRejected, 50*time.Millisecond)
	RecordSignRequestDuration("evm", "typed_eip712", SignOutcomeError, 200*time.Millisecond)
	RecordSignRequestDuration("evm", "transaction", SignOutcomeNotFound, 10*time.Millisecond)
}

func TestRecordSimulationRequest(t *testing.T) {
	resetRegistry()
	RecordSimulationRequest("137", SimStatusSuccess, 500*time.Millisecond)
	RecordSimulationRequest("137", SimStatusError, 1*time.Second)
	RecordSimulationRequest("1", SimStatusRevert, 300*time.Millisecond)
}

func TestRecordSimulationBatchSize(t *testing.T) {
	resetRegistry()
	RecordSimulationBatchSize(5)
	RecordSimulationBatchSize(1)
	RecordSimulationBatchSize(20)
}

func TestHandler(t *testing.T) {
	h := Handler()
	assert.NotNil(t, h)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "# HELP")
}

func TestHandler_WithRecordedMetrics(t *testing.T) {
	resetRegistry()
	RecordRuleEvaluation("test_type", OutcomeAllow, 5*time.Millisecond)
	RecordSignRequestDuration("test", "tx", SignOutcomeOK, 10*time.Millisecond)

	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "remote_signer_rule_evaluation_")
	assert.Contains(t, body, "remote_signer_sign_request_duration_")
}
