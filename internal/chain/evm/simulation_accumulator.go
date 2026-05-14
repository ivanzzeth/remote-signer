package evm

import (
	"context"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
)

// batchKey groups pending requests by chain and signer.
type batchKey struct {
	chainID       string
	signerAddress string
}

// pendingSimRequest is a single sign request waiting for batch simulation.
type pendingSimRequest struct {
	chainID       string
	signerAddress string
	txParams      simulation.TxParams
	gasPayload    []byte // raw payload for gas cost estimation
	responseCh    chan<- simResponse
}

// simResponse carries the per-request result back from the accumulator.
type simResponse struct {
	outcome *SimulationOutcome
	err     error
}

// pendingBatch holds requests accumulated for one (chainID, signer) group.
type pendingBatch struct {
	requests []*pendingSimRequest
	timer    *time.Timer
	fireCh   chan struct{} // closed when timer fires
}

// TODO: The accumulator uses an in-memory channel as the pending request queue.
// On process restart, pending requests are lost (fail-safe: agent receives timeout error
// and retries). If higher durability is needed, consider upgrading to a persistent
// message queue (e.g. Redis Streams, NATS JetStream) while preserving the same
// enqueueAndWait / fireBatch interface.

// SetBatchConfig configures the batch accumulator window and max size.
// Must be called before StartAccumulator. window=0 disables accumulation.
func (r *SimulationBudgetRule) SetBatchConfig(window time.Duration, maxSize int) {
	r.batchWindow = window
	r.batchMaxSize = maxSize
	if r.batchMaxSize <= 0 {
		r.batchMaxSize = 20
	}
}

// StartAccumulator starts the background goroutine that collects and batches
// sign requests for simulation. No-op if batchWindow <= 0.
func (r *SimulationBudgetRule) StartAccumulator() {
	if r.batchWindow <= 0 {
		return
	}
	r.pendingCh = make(chan *pendingSimRequest, r.batchMaxSize*4)
	r.stopCh = make(chan struct{})
	r.accWg.Add(1)
	go r.accumulatorLoop()
	r.logger.Info("simulation batch accumulator started",
		"batch_window", r.batchWindow,
		"batch_max_size", r.batchMaxSize,
	)
}

// StopAccumulator gracefully shuts down the accumulator, draining pending requests.
func (r *SimulationBudgetRule) StopAccumulator() {
	if r.stopCh == nil {
		return
	}
	close(r.stopCh)
	r.accWg.Wait()
	r.logger.Info("simulation batch accumulator stopped")
}

// accumulatorLoop is the main goroutine that collects requests and fires batches.
func (r *SimulationBudgetRule) accumulatorLoop() {
	defer r.accWg.Done()

	batches := make(map[batchKey]*pendingBatch)
	// timerCh receives the batchKey when a timer fires.
	timerCh := make(chan batchKey, 64)

	for {
		select {
		case req, ok := <-r.pendingCh:
			if !ok {
				// Channel closed during shutdown — drain remaining batches
				for key, batch := range batches {
					batch.timer.Stop()
					r.fireBatch(batch)
					delete(batches, key)
				}
				return
			}

			key := batchKey{req.chainID, req.signerAddress}
			b, exists := batches[key]
			if !exists {
				fireCh := make(chan struct{})
				timer := time.AfterFunc(r.batchWindow, func() {
					close(fireCh)
					select {
					case timerCh <- key:
					default:
					}
				})
				b = &pendingBatch{timer: timer, fireCh: fireCh}
				batches[key] = b
			}
			b.requests = append(b.requests, req)

			// Check if batch is full
			if len(b.requests) >= r.batchMaxSize {
				b.timer.Stop()
				r.fireBatch(b)
				delete(batches, key)
			}

		case key := <-timerCh:
			b, exists := batches[key]
			if !exists {
				continue // already fired by size trigger
			}
			r.fireBatch(b)
			delete(batches, key)

		case <-r.stopCh:
			// Graceful shutdown: fire all pending batches
			for key, batch := range batches {
				batch.timer.Stop()
				r.fireBatch(batch)
				delete(batches, key)
			}
			return
		}
	}
}

// fireBatch simulates a batch of accumulated requests and distributes results.
func (r *SimulationBudgetRule) fireBatch(batch *pendingBatch) {
	if len(batch.requests) == 0 {
		return
	}

	first := batch.requests[0]
	chainID := first.chainID
	signerAddress := first.signerAddress

	// Build TxParams for batch simulation
	txParams := make([]simulation.TxParams, len(batch.requests))
	for i, req := range batch.requests {
		txParams[i] = req.txParams
	}

	// Use a background context with timeout (requests may have different deadlines)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Simulate entire batch
	batchReq := &simulation.BatchSimulationRequest{
		ChainID:      chainID,
		From:         signerAddress,
		Transactions: txParams,
	}

	batchResult, err := r.simulator.SimulateBatch(ctx, batchReq)
	if err != nil {
		r.logger.Error("batch accumulator simulation failed",
			"error", err,
			"chain_id", chainID,
			"signer", signerAddress,
			"batch_size", len(batch.requests),
		)
		// Return no_match to all — fall through to manual approval
		noMatch := &SimulationOutcome{Decision: "no_match"}
		for _, req := range batch.requests {
			req.responseCh <- simResponse{outcome: noMatch}
		}
		return
	}

	// Check if any tx reverted — deny entire batch
	for i, result := range batchResult.Results {
		if !result.Success {
			r.logger.Warn("batch accumulator tx reverted",
				"index", i,
				"chain_id", chainID,
				"signer", signerAddress,
				"revert_reason", result.RevertReason,
				"batch_size", len(batch.requests),
			)
			for j, req := range batch.requests {
				var reason string
				if j == i {
					reason = "transaction simulation reverted: " + result.RevertReason
				} else {
					reason = "batch rejected: another transaction in the batch reverted"
				}
				req.responseCh <- simResponse{
					outcome: &SimulationOutcome{
						Decision:   "deny",
						Reason:     reason,
						Simulation: &batchResult.Results[j],
					},
				}
			}
			return
		}
	}

	// Budget check against NET balance changes (same as EvaluateBatch)
	if err := r.checkBudgetFromBalanceChanges(ctx, chainID, signerAddress, batchResult.NetBalanceChanges); err != nil {
		r.logger.Warn("budget check failed in batch accumulator",
			"chain_id", chainID,
			"signer", signerAddress,
			"error", err,
			"batch_size", len(batch.requests),
		)
		for i, req := range batch.requests {
			req.responseCh <- simResponse{
				outcome: &SimulationOutcome{
					Decision:   "deny",
					Reason:     "simulation budget exceeded: " + err.Error(),
					Simulation: &batchResult.Results[i],
				},
			}
		}
		return
	}

	// Check approval events + dangerous state changes
	managedSigners := r.getManagedSigners(ctx)
	for i, result := range batchResult.Results {
		if simulation.DetectApproval(ctx, result.Events, managedSigners, chainID, r.allowanceQuerier) {
			r.logger.Info("approval detected in batch accumulator, deferring all to manual approval",
				"chain_id", chainID, "signer", signerAddress, "tx_index", i,
			)
			for j, req := range batch.requests {
				req.responseCh <- simResponse{
					outcome: &SimulationOutcome{Decision: "no_match", Simulation: &batchResult.Results[j]},
				}
			}
			return
		}
		if reason := simulation.DetectDangerousStateChanges(result.RawLogs, managedSigners); reason != "" {
			r.logger.Info("dangerous state change in batch accumulator, deferring all to manual approval",
				"chain_id", chainID, "signer", signerAddress, "tx_index", i, "reason", reason,
			)
			for j, req := range batch.requests {
				req.responseCh <- simResponse{
					outcome: &SimulationOutcome{Decision: "no_match", Simulation: &batchResult.Results[j]},
				}
			}
			return
		}
	}

	// All checks passed — allow all
	for i, req := range batch.requests {
		req.responseCh <- simResponse{
			outcome: &SimulationOutcome{Decision: "allow", Simulation: &batchResult.Results[i]},
		}
	}

	r.logger.Info("batch accumulator fired",
		"chain_id", chainID,
		"signer", signerAddress,
		"batch_size", len(batch.requests),
		"decision", "allow",
	)
}

// enqueueAndWait sends a request to the accumulator and blocks until the result is ready.
func (r *SimulationBudgetRule) enqueueAndWait(
	ctx context.Context,
	req *types.SignRequest,
	txParams simulation.TxParams,
	rawPayload []byte,
) (*SimulationOutcome, error) {
	respCh := make(chan simResponse, 1)
	pending := &pendingSimRequest{
		chainID:       req.ChainID,
		signerAddress: req.SignerAddress,
		txParams:      txParams,
		gasPayload:    rawPayload,
		responseCh:    respCh,
	}

	select {
	case r.pendingCh <- pending:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case resp := <-respCh:
		return resp.outcome, resp.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// accumulatorActive returns true if the batch accumulator is running.
func (r *SimulationBudgetRule) accumulatorActive() bool {
	return r.batchWindow > 0 && r.pendingCh != nil
}

