package evm

import (
	"sync"
	"time"

	"github.com/grafana/sobek"
)

// pausableTimer tracks pure JS execution time independently of Go-side RPC callback time.
// The timer pauses when control enters a Go callback (RPC helper) and resumes when control
// returns to JS. This ensures the JS timeout budget only counts actual JS execution.
//
// Thread safety: pause/resume are called from the JS goroutine (synchronous callbacks).
// The expiry callback runs in a timer goroutine. The mutex protects shared state.
type pausableTimer struct {
	mu        sync.Mutex
	vm        *sobek.Runtime
	budget    time.Duration // total JS execution time allowed
	elapsed   time.Duration // JS time consumed so far
	startedAt time.Time     // when the current running segment started (zero if paused)
	timer     *time.Timer   // active timer (nil if paused or expired)
	expired   bool          // set once; prevents restart after expiry
}

// newPausableTimer creates and starts a pausable timer that will interrupt the VM
// after the given budget of pure JS execution time.
func newPausableTimer(vm *sobek.Runtime, budget time.Duration) *pausableTimer {
	pt := &pausableTimer{
		vm:     vm,
		budget: budget,
	}
	pt.startedAt = time.Now()
	pt.timer = time.AfterFunc(budget, pt.expire)
	return pt
}

// expire is called by the timer goroutine when the JS budget is exhausted.
func (pt *pausableTimer) expire() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.expired = true
	pt.vm.Interrupt("timeout")
}

// Pause pauses the timer, recording elapsed JS time. Called before entering a Go RPC callback.
// Safe to call multiple times (idempotent when already paused).
func (pt *pausableTimer) Pause() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.expired || pt.startedAt.IsZero() {
		return
	}
	pt.elapsed += time.Since(pt.startedAt)
	pt.startedAt = time.Time{} // mark as paused
	if pt.timer != nil {
		pt.timer.Stop()
		pt.timer = nil
	}
}

// Resume resumes the timer with the remaining JS budget. Called after a Go RPC callback returns.
// Safe to call multiple times (idempotent when already running).
func (pt *pausableTimer) Resume() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.expired || !pt.startedAt.IsZero() {
		return
	}
	remaining := pt.budget - pt.elapsed
	if remaining <= 0 {
		// Budget already exhausted during accounting
		pt.expired = true
		pt.vm.Interrupt("timeout")
		return
	}
	pt.startedAt = time.Now()
	pt.timer = time.AfterFunc(remaining, pt.expire)
}

// Stop stops the timer permanently. Must be called when evaluation completes to prevent
// a stale timer goroutine from interrupting a recycled VM.
func (pt *pausableTimer) Stop() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.expired = true
	if pt.timer != nil {
		pt.timer.Stop()
		pt.timer = nil
	}
}
