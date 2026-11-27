//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultReconcileDebounce     = 250 * time.Millisecond
	defaultReconcileRestartDelay = 250 * time.Millisecond
	maxReconcileRestartDelay     = 5 * time.Second
	defaultReconcileResync       = 30 * time.Second
)

// ErrReconcilerRunning reports a second Start on a reconciler that is already
// running.
var ErrReconcilerRunning = errors.New("split tunnel reconciler is already running")

var errReconcilerNoReapplier = errors.New("split tunnel reconciler has no policy reapplier")

// PolicyReapplier re-applies the last successfully applied split tunnel policy.
// Backend implements it.
type PolicyReapplier interface {
	Reapply(ctx context.Context) error
}

// eventMonitor is the netlink monitor surface used by the reconciler.
type eventMonitor interface {
	Start(ctx context.Context) (<-chan Event, error)
	Stop()
}

// Reconciler owns the netlink monitor lifecycle and re-applies the last
// successfully compiled policy after link, address and route changes.
//
// Bursts are debounced into one apply and every apply runs on the reconciler
// goroutine, so a burst cannot start concurrent applies. When the event stream
// ends, the monitor is restarted with a capped backoff and the policy is
// reconciled once the stream is live again. A periodic resync covers changes
// lost across suspend or a monitor restart. Stop is idempotent.
type Reconciler struct {
	monitor   eventMonitor
	reapplier PolicyReapplier

	debounce     time.Duration
	restartDelay time.Duration
	resync       time.Duration

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr string

	reconciles atomic.Uint64
}

// NewReconciler returns a reconciler backed by the real netlink monitor. A nil
// monitor is replaced with NewMonitor.
func NewReconciler(monitor *Monitor, reapplier PolicyReapplier) *Reconciler {
	if monitor == nil {
		monitor = NewMonitor()
	}
	return newReconciler(monitor, reapplier,
		defaultReconcileDebounce, defaultReconcileRestartDelay, defaultReconcileResync)
}

func newReconciler(
	monitor eventMonitor,
	reapplier PolicyReapplier,
	debounce time.Duration,
	restartDelay time.Duration,
	resync time.Duration,
) *Reconciler {
	return &Reconciler{
		monitor:      monitor,
		reapplier:    reapplier,
		debounce:     debounce,
		restartDelay: restartDelay,
		resync:       resync,
	}
}

// Start begins monitoring and returns after the first subscription succeeds. A
// later monitor failure is recovered inside the reconciler goroutine. Start
// returns ErrReconcilerRunning when a previous Start has not been stopped.
func (r *Reconciler) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.reapplier == nil {
		return errReconcilerNoReapplier
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.started {
		return ErrReconcilerRunning
	}

	runCtx, cancel := context.WithCancel(ctx)
	events, err := r.monitor.Start(runCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("start netlink monitor: %w", err)
	}

	done := make(chan struct{})
	r.started = true
	r.cancel = cancel
	r.done = done
	go r.run(runCtx, events, done)
	return nil
}

// Stop ends monitoring and waits for the reconciler goroutine to exit. It is
// safe to call repeatedly and before Start.
func (r *Reconciler) Stop() {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return
	}
	cancel := r.cancel
	done := r.done
	r.mu.Unlock()

	cancel()
	<-done

	r.mu.Lock()
	if r.done == done {
		r.started = false
		r.cancel = nil
		r.done = nil
	}
	r.mu.Unlock()
}

// Reconciles returns the number of completed reapply attempts, including
// attempts that failed.
func (r *Reconciler) Reconciles() uint64 {
	return r.reconciles.Load()
}

// LastError returns the error from the most recent reapply attempt, or an
// empty string when it succeeded.
func (r *Reconciler) LastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

func (r *Reconciler) run(ctx context.Context, events <-chan Event, done chan struct{}) {
	defer close(done)
	defer r.monitor.Stop()

	var resyncC <-chan time.Time
	if r.resync > 0 {
		ticker := time.NewTicker(r.resync)
		defer ticker.Stop()
		resyncC = ticker.C
	}

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	var timerC <-chan time.Time
	defer stopReconcileTimer(timer, &timerC)

	armReconcileTimer(timer, &timerC, r.debounce)
	backoff := r.restartDelay

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				stopReconcileTimer(timer, &timerC)
				events = r.restartMonitor(ctx, &backoff)
				if events == nil {
					return
				}
				armReconcileTimer(timer, &timerC, r.debounce)
				continue
			}
			armReconcileTimer(timer, &timerC, r.debounce)
		case <-timerC:
			timerC = nil
			r.reconcile(ctx)
		case <-resyncC:
			armReconcileTimer(timer, &timerC, r.debounce)
		}
	}
}

// restartMonitor stops the failed monitor and retries until a subscription
// succeeds or ctx is cancelled. The returned channel is nil when ctx ended.
func (r *Reconciler) restartMonitor(ctx context.Context, backoff *time.Duration) <-chan Event {
	for {
		r.monitor.Stop()
		if !waitContext(ctx, *backoff) {
			return nil
		}

		events, err := r.monitor.Start(ctx)
		if err != nil {
			r.recordError(err)
			*backoff = nextRestartDelay(*backoff)
			continue
		}
		*backoff = r.restartDelay
		return events
	}
}

func nextRestartDelay(current time.Duration) time.Duration {
	next := current * 2
	if next <= 0 || next > maxReconcileRestartDelay {
		return maxReconcileRestartDelay
	}
	return next
}

func (r *Reconciler) reconcile(ctx context.Context) {
	err := r.reapplier.Reapply(ctx)
	r.reconciles.Add(1)
	r.recordError(err)
}

func (r *Reconciler) recordError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.lastErr = ""
		return
	}
	r.lastErr = err.Error()
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func armReconcileTimer(timer *time.Timer, active *<-chan time.Time, delay time.Duration) {
	stopReconcileTimer(timer, active)
	timer.Reset(delay)
	*active = timer.C
}

func stopReconcileTimer(timer *time.Timer, active *<-chan time.Time) {
	if *active == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	*active = nil
}
