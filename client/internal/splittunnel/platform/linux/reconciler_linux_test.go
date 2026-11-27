//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeEventMonitor struct {
	mu       sync.Mutex
	starts   int
	stops    int
	startErr error
	events   chan Event
}

func (f *fakeEventMonitor) Start(context.Context) (<-chan Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.starts++
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.events = make(chan Event, 32)
	return f.events, nil
}

func (f *fakeEventMonitor) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeEventMonitor) send(kind EventKind) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.events == nil {
		return
	}
	f.events <- Event{Kind: kind}
}

func (f *fakeEventMonitor) closeEvents() {
	f.mu.Lock()
	events := f.events
	f.events = nil
	f.mu.Unlock()
	if events != nil {
		close(events)
	}
}

func (f *fakeEventMonitor) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

func (f *fakeEventMonitor) stopCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stops
}

type fakeReapplier struct {
	mu      sync.Mutex
	err     error
	applied chan struct{}
}

func newFakeReapplier() *fakeReapplier {
	return &fakeReapplier{applied: make(chan struct{}, 32)}
}

func (f *fakeReapplier) Reapply(context.Context) error {
	f.mu.Lock()
	err := f.err
	applied := f.applied
	f.mu.Unlock()

	select {
	case applied <- struct{}{}:
	default:
	}
	return err
}

func (f *fakeReapplier) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func waitForCondition(t *testing.T, condition func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", message)
}

func startTestReconciler(t *testing.T, monitor *fakeEventMonitor, reapplier *fakeReapplier) *Reconciler {
	t.Helper()

	reconciler := newReconciler(monitor, reapplier, 20*time.Millisecond, 10*time.Millisecond, 0)
	require.NoError(t, reconciler.Start(context.Background()))
	t.Cleanup(reconciler.Stop)
	return reconciler
}

func TestReconcilerDebouncesEventBursts(t *testing.T) {
	monitor := &fakeEventMonitor{}
	reapplier := newFakeReapplier()
	reconciler := startTestReconciler(t, monitor, reapplier)

	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 1 },
		"the initial reconcile")
	initial := reconciler.Reconciles()

	kinds := []EventKind{EventLink, EventAddress, EventRoute}
	for i := 0; i < 20; i++ {
		monitor.send(kinds[i%len(kinds)])
	}
	waitForCondition(t, func() bool { return reconciler.Reconciles() > initial },
		"the debounced reconcile")

	time.Sleep(80 * time.Millisecond)
	assert.Equal(t, initial+1, reconciler.Reconciles(),
		"a burst must coalesce into one reapply")
}

func TestReconcilerSchedulesSeparateAppliesForSeparatedEvents(t *testing.T) {
	monitor := &fakeEventMonitor{}
	reapplier := newFakeReapplier()
	reconciler := startTestReconciler(t, monitor, reapplier)

	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 1 },
		"the initial reconcile")

	monitor.send(EventLink)
	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 2 },
		"the first event reconcile")
	monitor.send(EventRoute)
	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 3 },
		"the second event reconcile")
}

func TestReconcilerRestartsMonitorAfterStreamEnds(t *testing.T) {
	monitor := &fakeEventMonitor{}
	reapplier := newFakeReapplier()
	reconciler := startTestReconciler(t, monitor, reapplier)

	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 1 },
		"the initial reconcile")

	monitor.closeEvents()
	waitForCondition(t, func() bool { return monitor.startCount() >= 2 },
		"the monitor restart")
	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 2 },
		"the reconcile after restart")

	monitor.send(EventAddress)
	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 3 },
		"an event from the restarted monitor")
}

func TestReconcilerRetriesAfterFailedReapply(t *testing.T) {
	monitor := &fakeEventMonitor{}
	reapplier := newFakeReapplier()
	reapplier.setError(errors.New("reapply failed"))
	reconciler := startTestReconciler(t, monitor, reapplier)

	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 1 },
		"the failed initial reconcile")
	assert.Contains(t, reconciler.LastError(), "reapply failed")

	reapplier.setError(nil)
	monitor.send(EventRoute)
	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 2 },
		"the retry after a failed reapply")
	assert.Empty(t, reconciler.LastError())
}

func TestReconcilerStopIsIdempotentAndRestartable(t *testing.T) {
	monitor := &fakeEventMonitor{}
	reapplier := newFakeReapplier()
	reconciler := newReconciler(monitor, reapplier, 10*time.Millisecond, 10*time.Millisecond, 0)
	require.NoError(t, reconciler.Start(context.Background()))

	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			reconciler.Stop()
		}()
	}
	group.Wait()
	assert.GreaterOrEqual(t, monitor.stopCount(), 1)

	require.NoError(t, reconciler.Start(context.Background()))
	reconciler.Stop()
}

func TestReconcilerRejectsConcurrentStart(t *testing.T) {
	monitor := &fakeEventMonitor{}
	reconciler := newReconciler(monitor, newFakeReapplier(), time.Second, time.Second, 0)
	require.NoError(t, reconciler.Start(context.Background()))
	t.Cleanup(reconciler.Stop)

	err := reconciler.Start(context.Background())
	require.ErrorIs(t, err, ErrReconcilerRunning)
}

func TestReconcilerStartReturnsSubscriptionError(t *testing.T) {
	startErr := errors.New("netlink unavailable")
	monitor := &fakeEventMonitor{startErr: startErr}
	reconciler := newReconciler(monitor, newFakeReapplier(), time.Second, time.Second, 0)

	err := reconciler.Start(context.Background())
	require.ErrorIs(t, err, startErr)
	reconciler.Stop()
}

func TestReconcilerContextCancellationStopsIt(t *testing.T) {
	monitor := &fakeEventMonitor{}
	reapplier := newFakeReapplier()
	reconciler := newReconciler(monitor, reapplier, 10*time.Millisecond, 10*time.Millisecond, 0)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, reconciler.Start(ctx))
	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 1 },
		"the initial reconcile")

	cancel()
	done := make(chan struct{})
	go func() {
		reconciler.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the context was cancelled")
	}
}
