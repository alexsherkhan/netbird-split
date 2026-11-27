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
	"github.com/vishvananda/netlink"
)

type fakeSubscriber struct {
	linkErr  error
	addrErr  error
	routeErr error

	linkCh  chan<- netlink.LinkUpdate
	addrCh  chan<- netlink.AddrUpdate
	routeCh chan<- netlink.RouteUpdate
}

func (f *fakeSubscriber) SubscribeLink(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
	if f.linkErr != nil {
		return f.linkErr
	}
	f.linkCh = ch
	go closeOnDone(ch, done)
	return nil
}

func (f *fakeSubscriber) SubscribeAddress(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
	if f.addrErr != nil {
		return f.addrErr
	}
	f.addrCh = ch
	go closeOnDone(ch, done)
	return nil
}

func (f *fakeSubscriber) SubscribeRoute(ch chan<- netlink.RouteUpdate, done <-chan struct{}) error {
	if f.routeErr != nil {
		return f.routeErr
	}
	f.routeCh = ch
	go closeOnDone(ch, done)
	return nil
}

func closeOnDone[T any](ch chan<- T, done <-chan struct{}) {
	<-done
	close(ch)
}

func newTestMonitor(sub netlinkSubscriber) *Monitor {
	return &Monitor{subs: sub}
}

func receiveEvent(t *testing.T, events <-chan Event) Event {
	t.Helper()

	select {
	case event, ok := <-events:
		require.True(t, ok, "event channel closed before an event arrived")
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a monitor event")
		return Event{}
	}
}

func TestMonitorRelaysAllEventKindsAndStops(t *testing.T) {
	sub := &fakeSubscriber{}
	monitor := newTestMonitor(sub)
	events, err := monitor.Start(context.Background())
	require.NoError(t, err)

	sub.linkCh <- netlink.LinkUpdate{
		Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}},
	}
	sub.addrCh <- netlink.AddrUpdate{LinkIndex: 3}
	sub.routeCh <- netlink.RouteUpdate{Type: 24}

	got := make(map[EventKind]Event, 3)
	for i := 0; i < 3; i++ {
		event := receiveEvent(t, events)
		got[event.Kind] = event
	}

	require.Contains(t, got, EventLink)
	require.NotNil(t, got[EventLink].Link)
	assert.Equal(t, "eth0", got[EventLink].Link.Link.Attrs().Name)

	require.Contains(t, got, EventAddress)
	require.NotNil(t, got[EventAddress].Address)
	assert.Equal(t, 3, got[EventAddress].Address.LinkIndex)

	require.Contains(t, got, EventRoute)
	require.NotNil(t, got[EventRoute].Route)
	assert.Equal(t, uint16(24), got[EventRoute].Route.Type)

	monitor.Stop()
	_, ok := <-events
	assert.False(t, ok, "the event channel must close after Stop")

	monitor.Stop()
}

func TestMonitorStopsOnContextCancellation(t *testing.T) {
	sub := &fakeSubscriber{}
	monitor := newTestMonitor(sub)
	ctx, cancel := context.WithCancel(context.Background())

	events, err := monitor.Start(ctx)
	require.NoError(t, err)

	cancel()
	select {
	case _, ok := <-events:
		assert.False(t, ok, "cancellation must close the event channel")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cancellation to stop the monitor")
	}

	monitor.Stop()
	monitor.Stop()
}

func TestMonitorStopBeforeStart(t *testing.T) {
	monitor := newTestMonitor(&fakeSubscriber{})
	monitor.Stop()
}

func TestMonitorRejectsConcurrentStartAndRestartsAfterStop(t *testing.T) {
	sub := &fakeSubscriber{}
	monitor := newTestMonitor(sub)

	events, err := monitor.Start(context.Background())
	require.NoError(t, err)
	require.NotNil(t, events)

	_, err = monitor.Start(context.Background())
	require.ErrorIs(t, err, ErrMonitorRunning)

	monitor.Stop()

	events, err = monitor.Start(context.Background())
	require.NoError(t, err)
	require.NotNil(t, events)
	monitor.Stop()
}

func TestMonitorSubscriptionFailures(t *testing.T) {
	tests := []struct {
		name string
		sub  *fakeSubscriber
	}{
		{name: "link", sub: &fakeSubscriber{linkErr: errors.New("link")}},
		{name: "address", sub: &fakeSubscriber{addrErr: errors.New("address")}},
		{name: "route", sub: &fakeSubscriber{routeErr: errors.New("route")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor := newTestMonitor(tt.sub)
			events, err := monitor.Start(context.Background())
			require.Error(t, err)
			assert.Nil(t, events)
			monitor.Stop()
		})
	}
}

func TestMonitorConcurrentStop(t *testing.T) {
	sub := &fakeSubscriber{}
	monitor := newTestMonitor(sub)
	events, err := monitor.Start(context.Background())
	require.NoError(t, err)

	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			monitor.Stop()
		}()
	}
	group.Wait()

	_, ok := <-events
	assert.False(t, ok)
}

func TestRealMonitorStartsAndStops(t *testing.T) {
	monitor := NewMonitor()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, err := monitor.Start(ctx)
	if err != nil {
		t.Skipf("netlink subscriptions are unavailable: %v", err)
	}

	monitor.Stop()
	_, ok := <-events
	assert.False(t, ok)
}
