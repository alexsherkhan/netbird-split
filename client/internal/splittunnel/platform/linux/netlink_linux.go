//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vishvananda/netlink"
)

const (
	eventBuffer        = 64
	subscriptionBuffer = 16
)

// ErrMonitorRunning reports a second Start on a monitor that is already
// running.
var ErrMonitorRunning = errors.New("netlink monitor is already running")

// EventKind identifies a netlink monitor event.
type EventKind string

const (
	// EventLink is a link add, delete or change.
	EventLink EventKind = "link"
	// EventAddress is an address add or delete.
	EventAddress EventKind = "address"
	// EventRoute is a route add, delete or change.
	EventRoute EventKind = "route"
)

// Event carries exactly one netlink update selected by Kind.
type Event struct {
	Kind    EventKind
	Link    *netlink.LinkUpdate
	Address *netlink.AddrUpdate
	Route   *netlink.RouteUpdate
}

type netlinkSubscriber interface {
	SubscribeLink(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
	SubscribeAddress(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error
	SubscribeRoute(ch chan<- netlink.RouteUpdate, done <-chan struct{}) error
}

type systemSubscriber struct{}

func (systemSubscriber) SubscribeLink(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
	return netlink.LinkSubscribe(ch, done)
}

func (systemSubscriber) SubscribeAddress(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
	return netlink.AddrSubscribe(ch, done)
}

func (systemSubscriber) SubscribeRoute(ch chan<- netlink.RouteUpdate, done <-chan struct{}) error {
	return netlink.RouteSubscribe(ch, done)
}

// Monitor relays link, address and route updates from netlink. It is inert
// until M04 wires it into route reconciliation.
type Monitor struct {
	mu sync.Mutex

	subs netlinkSubscriber

	started  bool
	cancel   context.CancelFunc
	done     chan struct{}
	finished chan struct{}
	stopOnce *sync.Once
}

// NewMonitor returns a monitor backed by the real netlink subscriptions.
func NewMonitor() *Monitor {
	return &Monitor{subs: systemSubscriber{}}
}

// Start begins all three subscriptions and returns the event channel. The
// channel closes after Stop or after a context cancellation. Start returns
// ErrMonitorRunning when a previous Start has not been stopped.
func (m *Monitor) Start(ctx context.Context) (<-chan Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return nil, ErrMonitorRunning
	}
	subs := m.subs

	subCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	linkCh := make(chan netlink.LinkUpdate, subscriptionBuffer)
	addrCh := make(chan netlink.AddrUpdate, subscriptionBuffer)
	routeCh := make(chan netlink.RouteUpdate, subscriptionBuffer)

	abort := func() {
		cancel()
		close(done)
	}

	if err := subs.SubscribeLink(linkCh, done); err != nil {
		abort()
		close(linkCh)
		return nil, fmt.Errorf("subscribe to link updates: %w", err)
	}
	if err := subs.SubscribeAddress(addrCh, done); err != nil {
		abort()
		close(addrCh)
		drain(linkCh)
		return nil, fmt.Errorf("subscribe to address updates: %w", err)
	}
	if err := subs.SubscribeRoute(routeCh, done); err != nil {
		abort()
		close(routeCh)
		drain(linkCh)
		drain(addrCh)
		return nil, fmt.Errorf("subscribe to route updates: %w", err)
	}

	if err := subCtx.Err(); err != nil {
		abort()
		drain(linkCh)
		drain(addrCh)
		drain(routeCh)
		return nil, err
	}

	events := make(chan Event, eventBuffer)
	finished := make(chan struct{})
	once := &sync.Once{}
	stop := func() {
		once.Do(func() {
			cancel()
			close(done)
		})
	}

	var relayGroup sync.WaitGroup
	relayGroup.Add(3)
	go relayLinks(linkCh, events, subCtx, stop, &relayGroup)
	go relayAddresses(addrCh, events, subCtx, stop, &relayGroup)
	go relayRoutes(routeCh, events, subCtx, stop, &relayGroup)

	go func() {
		relayGroup.Wait()
		close(events)
		close(finished)
	}()
	go func() {
		select {
		case <-subCtx.Done():
			stop()
		case <-finished:
		}
	}()

	m.started = true
	m.cancel = cancel
	m.done = done
	m.finished = finished
	m.stopOnce = once
	return events, nil
}

// Stop ends the subscriptions and waits for relay goroutines to exit. It is
// safe to call repeatedly and before Start.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return
	}
	cancel := m.cancel
	done := m.done
	once := m.stopOnce
	finished := m.finished
	m.mu.Unlock()

	once.Do(func() {
		cancel()
		close(done)
	})
	<-finished

	m.mu.Lock()
	if m.finished == finished {
		m.started = false
		m.cancel = nil
		m.done = nil
		m.finished = nil
		m.stopOnce = nil
	}
	m.mu.Unlock()
}

func relayLinks(
	ch <-chan netlink.LinkUpdate,
	out chan<- Event,
	ctx context.Context,
	stop func(),
	group *sync.WaitGroup,
) {
	defer group.Done()
	defer stop()

	for {
		select {
		case update, ok := <-ch:
			if !ok {
				return
			}
			event := Event{Kind: EventLink, Link: &update}
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func relayAddresses(
	ch <-chan netlink.AddrUpdate,
	out chan<- Event,
	ctx context.Context,
	stop func(),
	group *sync.WaitGroup,
) {
	defer group.Done()
	defer stop()

	for {
		select {
		case update, ok := <-ch:
			if !ok {
				return
			}
			event := Event{Kind: EventAddress, Address: &update}
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func relayRoutes(
	ch <-chan netlink.RouteUpdate,
	out chan<- Event,
	ctx context.Context,
	stop func(),
	group *sync.WaitGroup,
) {
	defer group.Done()
	defer stop()

	for {
		select {
		case update, ok := <-ch:
			if !ok {
				return
			}
			event := Event{Kind: EventRoute, Route: &update}
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func drain[T any](ch <-chan T) {
	for range ch {
	}
}
