package api

import (
	"sort"
	"sync"
	"time"
)

const maxEventHistory = 100_000

type eventHub struct {
	mu          sync.Mutex
	history     []Event
	capacity    int
	buffer      int
	next        uint64
	nextSubID   uint64
	subscribers map[uint64]*subscription
}

type subscription struct {
	id      uint64
	ch      chan delivery
	dropped uint64
}

type delivery struct {
	event   Event
	dropped uint64
}

func newEventHub(history, buffer int) *eventHub {
	if history < 0 {
		history = 0
	}
	if history > maxEventHistory {
		history = maxEventHistory
	}
	if buffer < 1 {
		buffer = 1
	}
	return &eventHub{
		capacity:    history,
		buffer:      buffer,
		subscribers: make(map[uint64]*subscription),
	}
}

func (h *eventHub) publish(event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.next++
	event.Sequence = h.next
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Details = cloneStringMap(event.Details)

	if h.capacity > 0 {
		if len(h.history) >= h.capacity {
			h.history = h.history[1:]
		}
		h.history = append(h.history, event)
	}
	for _, sub := range h.subscribers {
		sub.offer(event)
	}
}

func (s *subscription) offer(event Event) {
	next := delivery{event: event}
	select {
	case s.ch <- next:
		return
	default:
	}

	// The subscriber's queue is full. Drop the oldest queued event and deliver
	// the newest one, so a slow reader observes current state rather than a
	// stale backlog.
	select {
	case dropped := <-s.ch:
		s.dropped += dropped.dropped + 1
	default:
	}
	next.dropped = s.dropped
	s.dropped = 0
	s.ch <- next
}

func (h *eventHub) list(after uint64, limit int) ([]Event, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	events := replayEvents(h.history, after, limit)
	next := after
	if len(events) > 0 {
		next = events[len(events)-1].Sequence
	}
	return events, next
}

func (h *eventHub) subscribe(after uint64, limit int) (*subscription, []Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.nextSubID++
	sub := &subscription{
		id: h.nextSubID,
		ch: make(chan delivery, h.buffer),
	}
	h.subscribers[sub.id] = sub
	return sub, replayEvents(h.history, after, limit)
}

func (h *eventHub) unsubscribe(sub *subscription) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.subscribers[sub.id]; !ok {
		return
	}
	delete(h.subscribers, sub.id)
	close(sub.ch)
}

func replayEvents(history []Event, after uint64, limit int) []Event {
	start := sort.Search(len(history), func(i int) bool {
		return history[i].Sequence > after
	})
	if start == len(history) {
		return nil
	}
	end := len(history)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	events := make([]Event, end-start)
	copy(events, history[start:end])
	return events
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
