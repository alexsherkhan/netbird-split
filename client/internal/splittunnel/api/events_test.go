package api

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbproto "github.com/netbirdio/netbird/client/proto"
)

func TestEventHubBackpressureDropsOldest(t *testing.T) {
	hub := newEventHub(16, 2)
	sub, replay := hub.subscribe(0, 0)
	require.Empty(t, replay)
	defer hub.unsubscribe(sub)

	for i := 1; i <= 5; i++ {
		hub.publish(Event{Type: "test", Message: fmt.Sprintf("event-%d", i)})
	}

	var deliveries []delivery
	for {
		select {
		case delivered := <-sub.ch:
			deliveries = append(deliveries, delivered)
		default:
			goto drained
		}
	}
drained:
	require.Len(t, deliveries, 2, "the subscriber buffer must stay bounded")
	assert.Equal(t, uint64(4), deliveries[0].event.Sequence)
	assert.Equal(t, uint64(5), deliveries[1].event.Sequence)
	assert.Greater(t, deliveries[0].dropped+deliveries[1].dropped, uint64(0),
		"dropped events must be reported to the subscriber")
}

func TestEventHistoryIsBounded(t *testing.T) {
	hub := newEventHub(2, 4)
	for i := 1; i <= 3; i++ {
		hub.publish(Event{Type: "test", Message: fmt.Sprintf("event-%d", i)})
	}

	events, next := hub.list(0, 10)
	require.Len(t, events, 2)
	assert.Equal(t, uint64(2), events[0].Sequence)
	assert.Equal(t, uint64(3), events[1].Sequence)
	assert.Equal(t, uint64(3), next)
}

func TestEventHistoryListAfterSequence(t *testing.T) {
	hub := newEventHub(10, 4)
	for i := 1; i <= 4; i++ {
		hub.publish(Event{Type: "test", Message: fmt.Sprintf("event-%d", i)})
	}

	events, next := hub.list(2, 1)
	require.Len(t, events, 1)
	assert.Equal(t, uint64(3), events[0].Sequence)
	assert.Equal(t, uint64(3), next)

	events, next = hub.list(4, 10)
	assert.Empty(t, events)
	assert.Equal(t, uint64(4), next)
}

func TestListEventsRedactsDetails(t *testing.T) {
	service := New(&fakeBackend{}, WithEventHistory(8))
	service.Publish(Event{
		Type:     "config_changed",
		Severity: "info",
		Message:  "configuration applied",
		Details:  map[string]string{"revision": "2", "path": "/home/user/.config/netbird"},
	})
	client := startTestServer(t, service, unprivilegedIdentity(), true)

	response, err := client.ListEvents(testContext(t), &nbproto.ListSplitTunnelEventsRequest{ApiVersion: APIVersion})
	require.NoError(t, err)
	require.Len(t, response.Events, 1)
	event := response.Events[0]
	assert.Equal(t, "config_changed", event.Type)
	assert.True(t, event.Redacted)
	assert.Empty(t, event.Details)
	assert.Equal(t, uint64(1), response.NextSequence)
}

func TestListEventsPrivilegedCallerSeesDetails(t *testing.T) {
	service := New(&fakeBackend{}, WithEventHistory(8))
	service.Publish(Event{
		Type:    "config_changed",
		Message: "configuration applied",
		Details: map[string]string{"revision": "2"},
	})
	client := startTestServer(t, service, privilegedIdentity(), true)

	response, err := client.ListEvents(testContext(t), &nbproto.ListSplitTunnelEventsRequest{ApiVersion: APIVersion})
	require.NoError(t, err)
	require.Len(t, response.Events, 1)
	assert.Equal(t, map[string]string{"revision": "2"}, response.Events[0].Details)
	assert.False(t, response.Events[0].Redacted)
}

func TestSubscribeEventsReplaysAndStreams(t *testing.T) {
	service := New(&fakeBackend{}, WithEventHistory(8), WithSubscriberBuffer(8))
	service.Publish(Event{Type: "retained", Message: "first"})
	client := startTestServer(t, service, unprivilegedIdentity(), true)

	ctx, cancel := context.WithCancel(testContext(t))
	stream, err := client.SubscribeEvents(ctx, &nbproto.SubscribeSplitTunnelEventsRequest{ApiVersion: APIVersion})
	require.NoError(t, err)

	first, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, "retained", first.Type)
	assert.Equal(t, uint64(1), first.Sequence)

	service.Publish(Event{Type: "live", Message: "second"})
	second, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, "live", second.Type)
	assert.Equal(t, uint64(2), second.Sequence)

	cancel()
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.Canceled, status.Code(err))
}

func TestSubscribeEventsRedactsDetails(t *testing.T) {
	service := New(&fakeBackend{}, WithEventHistory(8), WithSubscriberBuffer(8))
	service.Publish(Event{
		Type:    "config_changed",
		Message: "applied",
		Details: map[string]string{"path": "/home/user/.config/netbird"},
	})
	client := startTestServer(t, service, unprivilegedIdentity(), true)

	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	stream, err := client.SubscribeEvents(ctx, &nbproto.SubscribeSplitTunnelEventsRequest{ApiVersion: APIVersion})
	require.NoError(t, err)

	event, err := stream.Recv()
	require.NoError(t, err)
	assert.True(t, event.Redacted)
	assert.Empty(t, event.Details)
}
