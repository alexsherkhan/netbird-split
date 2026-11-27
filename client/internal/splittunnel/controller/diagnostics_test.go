package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/diagnostics"
)

type counterBackend struct {
	*fakeBackend
	sample diagnostics.CounterSample
	err    error
}

func (b *counterBackend) TrafficCounters(context.Context) (diagnostics.CounterSample, error) {
	if b.err != nil {
		return diagnostics.CounterSample{}, b.err
	}
	return b.sample, nil
}

func TestDiagnosticsAggregatesOwnedCounters(t *testing.T) {
	backend := &counterBackend{
		fakeBackend: &fakeBackend{},
		sample: diagnostics.CounterSample{
			Classes: map[diagnostics.TrafficClass]diagnostics.ClassCounter{
				diagnostics.ClassVPN:    {Packets: 4, Bytes: 400},
				diagnostics.ClassDirect: {Packets: 2, Bytes: 200},
				diagnostics.ClassBlock:  {Packets: 1, Bytes: 100},
			},
			RuleHits: 7,
		},
	}
	controller := New(t.TempDir(), Options{Backend: backend, Runtime: testWiring})

	snapshot, err := controller.Diagnostics(context.Background())
	require.NoError(t, err)

	assert.True(t, snapshot.Traffic.Outgoing.Available)
	assert.Equal(t, uint64(7), snapshot.Traffic.Outgoing.Packets)
	assert.Equal(t, uint64(700), snapshot.Traffic.Outgoing.Bytes)
	assert.Equal(t, uint64(400), snapshot.Traffic.VPN.Bytes)
	assert.Equal(t, uint64(200), snapshot.Traffic.Direct.Bytes)
	assert.Equal(t, uint64(100), snapshot.Traffic.Block.Bytes)
	assert.False(t, snapshot.DNS.Available, "no tracker is attached before a policy is applied")
	assert.False(t, snapshot.Connections.Available)
}

func TestDiagnosticsReportsCounterFailureAsUnavailable(t *testing.T) {
	backend := &counterBackend{
		fakeBackend: &fakeBackend{},
		err:         errors.New("netlink permission denied"),
	}
	controller := New(t.TempDir(), Options{Backend: backend, Runtime: testWiring})

	snapshot, err := controller.Diagnostics(context.Background())
	require.NoError(t, err)

	assert.False(t, snapshot.Traffic.Outgoing.Available)
	assert.Contains(t, snapshot.Traffic.Outgoing.Reason, "netlink permission denied")
	assert.Contains(t, snapshot.UnavailableMetrics, "traffic.outgoing")
}

func TestStatusIncludesDiagnosticsSummary(t *testing.T) {
	backend := &counterBackend{
		fakeBackend: &fakeBackend{},
		sample: diagnostics.CounterSample{
			Classes: map[diagnostics.TrafficClass]diagnostics.ClassCounter{
				diagnostics.ClassVPN: {Packets: 3, Bytes: 30},
			},
			RuleHits: 3,
		},
	}
	controller := New(t.TempDir(), Options{Backend: backend, Runtime: testWiring})

	status, err := controller.Status(context.Background())
	require.NoError(t, err)

	assert.Contains(t, status.Diagnostics, "diagnostics.traffic.vpn")
	assert.Contains(t, status.Diagnostics["diagnostics.traffic.vpn"], "packets=3")
	assert.Equal(t, "0", status.Diagnostics["diagnostics.classification.errors"])
}
