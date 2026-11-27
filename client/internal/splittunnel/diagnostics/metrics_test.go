package diagnostics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregateTrafficSumsClassesAndKeepsEgressOnly(t *testing.T) {
	sample := CounterSample{
		Classes: map[TrafficClass]ClassCounter{
			ClassVPN:    {Packets: 10, Bytes: 1000},
			ClassDirect: {Packets: 5, Bytes: 500},
			ClassBlock:  {Packets: 2, Bytes: 200},
			ClassExit:   {Packets: 1, Bytes: 100},
		},
		RuleHits: 18,
	}

	traffic := AggregateTraffic(sample)

	assert.True(t, traffic.Outgoing.Available)
	assert.Equal(t, uint64(18), traffic.Outgoing.Packets, "outgoing packets must sum every class")
	assert.Equal(t, uint64(1800), traffic.Outgoing.Bytes, "outgoing bytes must sum every class")
	assert.True(t, traffic.VPN.Available)
	assert.Equal(t, uint64(10), traffic.VPN.Packets)
	assert.Equal(t, uint64(1000), traffic.VPN.Bytes)
	assert.Equal(t, uint64(5), traffic.Direct.Packets)
	assert.Equal(t, uint64(2), traffic.Block.Packets)
	assert.Equal(t, uint64(1), traffic.Exit.Packets)
	assert.True(t, traffic.RuleHits.Available)
	assert.Equal(t, uint64(18), traffic.RuleHits.Packets)

	assert.False(t, traffic.Incoming.Available)
	assert.NotEmpty(t, traffic.Incoming.Reason)
}

func TestAggregateTrafficUnavailableIsNotZero(t *testing.T) {
	traffic := UnavailableTraffic("no owned counters")
	for name, count := range map[string]Count{
		"incoming":  traffic.Incoming,
		"outgoing":  traffic.Outgoing,
		"vpn":       traffic.VPN,
		"direct":    traffic.Direct,
		"block":     traffic.Block,
		"exit":      traffic.Exit,
		"rule hits": traffic.RuleHits,
	} {
		assert.False(t, count.Available, "%s metric must be unavailable", name)
		assert.Zero(t, count.Bytes, "%s unavailable metric must not carry a value", name)
	}
}

type failingCounters struct {
	err error
}

func (f failingCounters) TrafficCounters(context.Context) (CounterSample, error) {
	return CounterSample{}, f.err
}

func TestCollectReportsCounterFailureAsUnavailable(t *testing.T) {
	snapshot := Collect(context.Background(), Sources{
		Counters: failingCounters{err: errors.New("netlink denied")},
		Now:      func() time.Time { return time.Unix(10, 0) },
	})

	assert.False(t, snapshot.Traffic.Outgoing.Available)
	assert.Contains(t, snapshot.Traffic.Outgoing.Reason, "netlink denied")
	assert.Contains(t, snapshot.UnavailableMetrics, "traffic.outgoing")
	assert.False(t, snapshot.Connections.Available, "connections are not implemented")
	assert.False(t, snapshot.DNS.Available)
	assert.False(t, snapshot.Apply.Available)
	assert.False(t, snapshot.Gateway.Available)
	assert.False(t, snapshot.KillSwitch.Available)
}

func TestCollectUsesEverySource(t *testing.T) {
	snapshot := Collect(context.Background(), Sources{
		Counters: counterSourceFunc(func(context.Context) (CounterSample, error) {
			return CounterSample{
				Classes:  map[TrafficClass]ClassCounter{ClassVPN: {Packets: 3, Bytes: 30}},
				RuleHits: 3,
			}, nil
		}),
		DNS:                  func() DNSState { return DNSState{Available: true, CacheSize: 7} },
		ClassificationErrors: func() uint64 { return 2 },
		Apply: func() ApplyState {
			return ApplyState{Available: true, Count: 1, LastDuration: 5 * time.Millisecond}
		},
		Gateway: func() GatewayState {
			return GatewayState{Available: true, BackendState: "ready", PolicyApplied: true}
		},
		KillSwitch: func() KillSwitchState {
			return KillSwitchState{Available: true, Mode: "selective", Armed: true, Events: 1}
		},
		Now: func() time.Time { return time.Unix(20, 0) },
	})

	assert.True(t, snapshot.Traffic.Outgoing.Available)
	assert.Equal(t, uint64(30), snapshot.Traffic.Outgoing.Bytes)
	assert.Equal(t, 7, snapshot.DNS.CacheSize)
	assert.Equal(t, uint64(2), snapshot.Classification.Errors)
	assert.Equal(t, 5*time.Millisecond, snapshot.Apply.LastDuration)
	assert.Equal(t, "ready", snapshot.Gateway.BackendState)
	assert.True(t, snapshot.KillSwitch.Armed)
	assert.Equal(t, time.Unix(20, 0).UTC(), snapshot.GeneratedAt)
}

type counterSourceFunc func(context.Context) (CounterSample, error)

func (f counterSourceFunc) TrafficCounters(ctx context.Context) (CounterSample, error) {
	return f(ctx)
}

func TestRecorderApplyLatencyAndOutcome(t *testing.T) {
	now := time.Unix(30, 0)
	recorder := NewRecorder(func() time.Time { return now })

	assert.False(t, recorder.ApplyState().Available)

	recorder.RecordApply(4*time.Millisecond, nil)
	state := recorder.ApplyState()
	require.True(t, state.Available)
	assert.Equal(t, uint64(1), state.Count)
	assert.Equal(t, 4*time.Millisecond, state.LastDuration)
	assert.Empty(t, state.LastError)

	recorder.RecordApply(9*time.Millisecond, errors.New("backend rejected the policy"))
	state = recorder.ApplyState()
	assert.Equal(t, uint64(2), state.Count)
	assert.Equal(t, 9*time.Millisecond, state.LastDuration)
	assert.Contains(t, state.LastError, "backend rejected the policy")
}

func TestRecorderKillSwitchCountsTransitionsOnly(t *testing.T) {
	now := time.Unix(40, 0)
	recorder := NewRecorder(func() time.Time { return now })

	recorder.RecordKillSwitch("armed")
	recorder.RecordKillSwitch("armed")
	recorder.RecordKillSwitch("disarmed")
	recorder.RecordKillSwitch("armed")

	state := recorder.KillSwitchState("selective", true)
	assert.True(t, state.Available)
	assert.Equal(t, uint64(3), state.Events, "repeated observations are not new events")
	assert.Equal(t, "armed", state.LastEvent)
	assert.Equal(t, now.UTC(), state.LastEventAt)
}

func TestRecorderClassificationErrorsIncrement(t *testing.T) {
	recorder := NewRecorder(nil)
	assert.Equal(t, uint64(0), recorder.ClassificationErrors())
	recorder.RecordClassificationError()
	recorder.RecordClassificationError()
	assert.Equal(t, uint64(2), recorder.ClassificationErrors())
}
