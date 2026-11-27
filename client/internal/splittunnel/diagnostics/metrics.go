// Package diagnostics collects local split tunnel observability data.
//
// It aggregates counters the split tunnel backend owns, exposes point-in-time
// snapshots through a typed interface, keeps a bounded structured log, and
// writes a redacted support bundle only after explicit consent. Nothing in this
// package uploads data or contacts a remote endpoint.
package diagnostics

import (
	"context"
	"sync"
	"time"
)

// TrafficClass is one split tunnel traffic class counter.
type TrafficClass string

const (
	// ClassVPN is traffic routed through the overlay.
	ClassVPN TrafficClass = "vpn"
	// ClassDirect is traffic routed through the physical path.
	ClassDirect TrafficClass = "direct"
	// ClassBlock is traffic the policy drops.
	ClassBlock TrafficClass = "block"
	// ClassExit is traffic routed through an exit node.
	ClassExit TrafficClass = "exit"
)

// ClassCounter is the raw packet and byte total for one traffic class.
type ClassCounter struct {
	Packets uint64
	Bytes   uint64
}

// CounterSample is what an owned counter source reports. It is deliberately
// separate from the rendered snapshot so a source never fabricates an
// availability state.
type CounterSample struct {
	Classes  map[TrafficClass]ClassCounter
	RuleHits uint64
}

// CounterSource reads owned counters. A source that cannot read them returns
// an error, and the snapshot reports the metric as unavailable.
type CounterSource interface {
	TrafficCounters(ctx context.Context) (CounterSample, error)
}

// Count is one metric with an explicit availability state. A zero value is not
// a valid measurement; callers must check Available before displaying it.
type Count struct {
	Available bool
	Packets   uint64
	Bytes     uint64
	Reason    string
}

// Unavailable reports a metric that cannot be collected safely.
func Unavailable(reason string) Count {
	return Count{Reason: reason}
}

// Measured reports an available metric.
func Measured(packets, bytes uint64) Count {
	return Count{Available: true, Packets: packets, Bytes: bytes}
}

// Traffic is the aggregated byte and packet view.
type Traffic struct {
	Incoming Count
	Outgoing Count
	VPN      Count
	Direct   Count
	Block    Count
	Exit     Count
	RuleHits Count
}

// AggregateTraffic turns a raw counter sample into an answer that separates
// input from output and keeps each class disjoint. Class totals are added, not
// intersected, because one packet matches at most one classification rule.
func AggregateTraffic(sample CounterSample) Traffic {
	traffic := Traffic{
		Incoming: Unavailable("owned counters observe egress only"),
	}
	var total ClassCounter
	for _, class := range []TrafficClass{ClassVPN, ClassDirect, ClassBlock, ClassExit} {
		counter := sample.Classes[class]
		total.Packets += counter.Packets
		total.Bytes += counter.Bytes
	}
	traffic.Outgoing = Measured(total.Packets, total.Bytes)
	traffic.VPN = classCount(sample, ClassVPN)
	traffic.Direct = classCount(sample, ClassDirect)
	traffic.Block = classCount(sample, ClassBlock)
	traffic.Exit = classCount(sample, ClassExit)
	traffic.RuleHits = Count{Available: true, Packets: sample.RuleHits}
	return traffic
}

func classCount(sample CounterSample, class TrafficClass) Count {
	counter := sample.Classes[class]
	return Measured(counter.Packets, counter.Bytes)
}

// UnavailableTraffic reports every traffic metric as unavailable for one
// reason. It is used when the backend has no owned counter source.
func UnavailableTraffic(reason string) Traffic {
	return Traffic{
		Incoming: Unavailable(reason),
		Outgoing: Unavailable(reason),
		VPN:      Unavailable(reason),
		Direct:   Unavailable(reason),
		Block:    Unavailable(reason),
		Exit:     Unavailable(reason),
		RuleHits: Unavailable(reason),
	}
}

// DNSState reports the bounded domain tracker cache.
type DNSState struct {
	Available bool
	CacheSize int
	Reason    string
}

// ClassificationState reports classification failures.
type ClassificationState struct {
	Errors uint64
}

// ApplyState reports policy apply latency and outcome.
type ApplyState struct {
	Available    bool
	Count        uint64
	LastDuration time.Duration
	LastAt       time.Time
	LastError    string
	Reason       string
}

// GatewayState reports the local gateway and exit node state without exposing
// addresses or peer identities.
type GatewayState struct {
	Available         bool
	BackendState      string
	PolicyApplied     bool
	GatewayConfigured bool
	ExitConfigured    bool
	Protected         bool
	Reason            string
}

// KillSwitchState reports the mode, current arming state and transition log.
type KillSwitchState struct {
	Available   bool
	Mode        string
	Armed       bool
	Events      uint64
	LastEvent   string
	LastEventAt time.Time
	Reason      string
}

// Snapshot is a point-in-time local diagnostics view.
type Snapshot struct {
	GeneratedAt        time.Time
	Traffic            Traffic
	Connections        Count
	DNS                DNSState
	Classification     ClassificationState
	Apply              ApplyState
	Gateway            GatewayState
	KillSwitch         KillSwitchState
	UnavailableMetrics []string
}

// Provider is the typed local interface the daemon exposes to in-process
// callers. It intentionally does not cross the gRPC boundary.
type Provider interface {
	Diagnostics(ctx context.Context) (Snapshot, error)
}

// Sources supplies the live inputs for one snapshot. A nil function leaves the
// corresponding metric unavailable rather than guessing a value.
type Sources struct {
	Counters             CounterSource
	DNS                  func() DNSState
	ClassificationErrors func() uint64
	Apply                func() ApplyState
	Gateway              func() GatewayState
	KillSwitch           func() KillSwitchState
	Connections          func() Count
	Now                  func() time.Time
}

// Collect renders a snapshot from the supplied sources. Counter read failures
// become an unavailable metric, never a zero measurement.
func Collect(ctx context.Context, sources Sources) Snapshot {
	now := sources.Now
	if now == nil {
		now = time.Now
	}
	snapshot := Snapshot{
		GeneratedAt: now().UTC(),
		Connections: Unavailable("active connection counting is not implemented"),
	}
	if sources.Counters == nil {
		snapshot.Traffic = UnavailableTraffic("no owned counter source is available")
	} else {
		sample, err := sources.Counters.TrafficCounters(ctx)
		if err != nil {
			snapshot.Traffic = UnavailableTraffic("read owned counters: " + err.Error())
		} else {
			snapshot.Traffic = AggregateTraffic(sample)
		}
	}
	if sources.DNS == nil {
		snapshot.DNS = DNSState{Reason: "DNS observation is not attached"}
	} else {
		snapshot.DNS = sources.DNS()
	}
	if sources.ClassificationErrors != nil {
		snapshot.Classification.Errors = sources.ClassificationErrors()
	}
	if sources.Apply == nil {
		snapshot.Apply = ApplyState{Reason: "apply latency is not recorded"}
	} else {
		snapshot.Apply = sources.Apply()
	}
	if sources.Gateway == nil {
		snapshot.Gateway = GatewayState{Reason: "gateway state is not reported"}
	} else {
		snapshot.Gateway = sources.Gateway()
	}
	if sources.KillSwitch == nil {
		snapshot.KillSwitch = KillSwitchState{Reason: "kill switch state is not reported"}
	} else {
		snapshot.KillSwitch = sources.KillSwitch()
	}
	if sources.Connections != nil {
		snapshot.Connections = sources.Connections()
	}
	snapshot.UnavailableMetrics = unavailableMetrics(snapshot)
	return snapshot
}

func unavailableMetrics(snapshot Snapshot) []string {
	var names []string
	add := func(name string, count Count) {
		if !count.Available {
			names = append(names, name)
		}
	}
	add("traffic.incoming", snapshot.Traffic.Incoming)
	add("traffic.outgoing", snapshot.Traffic.Outgoing)
	add("traffic.vpn", snapshot.Traffic.VPN)
	add("traffic.direct", snapshot.Traffic.Direct)
	add("traffic.block", snapshot.Traffic.Block)
	add("traffic.exit", snapshot.Traffic.Exit)
	add("traffic.rule_hits", snapshot.Traffic.RuleHits)
	add("connections", snapshot.Connections)
	if !snapshot.DNS.Available {
		names = append(names, "dns.cache_size")
	}
	if !snapshot.Apply.Available {
		names = append(names, "apply.latency")
	}
	if !snapshot.Gateway.Available {
		names = append(names, "gateway.state")
	}
	if !snapshot.KillSwitch.Available {
		names = append(names, "kill_switch.state")
	}
	return names
}

// Recorder owns counters that no kernel object exposes: apply latency,
// classification failures and kill switch transitions. It is safe for
// concurrent use.
type Recorder struct {
	now func() time.Time

	mu sync.Mutex

	applyCount     uint64
	applyLast      time.Duration
	applyLastAt    time.Time
	applyLastError string
	applyRecorded  bool

	classErrors uint64

	ksEvents uint64
	ksLast   string
	ksLastAt time.Time
}

// NewRecorder returns a recorder. A nil clock uses time.Now.
func NewRecorder(now func() time.Time) *Recorder {
	if now == nil {
		now = time.Now
	}
	return &Recorder{now: now}
}

// RecordApply records one policy apply duration and outcome.
func (r *Recorder) RecordApply(duration time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyCount++
	r.applyLast = duration
	r.applyLastAt = r.now().UTC()
	r.applyRecorded = true
	if err != nil {
		r.applyLastError = err.Error()
		return
	}
	r.applyLastError = ""
}

// RecordClassificationError increments the classification failure counter.
func (r *Recorder) RecordClassificationError() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.classErrors++
}

// RecordKillSwitch records a kill switch transition. A repeated event is
// ignored so the count reflects transitions rather than repeated observations.
func (r *Recorder) RecordKillSwitch(event string) {
	if event == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if event == r.ksLast {
		return
	}
	r.ksEvents++
	r.ksLast = event
	r.ksLastAt = r.now().UTC()
}

// ApplyState returns the recorded apply counters.
func (r *Recorder) ApplyState() ApplyState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.applyRecorded {
		return ApplyState{Reason: "no policy apply has run"}
	}
	return ApplyState{
		Available:    true,
		Count:        r.applyCount,
		LastDuration: r.applyLast,
		LastAt:       r.applyLastAt,
		LastError:    r.applyLastError,
	}
}

// ClassificationErrors returns the classification failure count.
func (r *Recorder) ClassificationErrors() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.classErrors
}

// KillSwitchState returns the recorded kill switch state for one mode.
func (r *Recorder) KillSwitchState(mode string, armed bool) KillSwitchState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return KillSwitchState{
		Available:   true,
		Mode:        mode,
		Armed:       armed,
		Events:      r.ksEvents,
		LastEvent:   r.ksLast,
		LastEventAt: r.ksLastAt,
	}
}
