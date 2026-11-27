package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/diagnostics"
)

var _ diagnostics.Provider = (*Controller)(nil)

type counterSourceFunc func(context.Context) (diagnostics.CounterSample, error)

func (f counterSourceFunc) TrafficCounters(ctx context.Context) (diagnostics.CounterSample, error) {
	return f(ctx)
}

// Diagnostics returns a typed local snapshot without crossing the gRPC
// boundary. It aggregates owned counters, tracker state and controller
// counters. A metric that cannot be read is reported as unavailable.
func (c *Controller) Diagnostics(ctx context.Context) (diagnostics.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.diagnosticsLocked(ctx), nil
}

func (c *Controller) diagnosticsLocked(ctx context.Context) diagnostics.Snapshot {
	sources := diagnostics.Sources{
		Now: time.Now,
	}
	if c.backend != nil {
		if provider, ok := c.backend.(interface {
			TrafficCounters(context.Context) (diagnostics.CounterSample, error)
		}); ok {
			sources.Counters = counterSourceFunc(provider.TrafficCounters)
		}
	}
	sources.DNS = func() diagnostics.DNSState {
		if c.tracker == nil {
			return diagnostics.DNSState{Reason: "DNS observation is not attached"}
		}
		tracker := c.tracker.Diagnostics()
		return diagnostics.DNSState{Available: true, CacheSize: tracker.Addresses}
	}
	sources.ClassificationErrors = func() uint64 {
		var errors uint64
		if c.diag != nil {
			errors += c.diag.ClassificationErrors()
		}
		if c.tracker != nil {
			errors += c.tracker.Diagnostics().Errors
		}
		return errors
	}
	if c.diag != nil {
		sources.Apply = c.diag.ApplyState
		mode := config.KillSwitchDisabled
		if c.config != nil && c.config.SplitTunnel.KillSwitch != "" {
			mode = c.config.SplitTunnel.KillSwitch
		}
		sources.KillSwitch = func() diagnostics.KillSwitchState {
			return c.diag.KillSwitchState(string(mode), c.protectionArmed)
		}
	}
	sources.Gateway = func() diagnostics.GatewayState {
		return c.gatewayStateLocked(ctx)
	}
	return diagnostics.Collect(ctx, sources)
}

func (c *Controller) gatewayStateLocked(ctx context.Context) diagnostics.GatewayState {
	if c.backend == nil {
		return diagnostics.GatewayState{Reason: "split tunnel backend is unavailable"}
	}
	state := diagnostics.GatewayState{Available: true}
	if c.backendInitialized {
		status, err := c.backend.GetStatus(ctx)
		if err != nil {
			state.Available = false
			state.Reason = "read backend status: " + err.Error()
			return state
		}
		state.BackendState = string(status.State)
		state.PolicyApplied = status.PolicyApplied
	}
	state.GatewayConfigured = c.appliedOptions.VPN.Interface != ""
	state.ExitConfigured = c.appliedOptions.ExitNode != nil
	state.Protected = c.protectionArmed
	return state
}

func diagnosticsSummary(snapshot diagnostics.Snapshot) map[string]string {
	summary := map[string]string{
		"diagnostics.traffic.outgoing":        countSummary(snapshot.Traffic.Outgoing),
		"diagnostics.traffic.incoming":        countSummary(snapshot.Traffic.Incoming),
		"diagnostics.traffic.vpn":             countSummary(snapshot.Traffic.VPN),
		"diagnostics.traffic.direct":          countSummary(snapshot.Traffic.Direct),
		"diagnostics.traffic.block":           countSummary(snapshot.Traffic.Block),
		"diagnostics.traffic.exit":            countSummary(snapshot.Traffic.Exit),
		"diagnostics.traffic.rule_hits":       countSummary(snapshot.Traffic.RuleHits),
		"diagnostics.connections":             countSummary(snapshot.Connections),
		"diagnostics.classification.errors":   strconv.FormatUint(snapshot.Classification.Errors, 10),
		"diagnostics.apply.count":             strconv.FormatUint(snapshot.Apply.Count, 10),
		"diagnostics.kill_switch.events":      strconv.FormatUint(snapshot.KillSwitch.Events, 10),
		"diagnostics.kill_switch.last_event":  snapshot.KillSwitch.LastEvent,
		"diagnostics.kill_switch.armed":       strconv.FormatBool(snapshot.KillSwitch.Armed),
		"diagnostics.kill_switch.mode":        snapshot.KillSwitch.Mode,
		"diagnostics.gateway.state":           snapshot.Gateway.BackendState,
		"diagnostics.gateway.policy_applied":  strconv.FormatBool(snapshot.Gateway.PolicyApplied),
		"diagnostics.gateway.configured":      strconv.FormatBool(snapshot.Gateway.GatewayConfigured),
		"diagnostics.gateway.exit_configured": strconv.FormatBool(snapshot.Gateway.ExitConfigured),
		"diagnostics.gateway.protected":       strconv.FormatBool(snapshot.Gateway.Protected),
	}
	if snapshot.DNS.Available {
		summary["diagnostics.dns.cache_size"] = strconv.Itoa(snapshot.DNS.CacheSize)
	} else {
		summary["diagnostics.dns.cache_size"] = "unavailable"
	}
	if snapshot.Apply.Available {
		summary["diagnostics.apply.last_latency"] = snapshot.Apply.LastDuration.String()
	} else {
		summary["diagnostics.apply.last_latency"] = "unavailable"
	}
	if len(snapshot.UnavailableMetrics) > 0 {
		summary["diagnostics.unavailable"] = strings.Join(snapshot.UnavailableMetrics, ",")
	}
	return summary
}

func countSummary(count diagnostics.Count) string {
	if !count.Available {
		if count.Reason != "" {
			return "unavailable: " + count.Reason
		}
		return "unavailable"
	}
	return fmt.Sprintf("packets=%d bytes=%d", count.Packets, count.Bytes)
}
