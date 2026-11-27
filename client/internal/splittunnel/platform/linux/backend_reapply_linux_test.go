//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func vpnTargetOf(t *testing.T, plan routePlan) backend.RouteTarget {
	t.Helper()
	for _, class := range plan.classes {
		if class.class == classVPN {
			return class.target
		}
	}
	t.Fatal("plan has no VPN route")
	return backend.RouteTarget{}
}

func TestBackendReapplyRestoresLastPolicyAndAdvancesGeneration(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(1), status.Generation)

	require.NoError(t, b.Reapply(context.Background()))

	status, err = b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(2), status.Generation)
	assert.Equal(t, 2, router.applyCalls)
	assert.Equal(t, 2, manager.applyCalls)
	assert.Equal(t, "wt0", vpnTargetOf(t, router.plans[1]).Interface)
}

func TestBackendReapplyBeforeFirstApplyIsNoop(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	require.NoError(t, b.Reapply(context.Background()))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Zero(t, status.Generation)
	assert.Zero(t, router.applyCalls)
	assert.Zero(t, manager.applyCalls)
}

func TestBackendFailedApplyKeepsLastSuccessfulPolicyForReapply(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))

	applyErr := errors.New("route add failed")
	router.applyErr = applyErr
	failedOptions := testOptions()
	failedOptions.VPN.Interface = "wt-new"
	err := b.ApplyPolicy(context.Background(), compiled, failedOptions)
	require.ErrorIs(t, err, applyErr)

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(1), status.Generation,
		"a failed apply must not replace the last successful policy")

	router.applyErr = nil
	require.NoError(t, b.Reapply(context.Background()))

	require.NotEmpty(t, router.plans)
	assert.Equal(t, "wt0", vpnTargetOf(t, router.plans[len(router.plans)-1]).Interface,
		"reapply must use the last successful options, not the failed attempt")
}

func TestBackendReapplyOfDisabledPolicyIsNoop(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	disabled := &policy.CompiledPolicy{Enabled: false, Mode: config.ModeStandard}
	require.NoError(t, b.ApplyPolicy(context.Background(), disabled, backend.PolicyOptions{}))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(1), status.Generation)

	require.NoError(t, b.Reapply(context.Background()))

	status, err = b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(1), status.Generation,
		"reapplying a disabled policy must not change kernel state")
	assert.Zero(t, router.applyCalls)
	assert.Zero(t, manager.applyCalls)
}

func TestBackendReapplyUsesClonedOptions(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	exitID := config.ExitNodeID("exit-a")
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{{
				ID:         "exit",
				Name:       "exit",
				Enabled:    true,
				Priority:   10,
				MatchMode:  config.MatchAll,
				Action:     config.ActionExitNode,
				ExitNodeID: exitID,
				Conditions: []config.Condition{cidrCondition("203.0.113.0/24")},
			}},
		},
	}
	compiled := mustCompile(t, cfg)

	target6 := backend.RouteTarget6{Interface: "wt-exit6", Source: netip.MustParseAddr("fd00::1")}
	options := testOptions()
	options.ExitNode = &backend.ExitNode{
		ID:      exitID,
		Target:  backend.RouteTarget{Interface: "wt-exit4"},
		Target6: &target6,
	}
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	options.ExitNode.Target.Interface = "mutated"
	options.ExitNode.Target6.Interface = "mutated6"

	require.NoError(t, b.Reapply(context.Background()))

	last := router.plans[len(router.plans)-1]
	var exit classRoute
	for _, class := range last.classes {
		if class.class == classExit {
			exit = class
		}
	}
	require.NotEmpty(t, exit.target.Interface)
	assert.Equal(t, "wt-exit4", exit.target.Interface,
		"reapply must not observe a caller mutation of the stored options")
}

func TestBackendReapplyRestoresKillSwitchAndClonedDNS(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := killSwitchCompiled(t, config.KillSwitchGlobal)
	options := testOptions()
	options.DNSResolvers = []netip.Prefix{netip.MustParsePrefix("10.0.1.53/32")}
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	options.DNSResolvers[0] = netip.MustParsePrefix("10.0.9.53/32")
	require.NoError(t, b.Reapply(context.Background()))

	require.Len(t, manager.appliedPolicies, 2)
	last := manager.appliedPolicies[1]
	assert.NotEmpty(t, last.killswitch, "reconcile must reinstall the kill switch atomically")
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
		last.sets[setKillSwitchControl4])

	found := false
	for _, rule := range last.killswitch {
		for _, match := range rule.matches {
			if match.prefix == netip.MustParsePrefix("10.0.1.53/32") && match.port == 53 {
				found = true
			}
		}
	}
	assert.True(t, found, "reapply must use the cloned DNS resolver list")
}
