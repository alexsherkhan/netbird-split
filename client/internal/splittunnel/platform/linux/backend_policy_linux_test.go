//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func initializedBackend(t *testing.T, manager nftManager, router routeManager) *Backend {
	t.Helper()
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _, _ := newTestBackendWithRouter(probe, manager, router)
	require.NoError(t, b.Initialize(context.Background()))
	return b
}

func TestBackendApplyPolicyInstallsAndRollsBack(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, status.PolicyApplied)
	assert.Equal(t, 1, manager.applyCalls)
	assert.Equal(t, 1, router.applyCalls)
	assert.Equal(t, 1, manager.clearCalls, "apply must clear stale policy first")
	assert.Equal(t, 1, router.removeCalls, "apply must remove stale routes first")

	require.NoError(t, b.Rollback(context.Background()))
	status, err = b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.PolicyApplied)
	assert.Equal(t, 2, manager.clearCalls)
	assert.Equal(t, 2, router.removeCalls)
}

func TestBackendApplyPolicySkipsIPv6WithoutHostSupport(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}

	capabilities := availableCapabilities()
	for i := range capabilities.Items {
		if capabilities.Items[i].ID == backend.CapabilityIPv6 {
			capabilities.Items[i] = backend.Capability{
				ID:     backend.CapabilityIPv6,
				State:  backend.CapabilityUnavailable,
				Detail: "IPv6 is disabled",
			}
		}
	}
	probe := &fakeProber{capabilities: capabilities}
	b, _, _ := newTestBackendWithRouter(probe, manager, router)
	require.NoError(t, b.Initialize(context.Background()))

	cfg := includeConfig(
		testRule("vpn4", config.ActionVPN, cidrCondition("10.9.3.0/24")),
		testRule("vpn6", config.ActionVPN, cidrCondition("2001:db8::/32")),
	)
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))

	require.Len(t, router.plans, 1)
	assert.NotEmpty(t, router.plans[0].classes, "IPv4 must still be applied")
	assert.Empty(t, router.plans[0].classes6,
		"a host without IPv6 must skip only the v6 route path")

	require.Len(t, manager.appliedPolicies, 1)
	for _, rule := range manager.appliedPolicies[0].rules {
		assert.Equal(t, family4, rule.family,
			"a host without IPv6 must not install v6 classification rules")
	}
	assert.Empty(t, manager.appliedPolicies[0].sets[setVPN6])
}

func TestBackendApplyPolicyReconcilesWithStableAllocations(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))

	require.Len(t, router.plans, 2)
	first := allocationSnapshot(router.plans[0])
	second := allocationSnapshot(router.plans[1])
	assert.Equal(t, first, second, "repeated applies must reuse allocated primitives")
	assert.Equal(t, 2, manager.applyCalls)
	assert.Equal(t, 2, manager.clearCalls)
}

func allocationSnapshot(plan routePlan) map[routeClass]classAllocation {
	snapshot := make(map[routeClass]classAllocation, len(plan.classes))
	for _, class := range plan.classes {
		snapshot[class.class] = class.allocation
	}
	return snapshot
}

func TestBackendApplyPolicyRejectsUnsupportedWithoutKernelChanges(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("domain", config.ActionVPN,
			config.Condition{Type: config.ConditionDomain, Domain: "a.example.com"},
			config.Condition{Type: config.ConditionDomain, Domain: "b.example.com"}),
	))

	err := b.ApplyPolicy(context.Background(), compiled, testOptions())
	require.ErrorIs(t, err, backend.ErrUnsupportedCondition)
	assert.Zero(t, manager.applyCalls)
	assert.Zero(t, router.applyCalls)
	assert.Zero(t, router.removeCalls)

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.PolicyApplied)
}

func TestBackendApplyPolicyRouterFailureCleansUp(t *testing.T) {
	applyErr := errors.New("route add failed")
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{applyErr: applyErr}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))

	err := b.ApplyPolicy(context.Background(), compiled, testOptions())
	require.ErrorIs(t, err, applyErr)
	assert.Zero(t, manager.applyCalls)
	assert.GreaterOrEqual(t, router.removeCalls, 1)

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.PolicyApplied)
	assert.Contains(t, status.LastError, "route add failed")
}

func TestBackendApplyPolicyNFTFailureRollsBackRoutes(t *testing.T) {
	applyErr := errors.New("nftables failed")
	manager := &fakeManager{createdTable: true, applyPolicyErr: applyErr}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))

	err := b.ApplyPolicy(context.Background(), compiled, testOptions())
	require.ErrorIs(t, err, applyErr)
	assert.Equal(t, 1, manager.applyCalls)
	assert.GreaterOrEqual(t, router.removeCalls, 2,
		"a failed nftables install must remove the routes it prepared")

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.PolicyApplied)
}

func TestBackendApplyDisabledPolicyClearsPrevious(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))
	require.Equal(t, 1, manager.applyCalls)

	disabled := &policy.CompiledPolicy{Enabled: false, Mode: config.ModeStandard}
	require.NoError(t, b.ApplyPolicy(context.Background(), disabled, backend.PolicyOptions{}))
	assert.Equal(t, 1, manager.applyCalls, "a disabled policy must not install rules")

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.PolicyApplied)
}

func TestBackendApplyPolicyExitNodeUnavailablePlanFailsClosed(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

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
				ExitNodeID: "exit-a",
				Conditions: []config.Condition{cidrCondition("203.0.113.0/24")},
			}},
		},
	}
	compiled := mustCompile(t, cfg)

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))
	require.Len(t, router.plans, 1)

	exit, ok := findRouteClass(&policyPlan{route: router.plans[0]}, classExit)
	require.True(t, ok)
	assert.True(t, exit.protected)
	assert.Empty(t, exit.target.Interface, "a missing exit node must route to an unreachable default")
}

func TestBackendApplyPolicyExitNodeMismatch(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

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
				ExitNodeID: "exit-a",
				Conditions: []config.Condition{cidrCondition("203.0.113.0/24")},
			}},
		},
	}
	compiled := mustCompile(t, cfg)

	options := testOptions()
	options.ExitNode = &backend.ExitNode{
		ID:     "exit-b",
		Target: backend.RouteTarget{Interface: "wt-exit"},
	}

	err := b.ApplyPolicy(context.Background(), compiled, options)
	require.ErrorIs(t, err, backend.ErrExitNodeUnavailable)
	assert.Zero(t, router.applyCalls)
}

func TestBackendCleanupRemovesPolicyBeforeTable(t *testing.T) {
	manager := &fakeManager{createdTable: true, owned: defaultOwned()}
	router := &fakeRouter{}
	b := initializedBackend(t, manager, router)

	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, testOptions()))

	clearBefore := manager.clearCalls
	removeBefore := router.removeCalls

	require.NoError(t, b.Cleanup(context.Background()))
	assert.Greater(t, manager.clearCalls, clearBefore,
		"cleanup must remove classification rules before deleting the table")
	assert.Greater(t, router.removeCalls, removeBefore,
		"cleanup must remove policy routing state")
	assert.Equal(t, 1, manager.cleanupCalls)
}
