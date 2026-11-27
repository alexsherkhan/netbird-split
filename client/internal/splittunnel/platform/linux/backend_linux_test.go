//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

type fakeProber struct {
	capabilities backend.Capabilities
	err          error
	calls        int
}

func (f *fakeProber) Probe(context.Context) (backend.Capabilities, error) {
	f.calls++
	return f.capabilities.Clone(), f.err
}

type fakeManager struct {
	ensureErr       error
	cleanupErr      error
	applyPolicyErr  error
	clearPolicyErr  error
	createdTable    bool
	ensureCalls     int
	cleanupCalls    int
	applyCalls      int
	clearCalls      int
	domainCalls     int
	killSwitchCalls int
	appliedPolicies []nftPolicy
	domainUpdates   [][]backend.DomainSetUpdate
	killSwitchRules [][]nftKillRule
	killSwitchSets  []map[setName][]netip.Prefix
	killSwitchErr   error
	domainErr       error
	owned           backend.OwnedObjects
	verifyErr       error
	inspectErr      error
	inspect         nftObservation
	verifyCalls     int
	inspectCalls    int
}

func (f *fakeManager) Ensure(context.Context) error {
	f.ensureCalls++
	return f.ensureErr
}

func (f *fakeManager) Cleanup(context.Context) error {
	f.cleanupCalls++
	return f.cleanupErr
}

func (f *fakeManager) CreatedTable() bool {
	return f.createdTable
}

func (f *fakeManager) Owned() backend.OwnedObjects {
	return f.owned.Clone()
}

func (f *fakeManager) ApplyPolicy(_ context.Context, policy nftPolicy) error {
	f.applyCalls++
	f.appliedPolicies = append(f.appliedPolicies, policy)
	return f.applyPolicyErr
}

func (f *fakeManager) ApplyKillSwitch(
	_ context.Context,
	controlSets map[setName][]netip.Prefix,
	rules []nftKillRule,
) error {
	f.killSwitchCalls++
	clonedSets := make(map[setName][]netip.Prefix, len(controlSets))
	for name, prefixes := range controlSets {
		clonedSets[name] = append([]netip.Prefix(nil), prefixes...)
	}
	f.killSwitchSets = append(f.killSwitchSets, clonedSets)
	f.killSwitchRules = append(f.killSwitchRules, append([]nftKillRule(nil), rules...))
	return f.killSwitchErr
}

func (f *fakeManager) ApplyDomainSets(_ context.Context, updates []backend.DomainSetUpdate) error {
	f.domainCalls++
	f.domainUpdates = append(f.domainUpdates, cloneDomainUpdates(updates))
	return f.domainErr
}

func (f *fakeManager) ClearPolicy(context.Context) error {
	f.clearCalls++
	return f.clearPolicyErr
}

func (f *fakeManager) VerifyPolicy(context.Context, nftPolicy) error {
	f.verifyCalls++
	return f.verifyErr
}

func (f *fakeManager) Inspect(context.Context) (nftObservation, error) {
	f.inspectCalls++
	return f.inspect, f.inspectErr
}

func cloneDomainUpdates(updates []backend.DomainSetUpdate) []backend.DomainSetUpdate {
	out := make([]backend.DomainSetUpdate, len(updates))
	for i := range updates {
		out[i].Action = updates[i].Action
		out[i].Entries = append([]backend.DomainEntry(nil), updates[i].Entries...)
	}
	return out
}

type fakeRouter struct {
	applyErr          error
	applyFailFrom     int
	removeErr         error
	removeUnusedErr   error
	verifyErr         error
	inspectErr        error
	applyCalls        int
	removeCalls       int
	removeUnusedCalls int
	verifyCalls       int
	inspectCalls      int
	plans             []routePlan
	allocations       allocations
	inspect           routeObservation
}

func (f *fakeRouter) Apply(_ context.Context, plan routePlan) error {
	f.applyCalls++
	f.plans = append(f.plans, plan)
	if f.applyFailFrom > 0 {
		if f.applyCalls >= f.applyFailFrom {
			return f.applyErr
		}
		return nil
	}
	return f.applyErr
}

func (f *fakeRouter) Remove(_ context.Context, allocations allocations) error {
	f.removeCalls++
	f.allocations = allocations
	return f.removeErr
}

func (f *fakeRouter) RemoveUnused(context.Context, allocations, map[routeClass]bool) error {
	f.removeUnusedCalls++
	return f.removeUnusedErr
}

func (f *fakeRouter) Verify(context.Context, routePlan) error {
	f.verifyCalls++
	return f.verifyErr
}

func (f *fakeRouter) Inspect(context.Context, allocations) (routeObservation, error) {
	f.inspectCalls++
	return f.inspect, f.inspectErr
}

func availableCapabilities() backend.Capabilities {
	ids := []backend.CapabilityID{
		backend.CapabilityNFTables,
		backend.CapabilityNetlink,
		backend.CapabilityPolicyRouting,
		backend.CapabilityRouteOutputHook,
		backend.CapabilityCgroupV2,
		backend.CapabilitySocketCgroupV2,
		backend.CapabilityEBPF,
		backend.CapabilityIPv6,
	}
	items := make([]backend.Capability, len(ids))
	for i, id := range ids {
		items[i] = backend.Capability{ID: id, State: backend.CapabilityAvailable}
	}
	return backend.Capabilities{Items: items}
}

func newTestBackend(probe capabilityProber, manager nftManager) (*Backend, *int) {
	b, openCalls, _ := newTestBackendWithRouter(probe, manager, &fakeRouter{})
	return b, openCalls
}

func newTestBackendWithRouter(
	probe capabilityProber,
	manager nftManager,
	router routeManager,
) (*Backend, *int, *fakeRouter) {
	openCalls := 0
	open := func(string) (nftManager, error) {
		openCalls++
		return manager, nil
	}
	fake, ok := router.(*fakeRouter)
	if !ok {
		fake = &fakeRouter{}
	}
	b := newBackendWith(probe, open, router, "netbird_split_test")
	return b, &openCalls, fake
}

func defaultOwned() backend.OwnedObjects {
	return backend.OwnedObjects{
		Table:  "netbird_split_test",
		Chains: []string{"classify_output"},
		Sets:   []string{"vpn4"},
	}
}

func TestInitializeIsIdempotent(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true, owned: defaultOwned()}
	b, openCalls := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))
	require.NoError(t, b.Initialize(context.Background()))

	assert.Equal(t, 1, manager.ensureCalls)
	assert.Equal(t, 1, *openCalls)
	assert.Equal(t, 1, probe.calls)

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateReady, status.State)
	assert.Equal(t, defaultOwned(), status.Owned)
	assert.False(t, status.PolicyApplied)
	assert.Empty(t, status.LastError)
}

func TestInitializeRollsBackOnlyCreatedTable(t *testing.T) {
	ensureErr := errors.New("ensure failed")

	t.Run("created table is removed", func(t *testing.T) {
		probe := &fakeProber{capabilities: availableCapabilities()}
		manager := &fakeManager{ensureErr: ensureErr, createdTable: true}
		b, _ := newTestBackend(probe, manager)

		err := b.Initialize(context.Background())
		require.ErrorIs(t, err, ensureErr)
		assert.Equal(t, 1, manager.cleanupCalls)

		status, statusErr := b.GetStatus(context.Background())
		require.NoError(t, statusErr)
		assert.Equal(t, backend.StateFailed, status.State)
		assert.Contains(t, status.LastError, "ensure failed")
	})

	t.Run("pre-existing table is left alone", func(t *testing.T) {
		probe := &fakeProber{capabilities: availableCapabilities()}
		manager := &fakeManager{ensureErr: ensureErr}
		b, _ := newTestBackend(probe, manager)

		err := b.Initialize(context.Background())
		require.ErrorIs(t, err, ensureErr)
		assert.Zero(t, manager.cleanupCalls,
			"a failed reconciliation must not remove a table it did not create")
	})
}

func TestInitializeReportsRollbackError(t *testing.T) {
	ensureErr := errors.New("ensure failed")
	cleanupErr := errors.New("cleanup failed")
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{
		ensureErr:    ensureErr,
		cleanupErr:   cleanupErr,
		createdTable: true,
	}
	b, _ := newTestBackend(probe, manager)

	err := b.Initialize(context.Background())
	require.ErrorIs(t, err, ensureErr)
	require.ErrorIs(t, err, cleanupErr)
}

func TestInitializeRejectsMissingRequiredCapabilities(t *testing.T) {
	capabilities := availableCapabilities()
	for i := range capabilities.Items {
		if capabilities.Items[i].ID == backend.CapabilityNFTables {
			capabilities.Items[i] = backend.Capability{
				ID:     backend.CapabilityNFTables,
				State:  backend.CapabilityUnavailable,
				Detail: "requires CAP_NET_ADMIN",
			}
		}
	}
	probe := &fakeProber{capabilities: capabilities}
	manager := &fakeManager{}
	b, openCalls := newTestBackend(probe, manager)

	err := b.Initialize(context.Background())
	require.ErrorIs(t, err, backend.ErrCapabilityUnavailable)
	assert.Zero(t, *openCalls)
	assert.Zero(t, manager.ensureCalls)

	status, statusErr := b.GetStatus(context.Background())
	require.NoError(t, statusErr)
	assert.Equal(t, backend.StateFailed, status.State)
}

func TestInitializeDegradesOnOptionalCapability(t *testing.T) {
	capabilities := availableCapabilities()
	for i := range capabilities.Items {
		if capabilities.Items[i].ID == backend.CapabilityCgroupV2 {
			capabilities.Items[i].State = backend.CapabilityUnavailable
		}
	}
	probe := &fakeProber{capabilities: capabilities}
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))
	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateDegraded, status.State)
}

func TestApplyPolicyRejectsNilPolicy(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{createdTable: true})

	require.NoError(t, b.Initialize(context.Background()))

	err := b.ApplyPolicy(context.Background(), nil, backend.PolicyOptions{})
	require.ErrorIs(t, err, backend.ErrInvalidPolicyOption)
}

func TestUpdateDomainSetsReplacesOwnedSets(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))

	expires := time.Now().Add(time.Minute).UTC()
	updates := []backend.DomainSetUpdate{
		{
			Action: config.ActionVPN,
			Entries: []backend.DomainEntry{
				{Prefix: netip.MustParsePrefix("192.0.2.1/32"), ExpiresAt: expires},
				{Prefix: netip.MustParsePrefix("2001:db8::1/128"), ExpiresAt: expires},
			},
		},
		{Action: config.ActionDirect},
		{Action: config.ActionBlock},
	}
	require.NoError(t, b.UpdateDomainSets(context.Background(), updates))

	require.Equal(t, 1, manager.domainCalls)
	applied := manager.domainUpdates[0]
	require.Len(t, applied, 3)
	assert.Equal(t, config.ActionVPN, applied[0].Action)
	assert.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}, []netip.Prefix{
		applied[0].Entries[0].Prefix, applied[0].Entries[1].Prefix,
	})
}

func TestUpdateDomainSetsRejectsInvalidBatchBeforeKernelChanges(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))

	err := b.UpdateDomainSets(context.Background(), []backend.DomainSetUpdate{
		{
			Action: config.ActionVPN,
			Entries: []backend.DomainEntry{{
				Prefix: netip.MustParsePrefix("192.0.2.2/32"),
			}},
		},
		{
			Action: config.ActionDirect,
			Entries: []backend.DomainEntry{{
				Prefix: netip.MustParsePrefix("192.0.2.2/32"),
			}},
		},
	})
	require.Error(t, err)
	assert.Zero(t, manager.domainCalls, "an invalid batch must not touch kernel state")

	err = b.UpdateDomainSets(context.Background(), []backend.DomainSetUpdate{{
		Action: config.ActionExitNode,
	}})
	require.Error(t, err)
	assert.Zero(t, manager.domainCalls)
}

func TestUpdateDomainSetsPropagatesBackendError(t *testing.T) {
	applyErr := errors.New("domain set update failed")
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true, domainErr: applyErr}
	b, _ := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))

	err := b.UpdateDomainSets(context.Background(), nil)
	require.ErrorIs(t, err, applyErr)

	status, statusErr := b.GetStatus(context.Background())
	require.NoError(t, statusErr)
	assert.Contains(t, status.LastError, "domain set update failed")
}

func TestPolicyOperationsRequireInitialization(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{})

	err := b.ApplyPolicy(context.Background(), nil, backend.PolicyOptions{})
	require.ErrorIs(t, err, backend.ErrNotInitialized)

	err = b.UpdateDomainSets(context.Background(), nil)
	require.ErrorIs(t, err, backend.ErrNotInitialized)
}

func TestRollbackIsIdempotent(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{createdTable: true})

	require.NoError(t, b.Rollback(context.Background()))
	require.NoError(t, b.Initialize(context.Background()))
	require.NoError(t, b.Rollback(context.Background()))
	require.NoError(t, b.Rollback(context.Background()))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateReady, status.State)
	assert.False(t, status.PolicyApplied)
}

func TestCleanupIsIdempotent(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true, owned: defaultOwned()}
	b, openCalls := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))
	require.NoError(t, b.Cleanup(context.Background()))
	require.NoError(t, b.Cleanup(context.Background()))

	assert.Equal(t, 1, manager.cleanupCalls)

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateUninitialized, status.State)
	assert.Equal(t, backend.OwnedObjects{}, status.Owned)

	require.NoError(t, b.Initialize(context.Background()))
	assert.Equal(t, 2, manager.ensureCalls)
	assert.Equal(t, 2, *openCalls)
}

func TestCleanupWithoutInitializeRemovesLeftovers(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{}
	b, openCalls := newTestBackend(probe, manager)

	require.NoError(t, b.Cleanup(context.Background()))
	assert.Equal(t, 1, manager.cleanupCalls)
	assert.Equal(t, 1, *openCalls)
}

func TestCloseIsIdempotentAndTerminal(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))
	require.NoError(t, b.Close(context.Background()))
	require.NoError(t, b.Close(context.Background()))

	assert.Equal(t, 1, manager.cleanupCalls)
	require.ErrorIs(t, b.Initialize(context.Background()), backend.ErrClosed)
	require.ErrorIs(t, b.ApplyPolicy(context.Background(), nil, backend.PolicyOptions{}), backend.ErrClosed)
	require.NoError(t, b.Cleanup(context.Background()))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateClosed, status.State)
}

func TestCloseKeepsBackendOpenOnCleanupFailure(t *testing.T) {
	cleanupErr := errors.New("cleanup failed")
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true, cleanupErr: cleanupErr}
	b, _ := newTestBackend(probe, manager)

	require.NoError(t, b.Initialize(context.Background()))
	require.ErrorIs(t, b.Close(context.Background()), cleanupErr)

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateFailed, status.State)

	manager.cleanupErr = nil
	require.NoError(t, b.Close(context.Background()))
	assert.Equal(t, 2, manager.cleanupCalls)

	status, err = b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateClosed, status.State)
}

func TestInitializeCanRetryAfterFailure(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true, ensureErr: errors.New("transient")}
	b, _ := newTestBackend(probe, manager)

	require.Error(t, b.Initialize(context.Background()))
	manager.ensureErr = nil
	require.NoError(t, b.Initialize(context.Background()))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateReady, status.State)
	assert.Empty(t, status.LastError)
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{})

	require.ErrorIs(t, b.Initialize(ctx), context.Canceled)
	require.ErrorIs(t, b.Cleanup(ctx), context.Canceled)
	_, err := b.GetStatus(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestStatusSnapshotsAreIndependent(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{createdTable: true, owned: defaultOwned()})
	require.NoError(t, b.Initialize(context.Background()))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	status.Owned.Chains[0] = "changed"
	status.Capabilities.Items[0].State = backend.CapabilityUnavailable

	second, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "classify_output", second.Owned.Chains[0])
	assert.Equal(t, backend.CapabilityAvailable, second.Capabilities.Items[0].State)
}

func TestNewBackendStatus(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{})

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateUninitialized, status.State)
	assert.Empty(t, status.Owned)
	assert.False(t, status.PolicyApplied)
}

func TestGetCapabilitiesRefreshesStatus(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{createdTable: true})
	require.NoError(t, b.Initialize(context.Background()))

	probe.capabilities = availableCapabilities()
	for i := range probe.capabilities.Items {
		if probe.capabilities.Items[i].ID == backend.CapabilityCgroupV2 {
			probe.capabilities.Items[i].State = backend.CapabilityUnavailable
		}
	}

	capabilities, err := b.GetCapabilities(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.CapabilityUnavailable, capabilities.StateOf(backend.CapabilityCgroupV2))

	status, err := b.GetStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, backend.StateDegraded, status.State)
}

func TestApplyPolicyRequiresApplicationCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		disabled backend.CapabilityID
	}{
		{name: "cgroup v2", disabled: backend.CapabilityCgroupV2},
		{name: "socket cgroupv2", disabled: backend.CapabilitySocketCgroupV2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capabilities := availableCapabilities()
			for i := range capabilities.Items {
				if capabilities.Items[i].ID == tt.disabled {
					capabilities.Items[i].State = backend.CapabilityUnavailable
				}
			}
			manager := &fakeManager{createdTable: true}
			b, _ := newTestBackend(&fakeProber{capabilities: capabilities}, manager)
			require.NoError(t, b.Initialize(context.Background()))

			compiled := mustCompile(t, includeConfig(
				testRule("firefox", config.ActionVPN,
					appCondition(config.ConditionDesktopID, "firefox.desktop")),
			))
			err := b.ApplyPolicy(context.Background(), compiled, testOptions())
			require.ErrorIs(t, err, backend.ErrCapabilityUnavailable)
			assert.Empty(t, manager.appliedPolicies,
				"an application policy must not fall back to unclassified routing")
		})
	}
}

func TestApplyPolicyInstallsCgroupRules(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(&fakeProber{capabilities: availableCapabilities()}, manager)
	require.NoError(t, b.Initialize(context.Background()))
	b.cgroupIDs = fakeCgroupResolver{"apps/firefox.scope": 0x42}

	compiled := mustCompile(t, includeConfig(
		testRule("firefox", config.ActionVPN,
			appCondition(config.ConditionDesktopID, "firefox.desktop")),
	))
	options := testOptions()
	options.Applications = []backend.ApplicationScope{{
		Identity:   backend.ApplicationIdentity{DesktopID: "firefox.desktop"},
		UID:        1000,
		CgroupPath: "apps/firefox.scope",
	}}

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	require.Len(t, manager.appliedPolicies, 1)

	var cgroupRules int
	for _, rule := range manager.appliedPolicies[0].rules {
		if rule.cgroup != nil {
			cgroupRules++
			assert.Equal(t, uint64(0x42), rule.cgroup.ID)
		}
	}
	assert.Positive(t, cgroupRules, "the compiled policy must contain a socket cgroup match")
}

func TestApplyPolicyReplacesApplicationCgroupRules(t *testing.T) {
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(&fakeProber{capabilities: availableCapabilities()}, manager)
	require.NoError(t, b.Initialize(context.Background()))
	resolver := fakeCgroupResolver{
		"apps/firefox.scope": 0x51,
		"apps/chrome.scope":  0x52,
	}
	b.cgroupIDs = resolver

	compiled := mustCompile(t, includeConfig(
		testRule("firefox", config.ActionVPN,
			appCondition(config.ConditionDesktopID, "firefox.desktop")),
		testRule("chrome", config.ActionDirect,
			appCondition(config.ConditionDesktopID, "chrome.desktop")),
	))

	first := testOptions()
	first.Applications = []backend.ApplicationScope{{
		Identity:   backend.ApplicationIdentity{DesktopID: "firefox.desktop"},
		CgroupPath: "apps/firefox.scope",
	}}
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, first))

	second := testOptions()
	second.Applications = []backend.ApplicationScope{{
		Identity:   backend.ApplicationIdentity{DesktopID: "chrome.desktop"},
		CgroupPath: "apps/chrome.scope",
	}}
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, second))

	require.Len(t, manager.appliedPolicies, 2)
	ids := map[uint64]bool{}
	for _, rule := range manager.appliedPolicies[1].rules {
		if rule.cgroup != nil {
			ids[rule.cgroup.ID] = true
		}
	}
	assert.Equal(t, map[uint64]bool{0x52: true}, ids,
		"a live policy update must replace the previous application cgroup match")
}

func killSwitchCompiled(t *testing.T, mode config.KillSwitchMode) *policy.CompiledPolicy {
	t.Helper()

	cfg := includeConfig(testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")))
	cfg.SplitTunnel.KillSwitch = mode
	compiled, err := policy.CompileWith(cfg, policy.Constraints{
		ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
	})
	require.NoError(t, err)
	return compiled
}

func TestApplyPolicyInstallsKillSwitch(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(probe, manager)
	require.NoError(t, b.Initialize(context.Background()))

	require.NoError(t, b.ApplyPolicy(context.Background(),
		killSwitchCompiled(t, config.KillSwitchGlobal), testOptions()))
	require.Len(t, manager.appliedPolicies, 1)
	assert.NotEmpty(t, manager.appliedPolicies[0].killswitch,
		"a full apply must install the kill switch in the same transaction")
	assert.NotEmpty(t, manager.appliedPolicies[0].sets[setKillSwitchControl4])

	require.NoError(t, b.ApplyPolicy(context.Background(),
		killSwitchCompiled(t, config.KillSwitchDisabled), testOptions()))
	require.Len(t, manager.appliedPolicies, 2)
	assert.Empty(t, manager.appliedPolicies[1].killswitch,
		"disabling the kill switch must clear the rules")
}

func TestInstallProtectionIsIdempotent(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true}
	b, _ := newTestBackend(probe, manager)
	require.NoError(t, b.Initialize(context.Background()))

	compiled := killSwitchCompiled(t, config.KillSwitchGlobal)
	require.NoError(t, b.InstallProtection(context.Background(), compiled, testOptions()))
	require.NoError(t, b.InstallProtection(context.Background(), compiled, testOptions()))

	require.Equal(t, 2, manager.killSwitchCalls)
	for _, rules := range manager.killSwitchRules {
		assert.NotEmpty(t, rules)
	}
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
		manager.killSwitchSets[0][setKillSwitchControl4])
	assert.Zero(t, manager.applyCalls,
		"pre-arming protection must not apply routes or classification")

	require.NoError(t, b.InstallProtection(context.Background(),
		killSwitchCompiled(t, config.KillSwitchDisabled), testOptions()))
	require.Equal(t, 3, manager.killSwitchCalls)
	assert.Empty(t, manager.killSwitchRules[2], "a disabled mode must clear the chain")
}

func TestInstallProtectionRequiresInitialization(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{})
	compiled := killSwitchCompiled(t, config.KillSwitchGlobal)

	require.ErrorIs(t, b.InstallProtection(context.Background(), compiled, testOptions()),
		backend.ErrNotInitialized)
}

func TestInstallProtectionRejectsNilPolicy(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{createdTable: true})
	require.NoError(t, b.Initialize(context.Background()))

	require.ErrorIs(t, b.InstallProtection(context.Background(), nil, testOptions()),
		backend.ErrInvalidPolicyOption)
}

func TestInstallProtectionPropagatesManagerError(t *testing.T) {
	applyErr := errors.New("kill switch apply failed")
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true, killSwitchErr: applyErr}
	b, _ := newTestBackend(probe, manager)
	require.NoError(t, b.Initialize(context.Background()))

	err := b.InstallProtection(context.Background(),
		killSwitchCompiled(t, config.KillSwitchStrict), testOptions())
	require.ErrorIs(t, err, applyErr)

	status, statusErr := b.GetStatus(context.Background())
	require.NoError(t, statusErr)
	assert.Contains(t, status.LastError, "kill switch apply failed")
}

func TestEmergencyResetClearsPolicyAndStopsReapply(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{createdTable: true}
	b, _, router := newTestBackendWithRouter(probe, manager, &fakeRouter{})
	require.NoError(t, b.Initialize(context.Background()))
	require.NoError(t, b.ApplyPolicy(context.Background(),
		killSwitchCompiled(t, config.KillSwitchGlobal), testOptions()))
	require.Equal(t, 1, manager.applyCalls)
	clearBefore := manager.clearCalls
	removeBefore := router.removeCalls

	require.NoError(t, b.EmergencyReset(context.Background()))
	assert.Equal(t, clearBefore+1, manager.clearCalls,
		"emergency reset must clear kill switch and policy rules")
	assert.Equal(t, removeBefore+1, router.removeCalls,
		"emergency reset must remove protected routes")
	assert.False(t, b.policyApplied)

	require.NoError(t, b.Reapply(context.Background()))
	assert.Equal(t, 1, manager.applyCalls, "emergency reset must not re-arm protection")

	require.NoError(t, b.EmergencyReset(context.Background()))
	assert.Equal(t, clearBefore+2, manager.clearCalls, "emergency reset must stay idempotent")
}

func TestEmergencyResetWithoutInitializeIsNoop(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{}
	b, _ := newTestBackend(probe, manager)

	require.NoError(t, b.EmergencyReset(context.Background()))
	assert.Zero(t, manager.clearCalls)
}
