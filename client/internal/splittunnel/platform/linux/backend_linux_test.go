//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
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
	appliedPolicies []nftPolicy
	owned           backend.OwnedObjects
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

func (f *fakeManager) ClearPolicy(context.Context) error {
	f.clearCalls++
	return f.clearPolicyErr
}

type fakeRouter struct {
	applyErr    error
	removeErr   error
	applyCalls  int
	removeCalls int
	plans       []routePlan
	allocations allocations
}

func (f *fakeRouter) Apply(_ context.Context, plan routePlan) error {
	f.applyCalls++
	f.plans = append(f.plans, plan)
	return f.applyErr
}

func (f *fakeRouter) Remove(_ context.Context, allocations allocations) error {
	f.removeCalls++
	f.allocations = allocations
	return f.removeErr
}

func availableCapabilities() backend.Capabilities {
	ids := []backend.CapabilityID{
		backend.CapabilityNFTables,
		backend.CapabilityNetlink,
		backend.CapabilityPolicyRouting,
		backend.CapabilityRouteOutputHook,
		backend.CapabilityCgroupV2,
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

func TestUpdateDomainSetsIsNotImplemented(t *testing.T) {
	probe := &fakeProber{capabilities: availableCapabilities()}
	b, _ := newTestBackend(probe, &fakeManager{createdTable: true})

	require.NoError(t, b.Initialize(context.Background()))

	err := b.UpdateDomainSets(context.Background(), nil)
	require.ErrorIs(t, err, backend.ErrNotImplemented)
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
