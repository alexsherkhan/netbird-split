package controller

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

type fakeBackend struct {
	mu sync.Mutex

	initCalls    int
	initErr      error
	recoverCalls int
	recoverErr   error
	recoverReply RecoveryReport

	applyCalls   int
	applyErr     error
	lastCompiled *policy.CompiledPolicy
	lastOptions  backend.PolicyOptions

	rollbackCalls  int
	emergencyCalls int
	closeCalls     int

	status    backend.Status
	statusErr error
}

func (b *fakeBackend) Initialize(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initCalls++
	return b.initErr
}

func (b *fakeBackend) Recover(context.Context) (RecoveryReport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.recoverCalls++
	return b.recoverReply, b.recoverErr
}

func (b *fakeBackend) ApplyPolicy(
	_ context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applyCalls++
	b.lastCompiled = compiled
	b.lastOptions = options
	return b.applyErr
}

func (b *fakeBackend) Rollback(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollbackCalls++
	return nil
}

func (b *fakeBackend) GetStatus(context.Context) (backend.Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status, b.statusErr
}

func (b *fakeBackend) EmergencyReset(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.emergencyCalls++
	return nil
}

func (b *fakeBackend) Close(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeCalls++
	return nil
}

func (b *fakeBackend) calls() (init, recoverCalls, apply int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.initCalls, b.recoverCalls, b.applyCalls
}

func (b *fakeBackend) setApplyErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applyErr = err
}

func testConfig() *config.Config {
	return &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			KillSwitch:    config.KillSwitchSelective,
			DNS:           config.DNSSettings{ConflictPolicy: config.ConflictVPN},
			Rules: []config.Rule{{
				ID:        "rule-vpn",
				Name:      "VPN rule",
				Enabled:   true,
				Priority:  10,
				MatchMode: config.MatchAll,
				Conditions: []config.Condition{{
					Type:   config.ConditionCIDR,
					Prefix: mustPrefix("10.0.0.0/8"),
				}},
				Action: config.ActionVPN,
			}},
		},
	}
}

func mustPrefix(value string) netip.Prefix {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		panic(err)
	}
	return prefix
}

func testWiring(context.Context) (Wiring, error) {
	return Wiring{
		Options: backend.PolicyOptions{
			VPN:    backend.RouteTarget{Interface: "wt0"},
			Direct: backend.RouteTarget{Interface: "eth0"},
		},
	}, nil
}

func newTestController(t *testing.T, path string, backend Backend) *Controller {
	t.Helper()
	return New(path, Options{Backend: backend, Runtime: testWiring})
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func TestStartWithMissingConfigLeavesBackendIdle(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	ctrl := newTestController(t, path, backend)

	require.NoError(t, ctrl.Start(testContext(t)))

	init, recoverCalls, apply := backend.calls()
	assert.Zero(t, init, "a missing configuration must not initialize the backend")
	assert.Zero(t, recoverCalls)
	assert.Zero(t, apply)

	status, err := ctrl.Status(testContext(t))
	require.NoError(t, err)
	assert.False(t, status.Enabled)
	assert.False(t, status.Running)
	assert.Equal(t, config.ModeStandard, status.Mode)
	assert.Equal(t, backendName(), status.Backend)
	assert.Equal(t, "missing", status.Diagnostics["config"])
}

func TestApplyPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigFileName)
	first := &fakeBackend{}
	ctrl := newTestController(t, path, first)
	require.NoError(t, ctrl.Start(testContext(t)))

	revision, err := ctrl.ApplyConfig(testContext(t), testConfig(), 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), revision)

	init, _, apply := first.calls()
	assert.Equal(t, 1, init)
	assert.Equal(t, 1, apply)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "config must be private")

	second := &fakeBackend{}
	reloaded := newTestController(t, path, second)
	require.NoError(t, reloaded.Start(testContext(t)))

	cfg, current, err := reloaded.Config(testContext(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), current)
	require.NotNil(t, cfg)
	assert.Equal(t, config.ModeCustom, cfg.SplitTunnel.Mode)

	_, _, apply = second.calls()
	assert.Equal(t, 1, apply, "an enabled persisted configuration is applied on startup")
}

func TestApplyAdvancesRevisionAndRejectsStaleWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	ctrl := newTestController(t, path, backend)
	require.NoError(t, ctrl.Start(testContext(t)))

	cfg := testConfig()
	revision, err := ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), revision)

	included := testConfig()
	included.SplitTunnel.Mode = config.ModeInclude
	included.SplitTunnel.Rules = nil
	revision, err = ctrl.ApplyConfig(testContext(t), included, revision)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), revision)

	_, _, applyBefore := backend.calls()
	_, err = ctrl.ApplyConfig(testContext(t), cfg, 1)
	require.ErrorIs(t, err, api.ErrRevisionConflict)
	_, _, applyAfter := backend.calls()
	assert.Equal(t, applyBefore, applyAfter, "a stale revision must not reach the backend")

	_, current, err := ctrl.Config(testContext(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), current)
}

func TestCorruptConfigFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	backend := &fakeBackend{}
	ctrl := newTestController(t, path, backend)

	err := ctrl.Start(testContext(t))
	require.Error(t, err)

	init, recoverCalls, apply := backend.calls()
	assert.Zero(t, init)
	assert.Zero(t, recoverCalls)
	assert.Zero(t, apply, "a corrupt configuration must not reach the backend")

	status, statusErr := ctrl.Status(testContext(t))
	require.NoError(t, statusErr)
	assert.Equal(t, "invalid", status.Diagnostics["config"])
	assert.NotEmpty(t, status.Diagnostics["config.error"])

	_, _, configErr := ctrl.Config(testContext(t))
	require.Error(t, configErr)
}

func TestFailedApplyKeepsPreviousRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	ctrl := newTestController(t, path, backend)
	require.NoError(t, ctrl.Start(testContext(t)))

	first := testConfig()
	revision, err := ctrl.ApplyConfig(testContext(t), first, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), revision)

	backend.setApplyErr(errors.New("boom"))
	second := testConfig()
	second.SplitTunnel.Mode = config.ModeInclude
	second.SplitTunnel.Rules = nil
	_, err = ctrl.ApplyConfig(testContext(t), second, revision)
	require.ErrorIs(t, err, ErrApplyFailed)

	cfg, current, configErr := ctrl.Config(testContext(t))
	require.NoError(t, configErr)
	assert.Equal(t, uint64(1), current, "a failed apply must not advance the revision")
	require.NotNil(t, cfg)
	assert.Equal(t, config.ModeCustom, cfg.SplitTunnel.Mode)

	status, statusErr := ctrl.Status(testContext(t))
	require.NoError(t, statusErr)
	assert.Equal(t, "failed", status.Diagnostics["apply"])
	assert.True(t, status.Running, "the previous applied policy stays active after a failed apply")
}

func TestRollbackRestoresHistoryAsNewRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	ctrl := newTestController(t, path, backend)
	require.NoError(t, ctrl.Start(testContext(t)))

	first := testConfig()
	revision, err := ctrl.ApplyConfig(testContext(t), first, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), revision)

	second := testConfig()
	second.SplitTunnel.Mode = config.ModeInclude
	second.SplitTunnel.Rules = nil
	revision, err = ctrl.ApplyConfig(testContext(t), second, revision)
	require.NoError(t, err)
	require.Equal(t, uint64(2), revision)

	revision, err = ctrl.RollbackConfig(testContext(t), 1, revision)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), revision)

	cfg, current, err := ctrl.Config(testContext(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(3), current)
	require.NotNil(t, cfg)
	assert.Equal(t, config.ModeCustom, cfg.SplitTunnel.Mode, "rollback restores the older mode")

	_, err = ctrl.RollbackConfig(testContext(t), 1, 2)
	require.ErrorIs(t, err, api.ErrRevisionConflict)

	_, err = ctrl.RollbackConfig(testContext(t), 99, revision)
	require.ErrorIs(t, err, ErrRevisionNotFound)
}

func TestBackendInitializationFailureIsReportedThroughStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	stored := newStore(path)
	require.NoError(t, stored.save(document{
		SchemaVersion: storeSchemaVersion,
		Revision:      1,
		Config:        testConfig(),
	}))

	backend := &fakeBackend{initErr: errors.New("nftables unavailable")}
	ctrl := newTestController(t, path, backend)

	err := ctrl.Start(testContext(t))
	require.Error(t, err)

	status, statusErr := ctrl.Status(testContext(t))
	require.NoError(t, statusErr)
	assert.False(t, status.Running)
	assert.Equal(t, "initialize_failed", status.Diagnostics["backend"])
	assert.Contains(t, status.Diagnostics["backend.error"], "nftables unavailable")

	cfg, revision, configErr := ctrl.Config(testContext(t))
	require.NoError(t, configErr, "the persisted configuration stays readable")
	assert.Equal(t, uint64(1), revision)
	require.NotNil(t, cfg)
}

func TestGlobalKillSwitchRequiresTransportWiring(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	ctrl := New(path, Options{
		Backend: backend,
		Runtime: func(context.Context) (Wiring, error) { return Wiring{}, nil },
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	cfg := testConfig()
	cfg.SplitTunnel.KillSwitch = config.KillSwitchGlobal
	_, err := ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.Error(t, err)

	var fieldErr *config.FieldError
	require.ErrorAs(t, err, &fieldErr)
	assert.Contains(t, fieldErr.Path, "killSwitch")

	_, _, apply := backend.calls()
	assert.Zero(t, apply, "an unsafe kill switch must not reach the backend")

	ctrl = New(path, Options{
		Backend: &fakeBackend{},
		Runtime: func(context.Context) (Wiring, error) {
			return Wiring{TransportConfigured: true}, nil
		},
	})
	require.NoError(t, ctrl.Start(testContext(t)))
	_, err = ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.NoError(t, err)
}

func TestStopEmergencyResetsAndClosesBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	ctrl := newTestController(t, path, backend)
	require.NoError(t, ctrl.Start(testContext(t)))
	_, err := ctrl.ApplyConfig(testContext(t), testConfig(), 0)
	require.NoError(t, err)

	require.NoError(t, ctrl.Stop(testContext(t)))
	assert.Equal(t, 1, backend.emergencyCalls)
	assert.Equal(t, 1, backend.closeCalls)

	status, statusErr := ctrl.Status(testContext(t))
	require.NoError(t, statusErr)
	assert.False(t, status.Running)
}

func TestBackendUnavailableKeepsConfigReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	stored := newStore(path)
	require.NoError(t, stored.save(document{
		SchemaVersion: storeSchemaVersion,
		Revision:      1,
		Config:        testConfig(),
	}))

	ctrl := New(path, Options{Runtime: testWiring})
	require.ErrorIs(t, ctrl.Start(testContext(t)), api.ErrBackendUnavailable)

	_, err := ctrl.ApplyConfig(testContext(t), testConfig(), 1)
	require.ErrorIs(t, err, api.ErrBackendUnavailable)

	cfg, revision, err := ctrl.Config(testContext(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), revision)
	require.NotNil(t, cfg)
}

func TestDisablingDoesNotRequireNetworkRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	stored := newStore(path)
	require.NoError(t, stored.save(document{
		SchemaVersion: storeSchemaVersion,
		Revision:      1,
		Config:        testConfig(),
	}))

	backend := &fakeBackend{}
	ctrl := New(path, Options{
		Backend: backend,
		Runtime: func(context.Context) (Wiring, error) {
			return Wiring{}, errors.New("network engine is not running")
		},
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	disabled := testConfig()
	disabled.SplitTunnel.Enabled = false
	revision, err := ctrl.ApplyConfig(testContext(t), disabled, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), revision)
	assert.False(t, disabled.SplitTunnel.Enabled)
}
