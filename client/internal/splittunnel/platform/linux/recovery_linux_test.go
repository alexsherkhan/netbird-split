//go:build linux && !android

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func testJournalEntry(t *testing.T) journalEntry {
	t.Helper()

	allocations := testAllocations(t)
	guard := &journalGuard{
		Control4: []string{"10.8.0.0/16"},
		Rules: []journalKillRule{{
			Family:  uint8(family4),
			Verdict: uint8(verdictDrop),
		}},
	}
	return journalEntry{
		SchemaVersion: journalSchemaVersion,
		State:         JournalStateValidated,
		Revision:      1,
		PolicyID:      "policy-a",
		Mode:          string(config.KillSwitchGlobal),
		Guard:         guard,
		Ownership: ownershipFrom(allocations, backend.OwnedObjects{
			Table:  "netbird_split_test",
			Chains: []string{"classify_output"},
			Sets:   []string{"vpn4"},
		}),
		UpdatedAt: time.Now().UTC(),
	}
}

func TestJournalStateTransitions(t *testing.T) {
	tests := []struct {
		from JournalState
		to   JournalState
		ok   bool
	}{
		{JournalStateValidated, JournalStatePreArmed, true},
		{JournalStateValidated, JournalStateStaged, false},
		{JournalStateValidated, JournalStateRolledBack, true},
		{JournalStatePreArmed, JournalStateStaged, true},
		{JournalStatePreArmed, JournalStateVerified, false},
		{JournalStatePreArmed, JournalStateRolledBack, true},
		{JournalStateStaged, JournalStateVerified, true},
		{JournalStateStaged, JournalStateCommitted, false},
		{JournalStateStaged, JournalStateRolledBack, true},
		{JournalStateVerified, JournalStateCommitted, true},
		{JournalStateVerified, JournalStatePreArmed, false},
		{JournalStateVerified, JournalStateRolledBack, true},
		{JournalStateCommitted, JournalStateValidated, true},
		{JournalStateCommitted, JournalStateStaged, false},
		{JournalStateCommitted, JournalStateRolledBack, true},
		{JournalStateRolledBack, JournalStateValidated, true},
		{JournalStateRolledBack, JournalStateCommitted, true},
		{JournalStateRolledBack, JournalStateStaged, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.from)+"->"+string(tt.to), func(t *testing.T) {
			entry := journalEntry{State: tt.from}
			err := entry.transition(tt.to)
			if !tt.ok {
				require.ErrorIs(t, err, ErrInvalidJournalTransition)
				assert.Equal(t, tt.from, entry.State, "a rejected transition must not change the state")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.to, entry.State)
			assert.False(t, entry.UpdatedAt.IsZero())
		})
	}
}

func TestJournalStateValid(t *testing.T) {
	for _, state := range []JournalState{
		JournalStateValidated, JournalStatePreArmed, JournalStateStaged,
		JournalStateVerified, JournalStateCommitted, JournalStateRolledBack,
	} {
		assert.True(t, state.Valid(), "%q must be valid", state)
	}
	assert.False(t, JournalState("unknown").Valid())
}

func TestFileJournalAtomicReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	journal := newFileJournal(path)

	first := testJournalEntry(t)
	first.Revision = 1
	require.NoError(t, journal.Save(first))

	loaded, err := journal.Load()
	require.NoError(t, err)
	assert.Equal(t, first.Revision, loaded.Revision)

	second := first
	second.Revision = 2
	second.State = JournalStateCommitted
	require.NoError(t, journal.Save(second))

	loaded, err = journal.Load()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), loaded.Revision)
	assert.Equal(t, JournalStateCommitted, loaded.State)

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "an atomic replace must not leave a temporary file")
}

func TestFileJournalPreservesPreviousEntryWhenReplaceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	journal := newFileJournal(path)
	first := testJournalEntry(t)
	first.Revision = 4
	require.NoError(t, journal.Save(first))

	journal.rename = func(string, string) error { return errors.New("rename failed") }
	second := first
	second.Revision = 5
	err := journal.Save(second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rename failed")

	loaded, loadErr := journal.Load()
	require.NoError(t, loadErr)
	assert.Equal(t, uint64(4), loaded.Revision,
		"a failed replace must leave the previous complete journal")
}

func TestFileJournalRejectsCorruptOrTruncatedEntries(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "empty", data: ""},
		{name: "truncated", data: `{"schema_version":1,"state":"committed"`},
		{name: "invalid json", data: `{`},
		{name: "wrong schema", data: `{"schema_version":99,"state":"committed","ownership":{"table":"netbird_split"}}`},
		{name: "unknown state", data: `{"schema_version":1,"state":"nonsense","ownership":{"table":"netbird_split"}}`},
		{name: "missing table", data: `{"schema_version":1,"state":"committed","ownership":{}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.data), 0o600))

			_, err := newFileJournal(path).Load()
			require.ErrorIs(t, err, ErrJournalCorrupt)
		})
	}
}

func TestFileJournalClearIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	journal := newFileJournal(path)
	require.NoError(t, journal.Save(testJournalEntry(t)))

	require.NoError(t, journal.Clear())
	_, err := journal.Load()
	require.ErrorIs(t, err, ErrJournalNotFound)
	require.NoError(t, journal.Clear())
}

func newRecoveryBackend(
	t *testing.T,
	journal journalStore,
) (*Backend, *fakeManager, *fakeRouter) {
	t.Helper()

	probe := &fakeProber{capabilities: availableCapabilities()}
	manager := &fakeManager{
		createdTable: true,
		owned:        defaultOwned(),
		inspect:      nftObservation{TablePresent: true},
	}
	router := &fakeRouter{}
	open := func(string) (nftManager, error) { return manager, nil }
	b := newBackendWithJournal(probe, open, router, "netbird_split_test", journal)
	require.NoError(t, b.Initialize(context.Background()))
	return b, manager, router
}

func recoveryPolicy(t *testing.T, vpnInterface string, mode config.KillSwitchMode) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	cfg := includeConfig(testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")))
	cfg.SplitTunnel.KillSwitch = mode
	compiled, err := policy.CompileWith(cfg, policy.Constraints{
		ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
	})
	require.NoError(t, err)

	options := testOptions()
	options.VPN.Interface = vpnInterface
	return compiled, options
}

func TestRecoverRevisionMismatchLeavesCommittedState(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, _ := newRecoveryBackend(t, journal)

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchGlobal)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	applied := manager.applyCalls

	_, err := b.Recover(context.Background(), &RecoveryIntent{
		Revision: 99,
		Compiled: compiled,
		Options:  options,
	})
	require.ErrorIs(t, err, ErrRevisionMismatch)
	assert.Equal(t, applied, manager.applyCalls,
		"a revision mismatch must not replace the committed state")

	entry, loadErr := journal.Load()
	require.NoError(t, loadErr)
	assert.Equal(t, JournalStateCommitted, entry.State)
}

func TestRecoverReappliesCommittedIntentAndIsIdempotent(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, _ := newRecoveryBackend(t, journal)

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchGlobal)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	applied := manager.applyCalls

	entry, err := journal.Load()
	require.NoError(t, err)

	changed := options
	changed.VPN.Interface = "wt1"
	report, err := b.Recover(context.Background(), &RecoveryIntent{
		Revision: entry.Revision,
		Compiled: compiled,
		Options:  changed,
	})
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionReapplied, report.Action)
	assert.Equal(t, applied+1, manager.applyCalls)

	report, err = b.Recover(context.Background(), &RecoveryIntent{
		Compiled: compiled,
		Options:  changed,
	})
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionVerified, report.Action)
	assert.Equal(t, applied+1, manager.applyCalls,
		"a recovery with an already matching kernel state must not apply again")
}

func TestRecoverCommittedWithoutIntentVerifiesAndRestoresGuard(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, _ := newRecoveryBackend(t, journal)

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchGlobal)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	manager.inspect = nftObservation{TablePresent: true}

	report, err := b.Recover(context.Background(), nil)
	require.ErrorIs(t, err, ErrRecoveryIntentRequired)
	assert.Equal(t, RecoveryActionVerified, report.Action)
	assert.NotEmpty(t, report.Issues)
}

func TestRecoverInterruptedRollsBackAndIsIdempotent(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, router := newRecoveryBackend(t, journal)

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchGlobal)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	b.applyHook = func(phase applyPhase) error {
		if phase == applyPhaseStaged {
			return errSimulatedCrash
		}
		return nil
	}
	changed := options
	changed.VPN.Interface = "wt1"
	require.ErrorIs(t, b.ApplyPolicy(context.Background(), compiled, changed), errSimulatedCrash)
	b.applyHook = nil

	entry, err := journal.Load()
	require.NoError(t, err)
	assert.Equal(t, JournalStateStaged, entry.State)

	recovered, manager2, router2 := newRecoveryBackend(t, journal)
	report, err := recovered.Recover(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionRolledBack, report.Action)
	assert.Equal(t, JournalStateRolledBack, report.JournalState)
	assert.Equal(t, 1, manager2.clearCalls)
	assert.Equal(t, 1, router2.removeCalls)
	assert.NotEmpty(t, report.Issues)

	clearBefore := manager2.clearCalls
	removeBefore := router2.removeCalls
	report, err = recovered.Recover(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionRolledBack, report.Action)
	assert.Equal(t, clearBefore, manager2.clearCalls,
		"an already rolled back journal must not clear policy again")
	assert.Equal(t, removeBefore, router2.removeCalls,
		"an already rolled back journal must not remove routes again")

	entry, err = journal.Load()
	require.NoError(t, err)
	assert.Equal(t, JournalStateRolledBack, entry.State)

	_ = manager
	_ = router
}

func TestRecoverCrashAfterCommitKeepsCommittedIntent(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, _ := newRecoveryBackend(t, journal)

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchGlobal)
	b.applyHook = func(phase applyPhase) error {
		if phase == applyPhaseCommitted {
			return errSimulatedCrash
		}
		return nil
	}
	require.ErrorIs(t, b.ApplyPolicy(context.Background(), compiled, options), errSimulatedCrash)

	entry, err := journal.Load()
	require.NoError(t, err)
	assert.Equal(t, JournalStateCommitted, entry.State)

	recovered, manager2, _ := newRecoveryBackend(t, journal)
	applied := manager2.applyCalls
	report, err := recovered.Recover(context.Background(), &RecoveryIntent{
		Revision: entry.Revision,
		Compiled: compiled,
		Options:  options,
	})
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionVerified, report.Action)
	assert.Equal(t, applied, manager2.applyCalls)
	_ = manager
}

func TestRecoverWithoutJournalCleansOrphanedOwnedState(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, router := newRecoveryBackend(t, journal)

	report, err := b.Recover(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionCleaned, report.Action)
	assert.Equal(t, 1, manager.cleanupCalls)
	assert.Equal(t, 1, router.removeCalls)

	manager.inspect = nftObservation{}
	report, err = b.Recover(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionNone, report.Action)
	assert.Equal(t, 1, manager.cleanupCalls)
}

func TestRecoverLeavesForeignObjectsUntouched(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, router := newRecoveryBackend(t, journal)
	manager.inspectErr = backend.ErrForeignObject

	_, err := b.Recover(context.Background(), nil)
	require.ErrorIs(t, err, backend.ErrForeignObject)
	assert.Zero(t, manager.cleanupCalls, "a foreign object must stop cleanup")
	assert.Zero(t, router.removeCalls)
}

type flakyManager struct {
	*fakeManager
	cleanupFailures int
	verifyFailures  int
}

func (f *flakyManager) Cleanup(ctx context.Context) error {
	f.cleanupCalls++
	if f.cleanupFailures > 0 {
		f.cleanupFailures--
		return errors.New("transient cleanup failure")
	}
	return nil
}

func (f *flakyManager) VerifyPolicy(ctx context.Context, policy nftPolicy) error {
	f.verifyCalls++
	if f.verifyFailures > 0 {
		f.verifyFailures--
		return errors.New("transient verify failure")
	}
	return nil
}

func TestRecoverRetriesTransientFailureWithinBound(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	manager := &fakeManager{
		createdTable: true,
		owned:        defaultOwned(),
		inspect:      nftObservation{TablePresent: true},
	}
	flaky := &flakyManager{fakeManager: manager, cleanupFailures: 2}
	router := &fakeRouter{}
	probe := &fakeProber{capabilities: availableCapabilities()}
	b := newBackendWithJournal(probe,
		func(string) (nftManager, error) { return flaky, nil },
		router, "netbird_split_test", journal)
	b.retryAttempts = 3
	b.retryDelay = 0
	require.NoError(t, b.Initialize(context.Background()))

	report, err := b.Recover(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionCleaned, report.Action)
	assert.Equal(t, 3, flaky.cleanupCalls, "two transient failures must be retried")
}

func TestRecoverStopsAtTheRetryBound(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	manager := &fakeManager{
		createdTable: true,
		owned:        defaultOwned(),
		inspect:      nftObservation{TablePresent: true},
	}
	flaky := &flakyManager{fakeManager: manager, cleanupFailures: 99}
	router := &fakeRouter{}
	probe := &fakeProber{capabilities: availableCapabilities()}
	b := newBackendWithJournal(probe,
		func(string) (nftManager, error) { return flaky, nil },
		router, "netbird_split_test", journal)
	b.retryAttempts = 4
	b.retryDelay = time.Nanosecond
	sleeps := 0
	b.sleep = func(context.Context, time.Duration) error {
		sleeps++
		return nil
	}
	require.NoError(t, b.Initialize(context.Background()))

	_, err := b.Recover(context.Background(), nil)
	require.Error(t, err)
	assert.Equal(t, 4, flaky.cleanupCalls, "recovery must not busy-loop")
	assert.Equal(t, 3, sleeps)
}

func TestApplyPolicyVerificationFailureRollsBack(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, router := newRecoveryBackend(t, journal)
	manager.verifyErr = errors.New("kernel state mismatch")

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchGlobal)
	err := b.ApplyPolicy(context.Background(), compiled, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kernel state mismatch")
	assert.Equal(t, 1, manager.applyCalls)
	assert.GreaterOrEqual(t, manager.clearCalls, 1,
		"a failed verification must remove the staged policy")
	assert.GreaterOrEqual(t, router.removeCalls, 1)

	_, loadErr := journal.Load()
	require.ErrorIs(t, loadErr, ErrJournalNotFound,
		"a first failed apply has no previous intent to keep")
	assert.False(t, b.policyApplied)
}

func TestApplyPolicyRollbackFailureInstallsFailClosedGuard(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, manager, router := newRecoveryBackend(t, journal)

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchGlobal)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	guardCalls := manager.killSwitchCalls

	manager.applyPolicyErr = errors.New("nftables install failed")
	router.applyErr = errors.New("route restore failed")
	router.applyFailFrom = 3
	changed := options
	changed.VPN.Interface = "wt1"
	err := b.ApplyPolicy(context.Background(), compiled, changed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nftables install failed")
	assert.Contains(t, err.Error(), "route restore failed")
	assert.Greater(t, manager.killSwitchCalls, guardCalls,
		"a failed rollback must install a fail-closed guard")

	diagnostics := b.RecoveryStatus()
	assert.True(t, diagnostics.RollbackFailed)
	assert.True(t, diagnostics.ProtectionPreserved)

	entry, loadErr := journal.Load()
	require.NoError(t, loadErr)
	assert.Equal(t, JournalStateRolledBack, entry.State)
}

func TestApplyPolicyRefusesInterruptedJournal(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	b, _, _ := newRecoveryBackend(t, journal)

	entry := testJournalEntry(t)
	entry.State = JournalStateStaged
	require.NoError(t, journal.Save(entry))

	compiled, options := recoveryPolicy(t, "wt0", config.KillSwitchDisabled)
	err := b.ApplyPolicy(context.Background(), compiled, options)
	require.ErrorIs(t, err, ErrRecoveryRequired)
}

func TestRecoverTruncatedJournalDoesNotMutateKernel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"schema_version":1`), 0o600))
	journal := newFileJournal(path)
	b, manager, router := newRecoveryBackend(t, journal)

	_, err := b.Recover(context.Background(), nil)
	require.ErrorIs(t, err, ErrJournalCorrupt)
	assert.Zero(t, manager.clearCalls)
	assert.Zero(t, manager.cleanupCalls)
	assert.Zero(t, router.removeCalls)
}

func TestJournalRoundTripPreservesIdentityAndInventory(t *testing.T) {
	journal := newFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	entry := testJournalEntry(t)
	entry.State = JournalStateCommitted
	entry.Previous = &journalSnapshot{Revision: 3, PolicyID: "previous"}
	require.NoError(t, journal.Save(entry))

	loaded, err := journal.Load()
	require.NoError(t, err)
	encoded, err := json.Marshal(loaded)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"policy_id":"policy-a"`)
	assert.Contains(t, string(encoded), `"mark_value"`)
	assert.NotContains(t, string(encoded), "/home/")
}
