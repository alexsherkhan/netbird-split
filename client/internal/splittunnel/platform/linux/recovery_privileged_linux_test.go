//go:build linux && !android && privileged

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func startM11Backend(t *testing.T, table, journalPath string, router routeManager) *Backend {
	t.Helper()

	if router == nil {
		router = newNetlinkRouter()
	}
	b := newBackendWithJournal(
		systemProber{},
		func(name string) (nftManager, error) { return newNFTablesManager(name) },
		router,
		table,
		newFileJournal(journalPath),
	)
	require.NoError(t, b.Initialize(context.Background()))
	return b
}

func m11Policy(t *testing.T, names testInterfaces) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	compiled, options := m04Policy(t, names)
	compiled.KillSwitch = config.KillSwitchGlobal
	return compiled, options
}

func m11Table(name string) string {
	return fmt.Sprintf("netbird_split_m11_%s_%d", name, os.Getpid())
}

func TestM11StagedApplyPreservesProtectionInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	table := m11Table("stage")
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	b := startM11Backend(t, table, journalPath, nil)
	t.Cleanup(func() {
		_ = b.Close(context.Background())
		removeTable(t, table)
	})

	compiled, options := m11Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	hookErr := errors.New("injected staged failure")
	var during interfaceCounters
	b.applyHook = func(phase applyPhase) error {
		if phase != applyPhaseStaged {
			return nil
		}
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.1.1", 9999))
		during = counters(t, names)
		assert.Equal(t, before.direct, during.direct,
			"protected traffic must not use the physical path during a staged apply")
		assert.Equal(t, before.exit+1, during.exit)
		return hookErr
	}

	err := b.ApplyPolicy(context.Background(), compiled, options)
	require.ErrorIs(t, err, hookErr)

	after := counters(t, names)
	require.NoError(t, sendUDP("10.9.1.1", 9999),
		"a failed staged apply must restore the previous protected path")
	final := counters(t, names)
	assert.Equal(t, after.exit+1, final.exit)
	assert.Equal(t, after.direct, final.direct)
}

type failingRestoreRouter struct {
	*netlinkRouter
	failFrom int
	err      error
	calls    int
}

func (f *failingRestoreRouter) Apply(ctx context.Context, plan routePlan) error {
	f.calls++
	if f.failFrom > 0 && f.calls >= f.failFrom {
		return f.err
	}
	return f.netlinkRouter.Apply(ctx, plan)
}

func TestM11VerificationAndRollbackFailureFailsClosedInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	table := m11Table("rollback")
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	router := &failingRestoreRouter{netlinkRouter: newNetlinkRouter()}
	b := startM11Backend(t, table, journalPath, router)
	t.Cleanup(func() {
		_ = b.Close(context.Background())
		removeTable(t, table)
	})

	compiled, options := m11Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	router.err = errors.New("route restore failed")
	router.failFrom = 3
	b.applyHook = func(phase applyPhase) error {
		if phase != applyPhaseApplied {
			return nil
		}
		tableID := b.allocations.byClass[classVPN].table
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
			&netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		deleted := false
		for i := range routes {
			if !isDefaultRoute(&routes[i]) {
				continue
			}
			require.NoError(t, netlink.RouteDel(&routes[i]))
			deleted = true
			break
		}
		require.True(t, deleted, "the VPN route must be present before verification")
		return nil
	}

	err := b.ApplyPolicy(context.Background(), compiled, options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy routing")
	assert.Contains(t, err.Error(), "route restore failed")

	diagnostics := b.RecoveryStatus()
	assert.True(t, diagnostics.RollbackFailed)
	assert.True(t, diagnostics.ProtectionPreserved)

	before := counters(t, names)
	requireBlocked(t, sendUDP("10.9.1.1", 9999))
	after := counters(t, names)
	assert.Equal(t, before.direct, after.direct,
		"a failed rollback must keep protection installed")
	assert.Equal(t, before.exit, after.exit)

	entry, loadErr := newFileJournal(journalPath).Load()
	require.NoError(t, loadErr)
	assert.Equal(t, JournalStateRolledBack, entry.State)
}

func TestM11StartupReconciliationRemovesOrphanedOwnedState(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	table := m11Table("orphan")
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	first := startM11Backend(t, table, journalPath, nil)
	t.Cleanup(func() { removeTable(t, table) })

	compiled, options := m11Policy(t, names)
	require.NoError(t, first.ApplyPolicy(context.Background(), compiled, options))
	require.NoError(t, os.Remove(journalPath))

	second := startM11Backend(t, table, journalPath, nil)
	report, err := second.Recover(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionCleaned, report.Action)
	assert.Nil(t, findInetTable(t, table), "orphaned owned objects must be removed")

	mainRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: 254}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	require.NotEmpty(t, mainRoutes, "recovery must leave the physical main table intact")
}

func TestM11RecoveryLeavesForeignObjectsInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	table := m11Table("foreign")
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	b := startM11Backend(t, table, journalPath, nil)
	t.Cleanup(func() {
		removeForeignChain(t, table, "intruder")
		_ = b.Close(context.Background())
		removeTable(t, table)
	})

	tableRef := requireInetTable(t, table)
	conn := &nftables.Conn{}
	conn.AddChain(&nftables.Chain{Name: "intruder", Table: tableRef})
	require.NoError(t, conn.Flush())

	_, err := b.Recover(context.Background(), nil)
	require.ErrorIs(t, err, backend.ErrForeignObject)
	assert.NotNil(t, findForeignChain(t, table, "intruder"),
		"recovery must leave a foreign chain untouched")
}

func removeForeignChain(t *testing.T, table, chain string) {
	t.Helper()

	tableRef := findInetTable(t, table)
	if tableRef == nil {
		return
	}
	conn := &nftables.Conn{}
	conn.DelChain(&nftables.Chain{Name: chain, Table: tableRef})
	_ = conn.Flush()
}

func findForeignChain(t *testing.T, table, chain string) *nftables.Chain {
	t.Helper()

	tableRef := findInetTable(t, table)
	if tableRef == nil {
		return nil
	}
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	require.NoError(t, err)
	for _, item := range chains {
		if item.Table != nil && item.Table.Name == table && item.Name == chain {
			return item
		}
	}
	return nil
}

func TestM11ApplyCrashHelper(t *testing.T) {
	phase := os.Getenv("NB_M11_CRASH_PHASE")
	if phase == "" {
		t.Skip("helper process only")
	}

	names := testInterfaces{
		direct: os.Getenv("NB_M11_DIRECT"),
		exit:   os.Getenv("NB_M11_EXIT"),
		vpn:    os.Getenv("NB_M11_VPN"),
	}
	b := startM11Backend(t, os.Getenv("NB_M11_TABLE"), os.Getenv("NB_M11_JOURNAL"), nil)
	compiled, options := m11Policy(t, names)
	b.applyHook = func(point applyPhase) error {
		if string(point) == phase {
			fmt.Fprintln(os.Stdout, "killing apply at", phase)
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	t.Fatalf("the helper did not crash at %s", phase)
}

func runM11CrashHelper(t *testing.T, phase, table, journal string, names testInterfaces) {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^TestM11ApplyCrashHelper$", "-test.timeout=120s")
	cmd.Env = append(os.Environ(),
		"NB_M11_CRASH_PHASE="+phase,
		"NB_M11_TABLE="+table,
		"NB_M11_JOURNAL="+journal,
		"NB_M11_DIRECT="+names.direct,
		"NB_M11_EXIT="+names.exit,
		"NB_M11_VPN="+names.vpn,
	)
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "helper output:\n%s", output)
	require.Equal(t, syscall.SIGKILL, exitErr.Sys().(syscall.WaitStatus).Signal(),
		"helper output:\n%s", output)
}

func TestM11CrashBeforeCommitRecoversFailClosedInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	table := m11Table("crashbefore")
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	b := startM11Backend(t, table, journalPath, nil)
	t.Cleanup(func() { removeTable(t, table) })

	compiled, options := m11Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	runM11CrashHelper(t, string(applyPhaseStaged), table, journalPath, names)

	recovered := startM11Backend(t, table, journalPath, nil)
	report, err := recovered.Recover(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionRolledBack, report.Action)
	assert.Equal(t, JournalStateRolledBack, report.JournalState)

	before := counters(t, names)
	requireBlocked(t, sendUDP("10.9.1.1", 9999))
	after := counters(t, names)
	assert.Equal(t, before.direct, after.direct,
		"recovered protected traffic must not reach the physical path")
	assert.Equal(t, before.exit, after.exit)
}

func TestM11CrashAfterCommitRecoversInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	table := m11Table("crashafter")
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	b := startM11Backend(t, table, journalPath, nil)
	t.Cleanup(func() { removeTable(t, table) })

	compiled, options := m11Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	runM11CrashHelper(t, string(applyPhaseCommitted), table, journalPath, names)

	entry, err := newFileJournal(journalPath).Load()
	require.NoError(t, err)
	require.Equal(t, JournalStateCommitted, entry.State)

	recovered := startM11Backend(t, table, journalPath, nil)
	report, err := recovered.Recover(context.Background(), &RecoveryIntent{
		Revision: entry.Revision,
		Compiled: compiled,
		Options:  options,
	})
	require.NoError(t, err)
	assert.Equal(t, RecoveryActionVerified, report.Action)

	before := counters(t, names)
	require.NoError(t, sendUDP("10.9.1.1", 9999),
		"a committed intent must be usable after recovery")
	after := counters(t, names)
	assert.Equal(t, before.exit+1, after.exit)
	assert.Equal(t, before.direct, after.direct)
}
