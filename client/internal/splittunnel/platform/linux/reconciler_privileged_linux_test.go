//go:build linux && !android && privileged

package linux

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func startPolicyReconciler(t *testing.T, b *Backend) *Reconciler {
	t.Helper()

	reconciler := newReconciler(NewMonitor(), b, 20*time.Millisecond, 20*time.Millisecond, 0)
	require.NoError(t, reconciler.Start(context.Background()))
	t.Cleanup(reconciler.Stop)

	waitForCondition(t, func() bool { return reconciler.Reconciles() >= 1 },
		"the initial reconciler apply")
	return reconciler
}

func waitForReconcileAfter(t *testing.T, reconciler *Reconciler, before uint64) {
	t.Helper()

	waitForCondition(t, func() bool { return reconciler.Reconciles() > before },
		"the reconciler to handle a netlink change")
}

func exitTableRoutes(t *testing.T, b *Backend, family routeFamily) []netlink.Route {
	t.Helper()

	table := b.allocations.byClass[classExit].table
	routes, err := netlink.RouteListFiltered(family.netlinkFamily(),
		&netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	return routes
}

func waitForExitDefaultType(t *testing.T, b *Backend, family routeFamily, wantType int) {
	t.Helper()

	waitForCondition(t, func() bool {
		routes := exitTableRoutes(t, b, family)
		for i := range routes {
			if isDefaultRoute(&routes[i]) && normalizeRouteType(routes[i].Type) == wantType {
				return true
			}
		}
		return false
	}, "the exit default route type to change")
}

func waitForExitGateway(t *testing.T, b *Backend, gateway netip.Addr) {
	t.Helper()

	waitForCondition(t, func() bool {
		for _, route := range exitTableRoutes(t, b, routeFamily4) {
			if !isDefaultRoute(&route) || normalizeRouteType(route.Type) != unix.RTN_UNICAST {
				continue
			}
			if route.Gw != nil && route.Gw.Equal(gateway.AsSlice()) {
				return true
			}
		}
		return false
	}, "the exit gateway to be reconciled")
}

func TestReconcilerExitNodeLifecycleInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	reconciler := startPolicyReconciler(t, b)

	t.Run("initial exit path works", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)
	})

	t.Run("link down fails closed and leaves no leak", func(t *testing.T) {
		exitLink, err := netlink.LinkByName(names.exit)
		require.NoError(t, err)
		beforeReconcile := reconciler.Reconciles()
		require.NoError(t, netlink.LinkSetDown(exitLink))
		waitForReconcileAfter(t, reconciler, beforeReconcile)
		waitForExitDefaultType(t, b, routeFamily4, unix.RTN_UNREACHABLE)

		before := counters(t, names)
		requireUnreachable(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.direct, after.direct,
			"protected traffic must not fall through to the physical default")
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("link up recovers the exit path", func(t *testing.T) {
		exitLink, err := netlink.LinkByName(names.exit)
		require.NoError(t, err)
		beforeReconcile := reconciler.Reconciles()
		require.NoError(t, netlink.LinkSetUp(exitLink))
		waitForReconcileAfter(t, reconciler, beforeReconcile)
		waitForExitDefaultType(t, b, routeFamily4, unix.RTN_UNICAST)

		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)
	})
}

func TestReconcilerRecoversFromSourceSelectionChange(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	reconciler := startPolicyReconciler(t, b)

	before := counters(t, names)
	require.NoError(t, sendUDP("10.9.1.1", 9999))
	after := counters(t, names)
	require.Equal(t, before.exit+1, after.exit, "the exit path must work before the change")

	exitLink, err := netlink.LinkByName(names.exit)
	require.NoError(t, err)
	oldAddr, err := netlink.ParseAddr("10.0.2.1/24")
	require.NoError(t, err)
	newAddr, err := netlink.ParseAddr("10.0.2.9/24")
	require.NoError(t, err)
	beforeReconcile := reconciler.Reconciles()
	require.NoError(t, netlink.AddrDel(exitLink, oldAddr))
	require.NoError(t, netlink.AddrAdd(exitLink, newAddr))

	waitForReconcileAfter(t, reconciler, beforeReconcile)
	waitForExitDefaultType(t, b, routeFamily4, unix.RTN_UNICAST)

	before = counters(t, names)
	require.NoError(t, sendUDP("10.9.1.1", 9999),
		"the exit path must recover with the current interface address as source")
	after = counters(t, names)
	assert.Equal(t, before.exit+1, after.exit)
	assert.Equal(t, before.direct, after.direct)
}

func TestReconcilerReappliesGatewayChange(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)
	gateway := netip.MustParseAddr("10.0.2.2")
	options.ExitNode.Target.Gateway = gateway
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	startPolicyReconciler(t, b)

	exitLink, err := netlink.LinkByName(names.exit)
	require.NoError(t, err)
	table := b.allocations.byClass[classExit].table
	require.NoError(t, netlink.RouteReplace(&netlink.Route{
		Type:      unix.RTN_UNICAST,
		Family:    netlink.FAMILY_V4,
		Table:     int(table),
		Dst:       defaultRouteDestinationFor(routeFamily4),
		LinkIndex: exitLink.Attrs().Index,
		Gw:        net.ParseIP("10.0.2.254"),
		Priority:  protectedPrimaryMetric,
		Scope:     netlink.SCOPE_UNIVERSE,
	}))

	waitForExitGateway(t, b, gateway)
}

func TestReconcilerIPv6ExitLifecycleFailsClosed(t *testing.T) {
	requirePrivilegedIPv6(t)

	names := createIPv6TestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m05IPv6Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	reconciler := startPolicyReconciler(t, b)

	t.Run("initial IPv6 exit path works", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:1::1", 9999))
		after := ipv6Counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)
	})

	t.Run("IPv6 link down fails closed", func(t *testing.T) {
		exitLink, err := netlink.LinkByName(names.exit)
		require.NoError(t, err)
		beforeReconcile := reconciler.Reconciles()
		require.NoError(t, netlink.LinkSetDown(exitLink))
		waitForReconcileAfter(t, reconciler, beforeReconcile)
		waitForExitDefaultType(t, b, routeFamily6, unix.RTN_UNREACHABLE)

		before := ipv6Counters(t, names)
		requireUnreachable(t, sendUDP6("fd00:9:1::1", 9999))
		after := ipv6Counters(t, names)
		assert.Equal(t, before.direct, after.direct,
			"protected IPv6 must not fall through to the physical default")
		assert.Equal(t, before.exit, after.exit)
	})

	t.Run("IPv6 link up recovers", func(t *testing.T) {
		exitLink, err := netlink.LinkByName(names.exit)
		require.NoError(t, err)
		beforeReconcile := reconciler.Reconciles()
		require.NoError(t, netlink.LinkSetUp(exitLink))
		waitForReconcileAfter(t, reconciler, beforeReconcile)
		waitForExitDefaultType(t, b, routeFamily6, unix.RTN_UNICAST)

		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:1::1", 9999))
		after := ipv6Counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)
	})
}

func TestReconcilerRollbackLeavesUpstreamMainRoutes(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	reconciler := startPolicyReconciler(t, b)
	reconciler.Stop()

	require.NoError(t, b.Rollback(context.Background()))

	mainRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: 254}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	require.NotEmpty(t, mainRoutes, "rollback must leave the upstream main table intact")
	mainDefault := false
	for i := range mainRoutes {
		if isDefaultRoute(&mainRoutes[i]) {
			mainDefault = true
		}
	}
	assert.True(t, mainDefault, "the physical default must remain")

	allocations := newAllocationsMust(t)
	for _, class := range splitClasses {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
			&netlink.Route{Table: int(allocations.byClass[class].table)},
			netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		assert.Empty(t, routes, "rollback must remove the %s split routes", class)
	}

	time.Sleep(100 * time.Millisecond)
	for _, class := range splitClasses {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
			&netlink.Route{Table: int(allocations.byClass[class].table)},
			netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		assert.Empty(t, routes, "a stopped reconciler must not restore split routes")
	}
}
