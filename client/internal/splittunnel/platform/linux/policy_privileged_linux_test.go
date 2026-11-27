//go:build linux && !android && privileged

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
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

type testInterfaces struct {
	direct string
	exit   string
	vpn    string
}

func requirePrivilegedNetwork(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}
}

func createTestInterfaces(t *testing.T) testInterfaces {
	t.Helper()

	suffix := fmt.Sprintf("m04_%d", os.Getpid())
	names := testInterfaces{
		direct: "nsd" + suffix,
		exit:   "nse" + suffix,
		vpn:    "nsv" + suffix,
	}

	direct := createDummy(t, names.direct, "10.0.1.1/24")
	createDummy(t, names.exit, "10.0.2.1/24")
	createDummy(t, names.vpn, "10.0.3.1/24")

	// Emulate the physical default a real host has. Without it a connected UDP
	// socket cannot resolve a route before the output hook reclassifies the
	// packet, so the test would never exercise the split path.
	require.NoError(t, netlink.RouteReplace(&netlink.Route{
		LinkIndex: direct.Attrs().Index,
		Dst:       defaultRouteDestinationFor(routeFamily4),
		Scope:     netlink.SCOPE_LINK,
	}))

	t.Cleanup(func() {
		for _, name := range []string{names.direct, names.exit, names.vpn} {
			if link, err := netlink.LinkByName(name); err == nil {
				_ = netlink.LinkDel(link)
			}
		}
	})
	return names
}

func createDummy(t *testing.T, name, address string) netlink.Link {
	t.Helper()

	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name},
	}))
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)

	// Disable IPv6 before bringing the link up so neighbor discovery does not
	// perturb the TX counters this test uses as its egress sink.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("1"), 0o644)

	require.NoError(t, netlink.LinkSetUp(link))
	addr, err := netlink.ParseAddr(address)
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(link, addr))
	return link
}

func startM04Backend(t *testing.T) *Backend {
	t.Helper()

	table := fmt.Sprintf("netbird_split_m04_%d", os.Getpid())
	b := newBackendWith(
		systemProber{},
		func(table string) (nftManager, error) {
			return newNFTablesManager(table)
		},
		newNetlinkRouter(),
		table,
	)
	require.NoError(t, b.Initialize(context.Background()))
	t.Cleanup(func() {
		assert.NoError(t, b.Close(context.Background()))
	})
	return b
}

func m04Policy(t *testing.T, names testInterfaces) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{
				{
					ID:         "exit",
					Name:       "exit",
					Enabled:    true,
					Priority:   10,
					MatchMode:  config.MatchAll,
					Action:     config.ActionExitNode,
					ExitNodeID: "exit-1",
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.9.1.0/24"),
					}},
				},
				{
					ID:        "block",
					Name:      "block",
					Enabled:   true,
					Priority:  20,
					MatchMode: config.MatchAll,
					Action:    config.ActionBlock,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.9.2.0/24"),
					}},
				},
				{
					ID:        "vpn",
					Name:      "vpn",
					Enabled:   true,
					Priority:  30,
					MatchMode: config.MatchAll,
					Action:    config.ActionVPN,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.9.3.0/24"),
					}},
				},
				{
					ID:        "direct",
					Name:      "direct",
					Enabled:   true,
					Priority:  40,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.9.4.0/24"),
					}},
				},
				{
					ID:        "vpn-udp",
					Name:      "vpn-udp",
					Enabled:   true,
					Priority:  5,
					MatchMode: config.MatchAll,
					Action:    config.ActionVPN,
					Conditions: []config.Condition{
						{
							Type:   config.ConditionCIDR,
							Prefix: netip.MustParsePrefix("10.9.6.0/24"),
						},
						{
							Type:     config.ConditionProtocolPort,
							Protocol: config.ProtocolUDP,
							Port:     5353,
						},
					},
				},
			},
		},
	}

	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)

	options := backend.PolicyOptions{
		VPN: backend.RouteTarget{
			Interface: names.vpn,
			Source:    netip.MustParseAddr("10.0.3.1"),
		},
		Direct: backend.RouteTarget{
			Interface: names.direct,
			Source:    netip.MustParseAddr("10.0.1.1"),
		},
		ExitNode: &backend.ExitNode{
			ID: "exit-1",
			Target: backend.RouteTarget{
				Interface: names.exit,
				Source:    netip.MustParseAddr("10.0.2.1"),
			},
		},
	}
	return compiled, options
}

func sendUDP(destination string, port int) error {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP(destination),
		Port: port,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte("split-tunnel-m04"))
	return err
}

func requireUnreachable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH),
		"expected an unreachable error, got %v", err)
}

func txPackets(t *testing.T, name string) uint64 {
	t.Helper()

	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	require.NotNil(t, link.Attrs().Statistics)
	return link.Attrs().Statistics.TxPackets
}

type interfaceCounters struct {
	direct uint64
	exit   uint64
	vpn    uint64
}

func counters(t *testing.T, names testInterfaces) interfaceCounters {
	t.Helper()
	return interfaceCounters{
		direct: txPackets(t, names.direct),
		exit:   txPackets(t, names.exit),
		vpn:    txPackets(t, names.vpn),
	}
}

func TestIPv4PolicyEgressInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	t.Run("exit node carries selected traffic", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("direct rule uses the physical path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.4.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct+1, after.direct)
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("unmatched traffic uses the direct default", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.5.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct+1, after.direct)
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("vpn rule uses the overlay path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.3.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.vpn+1, after.vpn)
		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.exit, after.exit)
	})

	t.Run("protocol port condition is enforced", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.6.1", 5353))
		after := counters(t, names)

		assert.Equal(t, before.vpn+1, after.vpn)
		assert.Equal(t, before.direct, after.direct)

		before = counters(t, names)
		require.NoError(t, sendUDP("10.9.6.1", 5354))
		after = counters(t, names)

		assert.Equal(t, before.direct+1, after.direct,
			"a different UDP port must fall through to the direct default")
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("block drops without leaving the host", func(t *testing.T) {
		before := counters(t, names)
		err := sendUDP("10.9.2.1", 9999)
		requireUnreachable(t, err)
		after := counters(t, names)

		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})
}

func TestIPv4PolicyMissingProtectedRouteFailsClosed(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)

	options.VPN.Interface = names.vpn + "_missing"
	options.ExitNode.Target.Interface = names.exit + "_missing"

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	t.Run("exit traffic cannot fall through", func(t *testing.T) {
		before := counters(t, names)
		requireUnreachable(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct, after.direct,
			"the physical default must not receive protected exit traffic")
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("vpn traffic cannot fall through", func(t *testing.T) {
		before := counters(t, names)
		requireUnreachable(t, sendUDP("10.9.3.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct, after.direct,
			"the physical default must not receive protected VPN traffic")
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("protocol-selected protected traffic cannot fall through", func(t *testing.T) {
		before := counters(t, names)
		requireUnreachable(t, sendUDP("10.9.6.1", 5353))
		after := counters(t, names)

		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("direct traffic still reaches the physical path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.4.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct+1, after.direct)
	})
}

func TestIPv4PolicyRollbackRemovesOnlyPolicyState(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)

	tableName := fmt.Sprintf("netbird_split_m04_%d", os.Getpid())
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	table := requireInetTable(t, tableName)

	require.NoError(t, b.Rollback(context.Background()))

	assert.NotNil(t, findInetTable(t, tableName), "rollback must keep the baseline table")
	assert.Len(t, chainsInTable(t, tableName), 4, "rollback must keep the baseline chains")
	assert.Len(t, setsInTable(t, table), len(setSpecs()), "rollback must keep the baseline sets")

	conn := &nftables.Conn{}
	classify := &nftables.Chain{Name: string(chainClassifyOutput), Table: table}
	rules, err := conn.GetRules(table, classify)
	require.NoError(t, err)
	assert.Empty(t, rules, "rollback must remove classification rules")

	policyRules, err := netlink.RuleList(netlink.FAMILY_V4)
	require.NoError(t, err)
	for _, rule := range policyRules {
		for _, class := range splitClasses {
			assert.NotEqual(t, int(newAllocationsMust(t).byClass[class].priority), rule.Priority,
				"rollback must remove split policy rules")
		}
	}

	allocations := newAllocationsMust(t)
	for _, class := range splitClasses {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
			&netlink.Route{Table: int(allocations.byClass[class].table)},
			netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		assert.Empty(t, routes, "rollback must remove %s routes", class)
	}

	mainRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: 254}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	require.NotEmpty(t, mainRoutes, "rollback must leave the upstream main table intact")
	assert.True(t, isDefaultRoute(&mainRoutes[0]), "the physical default must remain")
}

func newAllocationsMust(t *testing.T) allocations {
	t.Helper()
	allocations, err := newAllocations()
	require.NoError(t, err)
	return allocations
}

func TestIPv4PolicyTargetLossFailsClosed(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m04Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	require.NoError(t, sendUDP("10.9.1.1", 9999),
		"the exit path must work before the link is lost")

	exitLink, err := netlink.LinkByName(names.exit)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetDown(exitLink))

	before := counters(t, names)
	requireUnreachable(t, sendUDP("10.9.1.1", 9999))
	after := counters(t, names)

	assert.Equal(t, before.direct, after.direct,
		"losing the exit link must not fall back to the physical default")
	assert.Equal(t, before.exit, after.exit)
	assert.Equal(t, before.vpn, after.vpn)
}
