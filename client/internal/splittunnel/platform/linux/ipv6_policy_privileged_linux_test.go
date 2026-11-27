//go:build linux && !android && privileged

package linux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

type testIPv6Interfaces struct {
	direct string
	exit   string
	vpn    string
}

func requirePrivilegedIPv6(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}
	if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		t.Skipf("IPv6 is not available in this namespace: %v", err)
	}
}

func createIPv6TestInterfaces(t *testing.T) testIPv6Interfaces {
	t.Helper()

	suffix := fmt.Sprintf("m05_%d", os.Getpid())
	names := testIPv6Interfaces{
		direct: "n6d" + suffix,
		exit:   "n6e" + suffix,
		vpn:    "n6v" + suffix,
	}

	direct := createIPv6Dummy(t, names.direct, "10.20.1.1/24", "fd00:1::1/64")
	createIPv6Dummy(t, names.exit, "10.20.2.1/24", "fd00:2::1/64")
	createIPv6Dummy(t, names.vpn, "10.20.3.1/24", "fd00:3::1/64")

	// Emulate the physical defaults a real dual-stack host has. Without them
	// the connected socket cannot resolve a route before the output hook
	// reclassifies the packet.
	require.NoError(t, netlink.RouteReplace(&netlink.Route{
		LinkIndex: direct.Attrs().Index,
		Dst:       defaultRouteDestinationFor(routeFamily4),
		Scope:     netlink.SCOPE_LINK,
	}))
	require.NoError(t, netlink.RouteReplace(&netlink.Route{
		Family:    netlink.FAMILY_V6,
		LinkIndex: direct.Attrs().Index,
		Dst:       defaultRouteDestinationFor(routeFamily6),
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

func createIPv6Dummy(t *testing.T, name, ipv4, ipv6 string) netlink.Link {
	t.Helper()

	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name},
	}))
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)

	enableIPv6Interface(t, name)
	require.NoError(t, netlink.LinkSetUp(link))

	for _, address := range []string{ipv4, ipv6} {
		addr, err := netlink.ParseAddr(address)
		require.NoError(t, err)
		addr.Flags = unix.IFA_F_NODAD
		require.NoError(t, netlink.AddrAdd(link, addr))
	}
	return link
}

// enableIPv6Interface turns IPv6 on for one dummy and suppresses the
// neighbor-discovery chatter that would otherwise move the TX counters.
func enableIPv6Interface(t *testing.T, name string) {
	t.Helper()

	base := "/proc/sys/net/ipv6/conf/" + name + "/"
	if err := os.WriteFile(base+"disable_ipv6", []byte("0"), 0o644); err != nil {
		t.Skipf("enable IPv6 on %s: %v", name, err)
	}
	for _, setting := range []struct {
		key   string
		value string
	}{
		{"accept_ra", "0"},
		{"autoconf", "0"},
		{"dad_transmits", "0"},
		{"router_solicitations", "0"},
	} {
		_ = os.WriteFile(base+setting.key, []byte(setting.value), 0o644)
	}
}

func m05IPv6Policy(t *testing.T, names testIPv6Interfaces) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			IPv6:          true,
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
						Prefix: netip.MustParsePrefix("fd00:9:1::/64"),
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
						Prefix: netip.MustParsePrefix("fd00:9:2::/64"),
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
						Prefix: netip.MustParsePrefix("fd00:9:3::/64"),
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
						Prefix: netip.MustParsePrefix("fd00:9:4::/64"),
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
							Prefix: netip.MustParsePrefix("fd00:9:6::/64"),
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

	target6 := backend.RouteTarget6{
		Interface: names.exit,
		Source:    netip.MustParseAddr("fd00:2::1"),
	}
	options := backend.PolicyOptions{
		VPN: backend.RouteTarget{
			Interface: names.vpn,
			Source:    netip.MustParseAddr("10.20.3.1"),
		},
		Direct: backend.RouteTarget{
			Interface: names.direct,
			Source:    netip.MustParseAddr("10.20.1.1"),
		},
		VPN6: backend.RouteTarget6{
			Interface: names.vpn,
			Source:    netip.MustParseAddr("fd00:3::1"),
		},
		Direct6: backend.RouteTarget6{
			Interface: names.direct,
			Source:    netip.MustParseAddr("fd00:1::1"),
		},
		ExitNode: &backend.ExitNode{
			ID:      "exit-1",
			Target:  backend.RouteTarget{Interface: names.exit},
			Target6: &target6,
		},
	}
	return compiled, options
}

func sendUDP6(destination string, port int) error {
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{
		IP:   net.ParseIP(destination),
		Port: port,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte("split-tunnel-m05"))
	return err
}

type ipv6InterfaceCounters struct {
	direct uint64
	exit   uint64
	vpn    uint64
}

func ipv6Counters(t *testing.T, names testIPv6Interfaces) ipv6InterfaceCounters {
	t.Helper()
	return ipv6InterfaceCounters{
		direct: txPackets(t, names.direct),
		exit:   txPackets(t, names.exit),
		vpn:    txPackets(t, names.vpn),
	}
}

func TestIPv6PolicyEgressInNetworkNamespace(t *testing.T) {
	requirePrivilegedIPv6(t)

	names := createIPv6TestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m05IPv6Policy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	t.Run("exit node carries selected IPv6 traffic", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:1::1", 9999))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("direct rule uses the physical IPv6 path", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:4::1", 9999))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.direct+1, after.direct)
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("unmatched IPv6 traffic uses the direct default", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:5::1", 9999))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.direct+1, after.direct)
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("vpn rule uses the IPv6 overlay path", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:3::1", 9999))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.vpn+1, after.vpn)
		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.exit, after.exit)
	})

	t.Run("IPv6 protocol port condition is enforced", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:6::1", 5353))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.vpn+1, after.vpn)
		assert.Equal(t, before.direct, after.direct)

		before = ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:6::1", 5354))
		after = ipv6Counters(t, names)

		assert.Equal(t, before.direct+1, after.direct,
			"a different UDP port must fall through to the IPv6 direct default")
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("block drops IPv6 without leaving the host", func(t *testing.T) {
		before := ipv6Counters(t, names)
		err := sendUDP6("fd00:9:2::1", 9999)
		requireUnreachable(t, err)
		after := ipv6Counters(t, names)

		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})
}

func TestIPv6V4OnlyExitNodeCannotLeakProtectedTraffic(t *testing.T) {
	requirePrivilegedIPv6(t)

	names := createIPv6TestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m05IPv6Policy(t, names)
	options.ExitNode.Target6 = nil

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	t.Run("protected IPv6 cannot use the physical default", func(t *testing.T) {
		before := ipv6Counters(t, names)
		requireUnreachable(t, sendUDP6("fd00:9:1::1", 9999))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.direct, after.direct,
			"the physical IPv6 default must not receive protected exit traffic")
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("unprotected IPv6 direct path still works", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:4::1", 9999))
		after := ipv6Counters(t, names)
		assert.Equal(t, before.direct+1, after.direct,
			"an exit node without IPv6 must affect only the protected v6 class")
	})
}

func TestIPv6PolicyMissingProtectedRouteFailsClosed(t *testing.T) {
	requirePrivilegedIPv6(t)

	names := createIPv6TestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m05IPv6Policy(t, names)

	options.VPN6.Interface = names.vpn + "_missing"
	options.ExitNode.Target6 = &backend.RouteTarget6{Interface: names.exit + "_missing"}

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	t.Run("exit IPv6 cannot fall through", func(t *testing.T) {
		before := ipv6Counters(t, names)
		requireUnreachable(t, sendUDP6("fd00:9:1::1", 9999))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.direct, after.direct,
			"the physical default must not receive protected exit IPv6 traffic")
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("vpn IPv6 cannot fall through", func(t *testing.T) {
		before := ipv6Counters(t, names)
		requireUnreachable(t, sendUDP6("fd00:9:3::1", 9999))
		after := ipv6Counters(t, names)

		assert.Equal(t, before.direct, after.direct,
			"the physical default must not receive protected VPN IPv6 traffic")
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})
}

func TestIPv6PolicyRollbackRemovesOnlyOwnedState(t *testing.T) {
	requirePrivilegedIPv6(t)

	names := createIPv6TestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m05IPv6Policy(t, names)

	tableName := fmt.Sprintf("netbird_split_m04_%d", os.Getpid())
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	table := requireInetTable(t, tableName)

	require.NoError(t, b.Rollback(context.Background()))

	assert.NotNil(t, findInetTable(t, tableName), "rollback must keep the baseline table")
	assert.Len(t, chainsInTable(t, tableName), 4, "rollback must keep the baseline chains")
	assert.Len(t, setsInTable(t, table), 10, "rollback must keep the baseline sets")

	conn := &nftables.Conn{}
	classify := &nftables.Chain{Name: string(chainClassifyOutput), Table: table}
	rules, err := conn.GetRules(table, classify)
	require.NoError(t, err)
	assert.Empty(t, rules, "rollback must remove classification rules")

	allocations := newAllocationsMust(t)
	v6Rules, err := netlink.RuleList(netlink.FAMILY_V6)
	require.NoError(t, err)
	for _, rule := range v6Rules {
		for _, class := range splitClasses {
			assert.NotEqual(t, int(allocations.byClass[class].priority), rule.Priority,
				"rollback must remove split IPv6 policy rules")
		}
	}

	for _, class := range splitClasses {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: int(allocations.byClass[class].table)},
			netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		assert.Empty(t, routes, "rollback must remove %s IPv6 routes", class)
	}

	mainRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: 254}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	require.NotEmpty(t, mainRoutes, "rollback must leave the upstream main table intact")
	mainDefault := false
	for i := range mainRoutes {
		if isDefaultRoute(&mainRoutes[i]) {
			mainDefault = true
		}
	}
	assert.True(t, mainDefault, "the physical IPv6 default must remain")
}
