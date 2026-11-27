//go:build linux && !android && privileged

package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
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

const killSwitchControlPrefix = "10.9.7.0/24"

func m10V4Policy(
	t *testing.T,
	names testInterfaces,
	mode config.KillSwitchMode,
) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			KillSwitch:    mode,
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
					ID:        "vpn",
					Name:      "vpn",
					Enabled:   true,
					Priority:  20,
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
					Priority:  30,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.9.4.0/24"),
					}},
				},
			},
		},
	}
	compiled, err := policy.CompileWith(cfg, policy.Constraints{
		ControlPrefixes: []netip.Prefix{netip.MustParsePrefix(killSwitchControlPrefix)},
	})
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
		DNSResolvers: []netip.Prefix{netip.MustParsePrefix("10.0.1.53/32")},
	}
	return compiled, options
}

func m10V6Policy(
	t *testing.T,
	names testIPv6Interfaces,
	mode config.KillSwitchMode,
) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			KillSwitch:    mode,
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
					ID:        "vpn",
					Name:      "vpn",
					Enabled:   true,
					Priority:  20,
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
					Priority:  30,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("fd00:9:4::/64"),
					}},
				},
			},
		},
	}
	compiled, err := policy.CompileWith(cfg, policy.Constraints{
		ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("fd00:9:7::/64")},
	})
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
		DNSResolvers: []netip.Prefix{netip.MustParsePrefix("fd00:1::53/128")},
	}
	return compiled, options
}

func requireBlocked(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, syscall.EPERM) ||
			errors.Is(err, syscall.EHOSTUNREACH) ||
			errors.Is(err, syscall.ENETUNREACH),
		"expected the packet to be blocked, got %v", err)
}

func killSwitchChainRules(t *testing.T, tableName string) []*nftables.Rule {
	t.Helper()

	table := requireInetTable(t, tableName)
	conn := &nftables.Conn{}
	rules, err := conn.GetRules(table, &nftables.Chain{
		Name:  string(chainKillswitch),
		Table: table,
	})
	require.NoError(t, err)
	return rules
}

func requireAllRulesOwned(t *testing.T, rules []*nftables.Rule) {
	t.Helper()
	for _, rule := range rules {
		assert.Equal(t, ownedRuleUserData, rule.UserData,
			"kill switch rule %d must carry the ownership marker", rule.Handle)
	}
}

func TestSelectiveKillSwitchBlocksProtectedTrafficInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m10V4Policy(t, names, config.KillSwitchSelective)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	reconciler := startPolicyReconciler(t, b)

	tableName := fmt.Sprintf("netbird_split_m04_%d", os.Getpid())
	requireAllRulesOwned(t, killSwitchChainRules(t, tableName))

	t.Run("tunnel up carries protected and direct traffic", func(t *testing.T) {
		before := counters(t, names)

		require.NoError(t, sendUDP("10.9.1.1", 9999))
		require.NoError(t, sendUDP("10.9.3.1", 9999))
		require.NoError(t, sendUDP("10.9.4.1", 9999))

		after := counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.vpn+1, after.vpn)
		assert.Equal(t, before.direct+1, after.direct)
	})

	t.Run("exit link loss blocks only protected traffic", func(t *testing.T) {
		exitLink, err := netlink.LinkByName(names.exit)
		require.NoError(t, err)
		beforeReconcile := reconciler.Reconciles()
		require.NoError(t, netlink.LinkSetDown(exitLink))
		waitForReconcileAfter(t, reconciler, beforeReconcile)
		waitForExitDefaultType(t, b, routeFamily4, syscall.RTN_UNREACHABLE)

		before := counters(t, names)
		requireBlocked(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.direct, after.direct,
			"blocked exit traffic must not fall through to the physical gateway")
		assert.Equal(t, before.exit, after.exit)

		before = counters(t, names)
		require.NoError(t, sendUDP("10.9.4.1", 9999))
		after = counters(t, names)
		assert.Equal(t, before.direct+1, after.direct,
			"DIRECT traffic must continue while the exit path is down")
	})

	t.Run("reconnect restores the exit path", func(t *testing.T) {
		exitLink, err := netlink.LinkByName(names.exit)
		require.NoError(t, err)
		beforeReconcile := reconciler.Reconciles()
		require.NoError(t, netlink.LinkSetUp(exitLink))
		waitForReconcileAfter(t, reconciler, beforeReconcile)
		waitForExitDefaultType(t, b, routeFamily4, syscall.RTN_UNICAST)

		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)

		before = counters(t, names)
		require.NoError(t, sendUDP("10.9.4.1", 9999))
		after = counters(t, names)
		assert.Equal(t, before.direct+1, after.direct)
	})
}

func TestGlobalKillSwitchBlocksEgressInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m10V4Policy(t, names, config.KillSwitchGlobal)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	t.Run("protected and direct egress", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)

		before = counters(t, names)
		requireBlocked(t, sendUDP("10.9.4.1", 9999))
		after = counters(t, names)
		assert.Equal(t, before.direct, after.direct,
			"global mode must not let a direct rule use the physical path")

		before = counters(t, names)
		requireBlocked(t, sendUDP("10.9.5.1", 9999))
		after = counters(t, names)
		assert.Equal(t, before.direct, after.direct,
			"unmatched traffic must not leak to the physical default")
	})

	t.Run("control and DNS exceptions remain reachable", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.7.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.direct+1, after.direct,
			"control and transport prefixes must stay reachable")

		before = counters(t, names)
		require.NoError(t, sendUDP("10.0.1.53", 53))
		after = counters(t, names)
		assert.Equal(t, before.direct+1, after.direct,
			"configured DNS resolvers must stay reachable")
	})

	t.Run("loopback remains reachable", func(t *testing.T) {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 9999,
		})
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte("loopback"))
		require.NoError(t, err)
	})

	t.Run("disable clears protection", func(t *testing.T) {
		disabled, disabledOptions := m10V4Policy(t, names, config.KillSwitchDisabled)
		require.NoError(t, b.ApplyPolicy(context.Background(), disabled, disabledOptions))
		assert.Empty(t, killSwitchChainRules(t, fmt.Sprintf("netbird_split_m04_%d", os.Getpid())),
			"disabling the kill switch must clear the owned chain")

		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.4.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.direct+1, after.direct,
			"disabling the kill switch must restore direct connectivity")
	})
}

func TestStrictKillSwitchAllowsExplicitDirectInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m10V4Policy(t, names, config.KillSwitchStrict)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	t.Run("explicit direct rule stays reachable", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.4.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.direct+1, after.direct)
	})

	t.Run("default direct traffic is blocked", func(t *testing.T) {
		before := counters(t, names)
		requireBlocked(t, sendUDP("10.9.5.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.direct, after.direct,
			"a DIRECT default is not an explicit strict-mode grant")
	})

	t.Run("control and DNS exceptions stay reachable", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.7.1", 9999))
		require.NoError(t, sendUDP("10.0.1.53", 53))
		after := counters(t, names)
		assert.Equal(t, before.direct+2, after.direct)
	})

	t.Run("tunnel traffic still uses the protected path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
	})
}

func TestSelectiveKillSwitchIPv6InNetworkNamespace(t *testing.T) {
	requirePrivilegedIPv6(t)

	names := createIPv6TestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m10V6Policy(t, names, config.KillSwitchSelective)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	reconciler := startPolicyReconciler(t, b)

	t.Run("IPv6 tunnel up carries protected and direct traffic", func(t *testing.T) {
		before := ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:1::1", 9999))
		require.NoError(t, sendUDP6("fd00:9:4::1", 9999))
		after := ipv6Counters(t, names)
		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct+1, after.direct)
	})

	t.Run("IPv6 exit loss blocks protected traffic only", func(t *testing.T) {
		exitLink, err := netlink.LinkByName(names.exit)
		require.NoError(t, err)
		beforeReconcile := reconciler.Reconciles()
		require.NoError(t, netlink.LinkSetDown(exitLink))
		waitForReconcileAfter(t, reconciler, beforeReconcile)

		before := ipv6Counters(t, names)
		requireBlocked(t, sendUDP6("fd00:9:1::1", 9999))
		after := ipv6Counters(t, names)
		assert.Equal(t, before.direct, after.direct,
			"protected IPv6 must not fall through to the physical default")

		before = ipv6Counters(t, names)
		require.NoError(t, sendUDP6("fd00:9:4::1", 9999))
		after = ipv6Counters(t, names)
		assert.Equal(t, before.direct+1, after.direct,
			"DIRECT IPv6 must continue while the exit path is down")
	})
}

func TestGlobalKillSwitchIPv6InNetworkNamespace(t *testing.T) {
	requirePrivilegedIPv6(t)

	names := createIPv6TestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m10V6Policy(t, names, config.KillSwitchGlobal)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	before := ipv6Counters(t, names)
	require.NoError(t, sendUDP6("fd00:9:1::1", 9999))
	after := ipv6Counters(t, names)
	assert.Equal(t, before.exit+1, after.exit)

	before = ipv6Counters(t, names)
	requireBlocked(t, sendUDP6("fd00:9:4::1", 9999))
	after = ipv6Counters(t, names)
	assert.Equal(t, before.direct, after.direct,
		"global IPv6 must block direct egress")

	before = ipv6Counters(t, names)
	require.NoError(t, sendUDP6("fd00:9:7::1", 9999))
	after = ipv6Counters(t, names)
	assert.Equal(t, before.direct+1, after.direct,
		"global IPv6 must allow control prefixes")
}

func TestKillSwitchInstallBeforePolicyAndEmergencyReset(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)
	compiled, options := m10V4Policy(t, names, config.KillSwitchGlobal)

	require.NoError(t, b.InstallProtection(context.Background(), compiled, options))
	require.NoError(t, b.InstallProtection(context.Background(), compiled, options))

	before := counters(t, names)
	requireBlocked(t, sendUDP("10.9.4.1", 9999))
	after := counters(t, names)
	assert.Equal(t, before.direct, after.direct,
		"pre-armed protection must block traffic before managed routing exists")

	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	requireBlocked(t, sendUDP("10.9.4.1", 9999))

	require.NoError(t, b.EmergencyReset(context.Background()))
	before = counters(t, names)
	require.NoError(t, sendUDP("10.9.4.1", 9999))
	after = counters(t, names)
	assert.Equal(t, before.direct+1, after.direct,
		"emergency reset must restore normal connectivity")

	require.NoError(t, b.EmergencyReset(context.Background()),
		"emergency reset must stay idempotent")
	before = counters(t, names)
	require.NoError(t, sendUDP("10.9.4.1", 9999))
	after = counters(t, names)
	assert.Equal(t, before.direct+1, after.direct)
}

func TestKillSwitchSurvivesProcessKill(t *testing.T) {
	requirePrivilegedNetwork(t)

	if os.Getenv("NB_KILLSWITCH_HELPER") == "1" {
		runKillSwitchHelper(t)
		return
	}

	names := createTestInterfaces(t)
	table := fmt.Sprintf("netbird_split_m10_%d", os.Getpid())

	var output bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=TestKillSwitchSurvivesProcessKill")
	cmd.Env = append(os.Environ(),
		"NB_KILLSWITCH_HELPER=1",
		"NB_KILLSWITCH_TABLE="+table,
		"NB_KILLSWITCH_DIRECT="+names.direct,
		"NB_KILLSWITCH_EXIT="+names.exit,
		"NB_KILLSWITCH_VPN="+names.vpn,
	)
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	require.Error(t, err, "the helper must be killed before cleanup: %s", output.String())
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, syscall.SIGKILL, exitErr.Sys().(syscall.WaitStatus).Signal(),
		"helper output: %s", output.String())

	t.Cleanup(func() {
		cleanup := newBackendWith(systemProber{}, func(string) (nftManager, error) {
			return newNFTablesManager(table)
		}, newNetlinkRouter(), table)
		_ = cleanup.Cleanup(context.Background())
	})

	require.NotNil(t, findInetTable(t, table), "the helper's kernel state must survive SIGKILL")
	assert.NotEmpty(t, killSwitchChainRules(t, table),
		"the kill switch rules must survive SIGKILL")

	exitLink, err := netlink.LinkByName(names.exit)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetDown(exitLink))

	before := counters(t, names)
	requireBlocked(t, sendUDP("10.9.1.1", 9999))
	after := counters(t, names)
	assert.Equal(t, before.direct, after.direct,
		"after SIGKILL and link loss, protected traffic must not reach the physical path")

	before = counters(t, names)
	require.NoError(t, sendUDP("10.9.4.1", 9999))
	after = counters(t, names)
	assert.Equal(t, before.direct+1, after.direct,
		"DIRECT traffic must continue after SIGKILL")
}

func runKillSwitchHelper(t *testing.T) {
	t.Helper()

	table := os.Getenv("NB_KILLSWITCH_TABLE")
	names := testInterfaces{
		direct: os.Getenv("NB_KILLSWITCH_DIRECT"),
		exit:   os.Getenv("NB_KILLSWITCH_EXIT"),
		vpn:    os.Getenv("NB_KILLSWITCH_VPN"),
	}
	require.NotEmpty(t, table)

	b := newBackendWith(systemProber{}, func(string) (nftManager, error) {
		return newNFTablesManager(table)
	}, newNetlinkRouter(), table)
	require.NoError(t, b.Initialize(context.Background()))

	compiled, options := m10V4Policy(t, names, config.KillSwitchSelective)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	fmt.Fprintln(os.Stdout, "kill switch installed")
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}

func TestKillSwitchBootOrderingPending(t *testing.T) {
	t.Skip("systemd ordering, delegation and install-before-managed-traffic at boot " +
		"are not wired yet; InstallProtection is the in-process pre-arm hook")
}
