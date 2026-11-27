//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

func ipv6CIDRCondition(value string) config.Condition {
	return config.Condition{Type: config.ConditionCIDR, Prefix: netip.MustParsePrefix(value)}
}

func testOptions6() backend.PolicyOptions {
	options := testOptions()
	options.VPN6 = backend.RouteTarget6{Interface: "wt0"}
	options.Direct6 = backend.RouteTarget6{Interface: "eth0"}
	return options
}

func findRouteClass6(plan *policyPlan, class routeClass) (classRoute, bool) {
	for _, routeClass := range plan.route.classes6 {
		if routeClass.class == class {
			return routeClass, true
		}
	}
	return classRoute{}, false
}

func TestIPv6PrefixExprs(t *testing.T) {
	t.Run("host prefix", func(t *testing.T) {
		exprs := ipv6PrefixExprs(netip.MustParsePrefix("2001:db8::1/128"))
		require.Len(t, exprs, 2)

		payload, ok := exprs[0].(*expr.Payload)
		require.True(t, ok)
		assert.Equal(t, uint32(ipv6DestinationOffset), payload.Offset)
		assert.Equal(t, uint32(ipv6AddressLength), payload.Len)

		cmp, ok := exprs[1].(*expr.Cmp)
		require.True(t, ok)
		assert.Equal(t, netip.MustParseAddr("2001:db8::1").AsSlice(), cmp.Data)
	})

	t.Run("network prefix", func(t *testing.T) {
		exprs := ipv6PrefixExprs(netip.MustParsePrefix("2001:db8::/32"))
		require.Len(t, exprs, 3)

		bitwise, ok := exprs[1].(*expr.Bitwise)
		require.True(t, ok)
		assert.Equal(t, []byte(net.CIDRMask(32, 128)), bitwise.Mask)
		assert.Len(t, bitwise.Xor, ipv6AddressLength)

		cmp, ok := exprs[2].(*expr.Cmp)
		require.True(t, ok)
		assert.Equal(t, netip.MustParseAddr("2001:db8::").AsSlice(), cmp.Data)
	})
}

func TestIPv6PrefixSetElements(t *testing.T) {
	elements := prefixSetElements([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")})
	require.Len(t, elements, 2)
	assert.Equal(t, netip.MustParseAddr("2001:db8::").AsSlice(), elements[0].Key)
	assert.False(t, elements[0].IntervalEnd)
	assert.Equal(t, netip.MustParseAddr("2001:db9::").AsSlice(), elements[1].Key,
		"the interval end is the address after the last address in the prefix")
	assert.True(t, elements[1].IntervalEnd)

	elements = prefixSetElements([]netip.Prefix{netip.MustParsePrefix("::/0")})
	require.Len(t, elements, 2)
	assert.Equal(t, make([]byte, ipv6AddressLength), elements[0].Key)
	assert.Equal(t, make([]byte, ipv6AddressLength), elements[1].Key)

	elements = prefixSetElements([]netip.Prefix{
		netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
	})
	require.Len(t, elements, 2)
	assert.Equal(t, make([]byte, ipv6AddressLength), elements[1].Key,
		"the maximum IPv6 address wraps to an all-zero interval end")
}

func TestIPv6RuleExprsUsesIPv6GuardAndOffsets(t *testing.T) {
	sets := map[setName]*nftables.Set{
		setVPN6: {ID: 9, Name: string(setVPN6)},
	}
	rule := nftRule{family: family6, matches: []nftMatch{{set: setVPN6}}, mark: 0x1BD01}

	exprs, err := nftRuleExprs(rule, sets)
	require.NoError(t, err)
	require.Len(t, exprs, 9)

	cmp, ok := exprs[1].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, binaryutil.NativeEndian.PutUint32(unix.NFPROTO_IPV6), cmp.Data,
		"an IPv6 rule must carry the IPv6 family guard")

	payload, ok := exprs[4].(*expr.Payload)
	require.True(t, ok)
	assert.Equal(t, uint32(ipv6DestinationOffset), payload.Offset)
	assert.Equal(t, uint32(ipv6AddressLength), payload.Len)

	lookup, ok := exprs[5].(*expr.Lookup)
	require.True(t, ok)
	assert.Equal(t, uint32(9), lookup.SetID)
}

func TestIPv6RuleExprsCombinesPrefixAndProtocol(t *testing.T) {
	rule := nftRule{
		family: family6,
		matches: []nftMatch{
			{prefix: netip.MustParsePrefix("2001:db8::1/128")},
			{protocol: config.ProtocolTCP, port: 443},
		},
		mark: 0x1BD01,
	}

	exprs, err := nftRuleExprs(rule, nil)
	require.NoError(t, err)
	require.Len(t, exprs, 4+2+4+3,
		"IPv6 and mark guard, literal prefix, protocol port, then mark and return")

	cmp, ok := exprs[1].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, binaryutil.NativeEndian.PutUint32(unix.NFPROTO_IPV6), cmp.Data)
}

func TestIPv6RuleExprsRejectsFamilyMismatch(t *testing.T) {
	_, err := nftRuleExprs(nftRule{
		family:  family6,
		matches: []nftMatch{{prefix: netip.MustParsePrefix("10.0.0.0/8")}},
	}, nil)
	require.Error(t, err)

	sets := map[setName]*nftables.Set{
		setVPN4: {ID: 1, Name: string(setVPN4)},
	}
	_, err = nftRuleExprs(nftRule{
		family:  family6,
		matches: []nftMatch{{set: setVPN4}},
	}, sets)
	require.Error(t, err)
}

func TestCompilePolicyDualStack(t *testing.T) {
	allocations := testAllocations(t)
	cfg := includeConfig(
		testRule("vpn4", config.ActionVPN, ipv6CIDRCondition("10.9.3.0/24")),
		testRule("vpn6", config.ActionVPN, ipv6CIDRCondition("2001:db8:1::/48")),
		testRule("https6", config.ActionVPN,
			ipv6CIDRCondition("2001:db8:2::/48"), portCondition(config.ProtocolTCP, 443)),
	)
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	plan, err := compilePolicy(compiled, testOptions6(), allocations)
	require.NoError(t, err)

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.9.3.0/24")},
		plan.nft.sets[setVPN4])
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")},
		plan.nft.sets[setVPN6],
		"a protocol-qualified IPv6 prefix must stay out of the aggregate set")

	v4Rules := rulesInFamily(plan.nft.rules, family4)
	v6Rules := rulesInFamily(plan.nft.rules, family6)
	require.NotEmpty(t, v4Rules)
	require.NotEmpty(t, v6Rules)

	for _, rule := range v6Rules {
		assert.Equal(t, family6, rule.family)
	}

	vpn4, ok := findRouteClass(plan, classVPN)
	require.True(t, ok)
	assert.Equal(t, routeFamily4, vpn4.family)
	assert.Equal(t, "wt0", vpn4.target.Interface)

	vpn6, ok := findRouteClass6(plan, classVPN)
	require.True(t, ok)
	assert.Equal(t, routeFamily6, vpn6.family)
	assert.Equal(t, "wt0", vpn6.target.Interface)

	vpnMark := allocations.byClass[classVPN].mark.Value
	assert.Equal(t, 2, countRulesWithMarkAndFamily(v6Rules, vpnMark, family6),
		"the prefix-only and protocol-qualified v6 rules are emitted separately")

	foundProtocol := false
	for _, rule := range v6Rules {
		if rule.mark != vpnMark {
			continue
		}
		for _, match := range rule.matches {
			if match.protocol == config.ProtocolTCP && match.port == 443 {
				foundProtocol = true
			}
		}
	}
	assert.True(t, foundProtocol, "the v6 protocol-port condition must be compiled")
}

func rulesInFamily(rules []nftRule, family nftFamily) []nftRule {
	var out []nftRule
	for _, rule := range rules {
		if rule.family == family {
			out = append(out, rule)
		}
	}
	return out
}

func countRulesWithMarkAndFamily(rules []nftRule, mark uint32, family nftFamily) int {
	count := 0
	for _, rule := range rules {
		if rule.family == family && rule.mark == mark {
			count++
		}
	}
	return count
}

func TestCompilePolicyIPv6ProtocolOnlyMatchesBothFamilies(t *testing.T) {
	cfg := includeConfig(testRule("https", config.ActionVPN,
		portCondition(config.ProtocolTCP, 443)))
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	plan, err := compilePolicy(compiled, testOptions6(), testAllocations(t))
	require.NoError(t, err)

	vpnMark := testAllocations(t).byClass[classVPN].mark.Value
	assert.Equal(t, 1, countRulesWithMarkAndFamily(plan.nft.rules, vpnMark, family4))
	assert.Equal(t, 1, countRulesWithMarkAndFamily(plan.nft.rules, vpnMark, family6),
		"a protocol-only rule has no address family and must be installed for both")
}

func TestCompilePolicyV4OnlyExitNodeFailsClosedForIPv6(t *testing.T) {
	exitID := config.ExitNodeID("exit-a")
	rule := testRule("exit", config.ActionExitNode,
		ipv6CIDRCondition("203.0.113.0/24"), ipv6CIDRCondition("2001:db8:3::/48"))
	rule.ExitNodeID = exitID
	rule.MatchMode = config.MatchAny

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			IPv6:          true,
			Rules:         []config.Rule{rule},
		},
	}
	compiled := mustCompile(t, cfg)

	options := testOptions6()
	options.ExitNode = &backend.ExitNode{
		ID:     exitID,
		Target: backend.RouteTarget{Interface: "wt-exit"},
	}

	plan, err := compilePolicy(compiled, options, testAllocations(t))
	require.NoError(t, err)

	exit4, ok := findRouteClass(plan, classExit)
	require.True(t, ok)
	assert.Equal(t, routeFamily4, exit4.family)
	assert.Equal(t, "wt-exit", exit4.target.Interface)

	exit6, ok := findRouteClass6(plan, classExit)
	require.True(t, ok)
	assert.Equal(t, routeFamily6, exit6.family)
	assert.True(t, exit6.protected)
	assert.Empty(t, exit6.target.Interface,
		"a v4-only exit node must leave protected IPv6 with no route")
}

func TestCompilePolicyIPv6RequiresDirectTarget(t *testing.T) {
	cfg := includeConfig(testRule("vpn6", config.ActionVPN, ipv6CIDRCondition("2001:db8::/32")))
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	options := testOptions6()
	options.Direct6 = backend.RouteTarget6{}

	_, err := compilePolicy(compiled, options, testAllocations(t))
	require.ErrorIs(t, err, backend.ErrInvalidPolicyOption,
		"the include-mode IPv6 default needs a v6 direct target")
}

func TestCompilePolicyIPv6VPNWithoutTargetFailsClosed(t *testing.T) {
	cfg := includeConfig(testRule("vpn6", config.ActionVPN, ipv6CIDRCondition("2001:db8::/32")))
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	options := testOptions6()
	options.VPN6 = backend.RouteTarget6{}

	plan, err := compilePolicy(compiled, options, testAllocations(t))
	require.NoError(t, err)

	vpn6, ok := findRouteClass6(plan, classVPN)
	require.True(t, ok)
	assert.True(t, vpn6.protected)
	assert.Empty(t, vpn6.target.Interface,
		"protected IPv6 without an overlay target must be unreachable")
}

func TestCompilePolicyRejectsIPv6DomainWithCIDR(t *testing.T) {
	cfg := includeConfig(testRule("vpn6", config.ActionVPN,
		ipv6CIDRCondition("2001:db8::/32"),
		config.Condition{Type: config.ConditionWildcardDomain, Wildcard: "example.com"}))
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	_, err := compilePolicy(compiled, testOptions6(), testAllocations(t))
	require.ErrorIs(t, err, backend.ErrUnsupportedCondition)
}

func TestCompilePolicyRejectsMixedFamilyConjunction(t *testing.T) {
	cfg := includeConfig(testRule("vpn", config.ActionVPN,
		ipv6CIDRCondition("10.0.0.0/8"), ipv6CIDRCondition("2001:db8::/32")))
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	_, err := compilePolicy(compiled, testOptions6(), testAllocations(t))
	require.ErrorIs(t, err, backend.ErrUnsupportedCondition)
}

func TestCompilePolicyIPv6AllocatorReuseIsFamilySeparated(t *testing.T) {
	allocations := testAllocations(t)
	cfg := includeConfig(
		testRule("vpn4", config.ActionVPN, ipv6CIDRCondition("10.9.3.0/24")),
		testRule("vpn6", config.ActionVPN, ipv6CIDRCondition("2001:db8:1::/48")),
	)
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	plan, err := compilePolicy(compiled, testOptions6(), allocations)
	require.NoError(t, err)

	v4, ok := findRouteClass(plan, classVPN)
	require.True(t, ok)
	v6, ok := findRouteClass6(plan, classVPN)
	require.True(t, ok)

	assert.Equal(t, v4.allocation.table, v6.allocation.table,
		"table IDs may be reused because IPv4 and IPv6 policy rules are family-scoped")
	assert.Equal(t, v4.allocation.priority, v6.allocation.priority,
		"priority range 106-109 has no room for a second key set; family separates rules")
	assert.Equal(t, v4.allocation.mark, v6.allocation.mark,
		"the same mark is safe because each family has its own policy rule")
	assert.NotEqual(t, v4.family, v6.family)
}

func TestNetlinkRouterAppliesIPv6WithFamilySeparatedRule(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()

	plan := routePlan{
		classes: []classRoute{{
			class:      classDirect,
			allocation: allocations.byClass[classDirect],
			family:     routeFamily4,
			target:     backend.RouteTarget{Interface: "eth0"},
		}},
		classes6: []classRoute{{
			class:      classExit,
			allocation: allocations.byClass[classExit],
			family:     routeFamily6,
			target:     backend.RouteTarget{Interface: "eth0"},
			protected:  true,
		}},
	}

	require.NoError(t, recorded.router().Apply(context.Background(), plan))
	require.Len(t, recorded.routes, 3)

	v4 := recorded.routes[0]
	assert.Equal(t, netlink.FAMILY_V4, v4.Family)

	v6 := recorded.routes[1]
	assert.Equal(t, netlink.FAMILY_V6, v6.Family)
	assert.Equal(t, int(allocations.byClass[classExit].table), v6.Table)
	ones, bits := v6.Dst.Mask.Size()
	assert.Equal(t, 0, ones)
	assert.Equal(t, 128, bits, "the IPv6 default route is ::/0")

	fallback := recorded.routes[2]
	assert.Equal(t, unix.RTN_UNREACHABLE, fallback.Type)
	assert.Equal(t, netlink.FAMILY_V6, fallback.Family)
	assert.Equal(t, protectedFallbackMetric, fallback.Priority)

	require.Len(t, recorded.rules, 2)
	assert.Equal(t, netlink.FAMILY_V4, recorded.rules[0].Family)
	v6Rule := recorded.rules[1]
	assert.Equal(t, netlink.FAMILY_V6, v6Rule.Family)
	assert.Equal(t, int(allocations.byClass[classExit].table), v6Rule.Table)
	assert.Equal(t, int(allocations.byClass[classExit].priority), v6Rule.Priority)
	assert.Equal(t, allocations.byClass[classExit].mark.Value, v6Rule.Mark)
}

func TestNetlinkRouterRemovesOwnedIPv6State(t *testing.T) {
	allocations := testAllocations(t)
	allocation := allocations.byClass[classExit]

	ours := netlink.NewRule()
	ours.Family = netlink.FAMILY_V6
	ours.Table = int(allocation.table)
	ours.Priority = int(allocation.priority)
	ours.Mark = allocation.mark.Value
	mask := allocation.mark.Mask
	ours.Mask = &mask

	foreign := netlink.NewRule()
	foreign.Family = netlink.FAMILY_V6
	foreign.Table = 254
	foreign.Priority = 100
	foreign.Mark = 0x1234

	v6Default := netlink.Route{
		Family: netlink.FAMILY_V6,
		Table:  int(allocation.table),
		Type:   unix.RTN_UNREACHABLE,
		Dst:    defaultRouteDestinationFor(routeFamily6),
	}
	v6Specific := netlink.Route{
		Family: netlink.FAMILY_V6,
		Table:  int(allocation.table),
		Dst: &net.IPNet{
			IP:   netip.MustParseAddr("2001:db8::").AsSlice(),
			Mask: net.CIDRMask(32, 128),
		},
	}

	var deletedRules []netlink.Rule
	var deletedRoutes []netlink.Route
	router := &netlinkRouter{
		linkByName:   func(string) (netlink.Link, error) { return nil, errors.New("unused") },
		routeReplace: func(*netlink.Route) error { return nil },
		ruleAdd:      func(*netlink.Rule) error { return nil },
		ruleList: func(family int) ([]netlink.Rule, error) {
			if family == netlink.FAMILY_V6 {
				return []netlink.Rule{*ours, *foreign}, nil
			}
			return nil, nil
		},
		ruleDel: func(rule *netlink.Rule) error {
			deletedRules = append(deletedRules, *rule)
			return nil
		},
		routeListFiltered: func(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
			if family == netlink.FAMILY_V6 && filter.Table == int(allocation.table) {
				return []netlink.Route{v6Default, v6Specific}, nil
			}
			return nil, nil
		},
		routeDel: func(route *netlink.Route) error {
			deletedRoutes = append(deletedRoutes, *route)
			return nil
		},
	}

	require.NoError(t, router.Remove(context.Background(), allocations))

	require.Len(t, deletedRules, 1)
	assert.Equal(t, netlink.FAMILY_V6, deletedRules[0].Family)
	require.Len(t, deletedRoutes, 1, "a foreign specific IPv6 route must be left alone")
	assert.Equal(t, netlink.FAMILY_V6, deletedRoutes[0].Family)
	assert.Equal(t, unix.RTN_UNREACHABLE, deletedRoutes[0].Type)
}

func TestCompilePolicyIPv6ExitNodeIDMismatch(t *testing.T) {
	rule := testRule("exit", config.ActionExitNode, ipv6CIDRCondition("2001:db8::/32"))
	rule.ExitNodeID = "exit-a"
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			IPv6:          true,
			Rules:         []config.Rule{rule},
		},
	}
	compiled := mustCompile(t, cfg)

	options := testOptions6()
	target6 := backend.RouteTarget6{Interface: "wt-exit"}
	options.ExitNode = &backend.ExitNode{
		ID:      "exit-b",
		Target:  backend.RouteTarget{Interface: "wt-exit"},
		Target6: &target6,
	}

	_, err := compilePolicy(compiled, options, testAllocations(t))
	require.ErrorIs(t, err, backend.ErrExitNodeUnavailable)
}

func TestCompilePolicyV6OnlyExitNode(t *testing.T) {
	rule := testRule("exit", config.ActionExitNode, ipv6CIDRCondition("2001:db8::/32"))
	rule.ExitNodeID = "exit-a"
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			IPv6:          true,
			Rules:         []config.Rule{rule},
		},
	}
	compiled := mustCompile(t, cfg)

	options := testOptions6()
	target6 := backend.RouteTarget6{
		Interface: "wt-exit",
		Source:    netip.MustParseAddr("fd00::1"),
	}
	options.ExitNode = &backend.ExitNode{
		ID:      "exit-a",
		Target6: &target6,
	}

	plan, err := compilePolicy(compiled, options, testAllocations(t))
	require.NoError(t, err, "an IPv6-only exit node must not require an IPv4 target")

	exit6, ok := findRouteClass6(plan, classExit)
	require.True(t, ok)
	assert.Equal(t, "wt-exit", exit6.target.Interface)
	assert.Equal(t, netip.MustParseAddr("fd00::1"), exit6.target.Source)

	_, ok = findRouteClass(plan, classExit)
	assert.False(t, ok, "a v6-only exit rule must not install an IPv4 exit route")
}

func TestCompilePolicyWrapperEnablesIPv6FromPolicy(t *testing.T) {
	cfg := includeConfig(testRule("vpn6", config.ActionVPN, ipv6CIDRCondition("2001:db8::/32")))
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	plan, err := compilePolicy(compiled, testOptions6(), testAllocations(t))
	require.NoError(t, err)
	assert.NotEmpty(t, plan.route.classes6)
}

func TestCompilePolicyForHostWithoutIPv6SkipsOnlyV6(t *testing.T) {
	cfg := includeConfig(
		testRule("vpn4", config.ActionVPN, ipv6CIDRCondition("10.9.3.0/24")),
		testRule("vpn6", config.ActionVPN, ipv6CIDRCondition("2001:db8::/32")),
	)
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)

	plan, err := compilePolicyFor(compiled, testOptions(), testAllocations(t), false)
	require.NoError(t, err)

	assert.Empty(t, plan.route.classes6, "a host without IPv6 must skip the v6 route path")
	assert.Empty(t, plan.nft.sets[setVPN6])
	for _, rule := range plan.nft.rules {
		assert.Equal(t, family4, rule.family)
	}

	vpn4, ok := findRouteClass(plan, classVPN)
	require.True(t, ok, "the IPv4 path must still be applied")
	assert.Equal(t, "wt0", vpn4.target.Interface)
}
