//go:build linux && !android

package linux

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func cidrCondition(value string) config.Condition {
	return config.Condition{Type: config.ConditionCIDR, Prefix: netip.MustParsePrefix(value)}
}

func portCondition(protocol config.Protocol, port uint16) config.Condition {
	return config.Condition{Type: config.ConditionProtocolPort, Protocol: protocol, Port: port}
}

func testRule(id string, action config.Action, conditions ...config.Condition) config.Rule {
	return config.Rule{
		ID:         config.RuleID(id),
		Name:       id,
		Enabled:    true,
		Priority:   10,
		MatchMode:  config.MatchAll,
		Action:     action,
		Conditions: conditions,
	}
}

func includeConfig(rules ...config.Rule) *config.Config {
	return &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeInclude,
			DefaultAction: config.ActionDirect,
			Rules:         rules,
		},
	}
}

func mustCompile(t *testing.T, cfg *config.Config) *policy.CompiledPolicy {
	t.Helper()
	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)
	return compiled
}

func testAllocations(t *testing.T) allocations {
	t.Helper()
	allocations, err := newAllocations()
	require.NoError(t, err)
	return allocations
}

func testOptions() backend.PolicyOptions {
	return backend.PolicyOptions{
		VPN:    backend.RouteTarget{Interface: "wt0"},
		Direct: backend.RouteTarget{Interface: "eth0"},
	}
}

func findRouteClass(plan *policyPlan, class routeClass) (classRoute, bool) {
	for _, routeClass := range plan.route.classes {
		if routeClass.class == class {
			return routeClass, true
		}
	}
	return classRoute{}, false
}

func TestCompilePolicyIncludeDefaultDirect(t *testing.T) {
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	allocations := testAllocations(t)

	plan, err := compilePolicy(compiled, testOptions(), allocations)
	require.NoError(t, err)

	require.NotEmpty(t, plan.nft.rules)
	last := plan.nft.rules[len(plan.nft.rules)-1]
	assert.Equal(t, allocations.byClass[classDirect].mark.Value, last.mark,
		"include mode must mark unmatched traffic direct")
	assert.Empty(t, last.matches)

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		plan.nft.sets[setVPN4])

	vpn, ok := findRouteClass(plan, classVPN)
	require.True(t, ok)
	assert.True(t, vpn.protected)
	assert.Equal(t, "wt0", vpn.target.Interface)

	direct, ok := findRouteClass(plan, classDirect)
	require.True(t, ok)
	assert.False(t, direct.protected)
	assert.Equal(t, "eth0", direct.target.Interface)

	_, ok = findRouteClass(plan, classExit)
	assert.False(t, ok, "unused classes must not install routes")
}

func TestCompilePolicyExcludeDefaultVPN(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeExclude,
			DefaultAction: config.ActionVPN,
			Rules: []config.Rule{
				testRule("direct", config.ActionDirect, cidrCondition("192.168.0.0/16")),
			},
		},
	}
	compiled := mustCompile(t, cfg)
	allocations := testAllocations(t)

	plan, err := compilePolicy(compiled, testOptions(), allocations)
	require.NoError(t, err)

	last := plan.nft.rules[len(plan.nft.rules)-1]
	assert.Equal(t, allocations.byClass[classVPN].mark.Value, last.mark,
		"exclude mode must mark unmatched traffic vpn")
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		plan.nft.sets[setDirect4])

	vpn, ok := findRouteClass(plan, classVPN)
	require.True(t, ok)
	assert.True(t, vpn.protected)

	direct, ok := findRouteClass(plan, classDirect)
	require.True(t, ok)
	assert.False(t, direct.protected)
}

func TestCompilePolicyCustomDefaultBlock(t *testing.T) {
	exitID := config.ExitNodeID("exit-a")
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionBlock,
			Rules: []config.Rule{{
				ID:         "exit",
				Name:       "exit",
				Enabled:    true,
				Priority:   10,
				MatchMode:  config.MatchAll,
				Action:     config.ActionExitNode,
				ExitNodeID: exitID,
				Conditions: []config.Condition{cidrCondition("203.0.113.0/24")},
			}},
		},
	}
	compiled := mustCompile(t, cfg)
	allocations := testAllocations(t)

	options := testOptions()
	options.ExitNode = &backend.ExitNode{
		ID:     exitID,
		Target: backend.RouteTarget{Interface: "wt-exit"},
	}

	plan, err := compilePolicy(compiled, options, allocations)
	require.NoError(t, err)

	last := plan.nft.rules[len(plan.nft.rules)-1]
	assert.Equal(t, allocations.byClass[classBlock].mark.Value, last.mark)

	exit, ok := findRouteClass(plan, classExit)
	require.True(t, ok)
	assert.True(t, exit.protected)
	assert.Equal(t, "wt-exit", exit.target.Interface)

	block, ok := findRouteClass(plan, classBlock)
	require.True(t, ok)
	assert.True(t, block.blackhole)
	assert.True(t, block.protected)
}

func TestCompilePolicyDomainConditions(t *testing.T) {
	cfg := includeConfig(
		testRule("exact", config.ActionVPN, config.Condition{
			Type:   config.ConditionDomain,
			Domain: "api.example.com",
		}),
		testRule("wildcard", config.ActionBlock, config.Condition{
			Type:     config.ConditionWildcardDomain,
			Wildcard: "example.com",
		}),
	)
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)
	allocations := testAllocations(t)

	plan, err := compilePolicy(compiled, testOptions6(), allocations)
	require.NoError(t, err)

	vpnRules := rulesWithMark(plan, allocations.byClass[classVPN].mark.Value)
	require.Len(t, vpnRules, 2, "an exact domain rule must emit one rule per family")
	assert.Equal(t, family4, vpnRules[0].family)
	assert.Equal(t, setDomains4, vpnRules[0].matches[0].set)
	assert.Equal(t, family6, vpnRules[1].family)
	assert.Equal(t, setDomains6, vpnRules[1].matches[0].set)

	blockRules := rulesWithMark(plan, allocations.byClass[classBlock].mark.Value)
	require.Len(t, blockRules, 2, "a wildcard block rule must emit one rule per family")
	assert.Equal(t, setDomainBlock4, blockRules[0].matches[0].set)
	assert.Equal(t, setDomainBlock6, blockRules[1].matches[0].set)

	assert.Empty(t, plan.nft.sets[setVPN4], "a domain rule must not fill the prefix set")
	assert.Empty(t, plan.nft.sets[setBlocked4], "a domain block rule must not fill the prefix set")
}

func TestCompilePolicyRejectsDomainWithCIDR(t *testing.T) {
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN,
			config.Condition{Type: config.ConditionDomain, Domain: "example.com"},
			cidrCondition("10.0.0.0/8")),
	))

	_, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrUnsupportedCondition)
}

func TestCompilePolicyRejectsDomainWithProtocol(t *testing.T) {
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN,
			config.Condition{Type: config.ConditionDomain, Domain: "example.com"},
			portCondition(config.ProtocolTCP, 443)),
	))

	_, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrUnsupportedCondition)
}

func TestCompilePolicyRejectsMultipleDomainConditions(t *testing.T) {
	compiled := mustCompile(t, includeConfig(
		testRule("two", config.ActionVPN,
			config.Condition{Type: config.ConditionDomain, Domain: "a.example.com"},
			config.Condition{Type: config.ConditionDomain, Domain: "b.example.com"}),
	))

	_, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.ErrorIs(t, err, backend.ErrUnsupportedCondition)
}

func TestCompilePolicyIPv6DomainRuleFollowsIPv6Setting(t *testing.T) {
	cfg := includeConfig(testRule("exact", config.ActionVPN, config.Condition{
		Type:   config.ConditionDomain,
		Domain: "example.com",
	}))

	compiled := mustCompile(t, cfg)
	plan, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.NoError(t, err)
	for _, rule := range plan.nft.rules {
		assert.NotEqual(t, family6, rule.family, "a disabled IPv6 policy must not emit v6 rules")
	}

	cfg.SplitTunnel.IPv6 = true
	compiled = mustCompile(t, cfg)
	plan, err = compilePolicy(compiled, testOptions6(), testAllocations(t))
	require.NoError(t, err)

	seen6 := false
	for _, rule := range plan.nft.rules {
		if rule.family == family6 && hasSetMatch(rule, setDomains6) {
			seen6 = true
		}
	}
	assert.True(t, seen6, "an IPv6-enabled domain rule must use the v6 domain set")
}

func rulesWithMark(plan *policyPlan, mark uint32) []nftRule {
	var rules []nftRule
	for _, rule := range plan.nft.rules {
		if rule.mark == mark {
			rules = append(rules, rule)
		}
	}
	return rules
}

func hasSetMatch(rule nftRule, want setName) bool {
	for _, match := range rule.matches {
		if match.set == want {
			return true
		}
	}
	return false
}

func TestCompilePolicyIPv6DisabledSkipsV6(t *testing.T) {
	cfg := includeConfig(testRule("vpn6", config.ActionVPN, cidrCondition("2001:db8::/32")))
	cfg.SplitTunnel.IPv6 = false
	compiled := mustCompile(t, cfg)

	plan, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.NoError(t, err)

	assert.Empty(t, plan.nft.sets[setVPN6], "a disabled IPv6 policy must not fill IPv6 sets")
	assert.Empty(t, plan.route.classes6, "a disabled IPv6 policy must not install v6 routes")
	for _, rule := range plan.nft.rules {
		assert.NotEqual(t, family6, rule.family, "a disabled IPv6 policy must not emit v6 rules")
	}

	last := plan.nft.rules[len(plan.nft.rules)-1]
	assert.Equal(t, family4, last.family, "the IPv4 default rule must still be installed")
}

func TestCompilePolicyRejectsKillSwitch(t *testing.T) {
	cfg := includeConfig(testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")))
	cfg.SplitTunnel.KillSwitch = config.KillSwitchSelective
	compiled := mustCompile(t, cfg)

	_, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.ErrorIs(t, err, backend.ErrNotImplemented)
}

func TestCompilePolicyAcceptsDNSTracking(t *testing.T) {
	cfg := includeConfig(testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")))
	cfg.SplitTunnel.DNS.TrackingEnabled = true
	compiled := mustCompile(t, cfg)

	_, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.NoError(t, err)
}

func TestCompilePolicyRejectsExitNodeMismatch(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{{
				ID:         "exit",
				Name:       "exit",
				Enabled:    true,
				Priority:   10,
				MatchMode:  config.MatchAll,
				Action:     config.ActionExitNode,
				ExitNodeID: "exit-a",
				Conditions: []config.Condition{cidrCondition("203.0.113.0/24")},
			}},
		},
	}
	compiled := mustCompile(t, cfg)

	options := testOptions()
	options.ExitNode = &backend.ExitNode{
		ID:     "exit-b",
		Target: backend.RouteTarget{Interface: "wt-exit"},
	}

	_, err := compilePolicy(compiled, options, testAllocations(t))
	require.ErrorIs(t, err, backend.ErrExitNodeUnavailable)
	var exitErr *backend.ExitNodeUnavailableError
	require.True(t, errors.As(err, &exitErr))
	assert.Equal(t, config.ExitNodeID("exit-a"), exitErr.Requested)
	assert.Equal(t, config.ExitNodeID("exit-b"), exitErr.Active)
}

func TestCompilePolicyRejectsMultipleExitNodes(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{
				{
					ID:         "exit-b",
					Name:       "exit-b",
					Enabled:    true,
					Priority:   20,
					MatchMode:  config.MatchAll,
					Action:     config.ActionExitNode,
					ExitNodeID: "exit-b",
					Conditions: []config.Condition{cidrCondition("203.0.113.0/24")},
				},
				{
					ID:         "exit-a",
					Name:       "exit-a",
					Enabled:    true,
					Priority:   10,
					MatchMode:  config.MatchAll,
					Action:     config.ActionExitNode,
					ExitNodeID: "exit-a",
					Conditions: []config.Condition{cidrCondition("198.51.100.0/24")},
				},
			},
		},
	}
	compiled := mustCompile(t, cfg)

	options := testOptions()
	options.ExitNode = &backend.ExitNode{
		ID:     "exit-a",
		Target: backend.RouteTarget{Interface: "wt-exit"},
	}

	_, err := compilePolicy(compiled, options, testAllocations(t))
	require.ErrorIs(t, err, backend.ErrMultipleExitNodes)
	var multiErr *backend.MultipleExitNodesError
	require.True(t, errors.As(err, &multiErr))
	assert.Equal(t, []config.ExitNodeID{"exit-a", "exit-b"}, multiErr.IDs)
}

func TestCompilePolicyExitNodeUnavailableIsFailClosed(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{{
				ID:         "exit",
				Name:       "exit",
				Enabled:    true,
				Priority:   10,
				MatchMode:  config.MatchAll,
				Action:     config.ActionExitNode,
				ExitNodeID: "exit-a",
				Conditions: []config.Condition{cidrCondition("203.0.113.0/24")},
			}},
		},
	}
	compiled := mustCompile(t, cfg)

	plan, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.NoError(t, err, "an unavailable exit node must install a fail-closed path")

	exit, ok := findRouteClass(plan, classExit)
	require.True(t, ok)
	assert.True(t, exit.protected)
	assert.Empty(t, exit.target.Interface)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		plan.nft.sets[setExit4])
}

func TestCompilePolicyRequiresTargetsForUsedActions(t *testing.T) {
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))

	_, err := compilePolicy(compiled, backend.PolicyOptions{
		Direct: backend.RouteTarget{Interface: "eth0"},
	}, testAllocations(t))
	require.ErrorIs(t, err, backend.ErrInvalidPolicyOption)

	compiled = mustCompile(t, includeConfig())
	_, err = compilePolicy(compiled, backend.PolicyOptions{
		VPN: backend.RouteTarget{Interface: "wt0"},
	}, testAllocations(t))
	require.ErrorIs(t, err, backend.ErrInvalidPolicyOption,
		"the include-mode default needs the direct target it routes to")
}

func TestCompilePolicyCIDROnlyUsesOwnedSet(t *testing.T) {
	allocations := testAllocations(t)
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	plan, err := compilePolicy(compiled, testOptions(), allocations)
	require.NoError(t, err)

	rule := findRuleWithMark(t, plan, allocations.byClass[classVPN].mark.Value)
	require.Len(t, rule.matches, 1)
	assert.Equal(t, setVPN4, rule.matches[0].set)
	assert.False(t, rule.matches[0].prefix.IsValid())
}

func TestCompilePolicyProtocolAndCIDRUsesLiteralPrefix(t *testing.T) {
	allocations := testAllocations(t)
	compiled := mustCompile(t, includeConfig(
		testRule("vpn-https", config.ActionVPN,
			cidrCondition("10.0.0.0/8"), portCondition(config.ProtocolTCP, 443)),
	))
	plan, err := compilePolicy(compiled, testOptions(), allocations)
	require.NoError(t, err)

	rule := findRuleWithMark(t, plan, allocations.byClass[classVPN].mark.Value)
	require.Len(t, rule.matches, 2)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), rule.matches[0].prefix)
	assert.Equal(t, config.ProtocolTCP, rule.matches[1].protocol)
	assert.Equal(t, uint16(443), rule.matches[1].port)
}

func TestCompilePolicyMatchAnyExpandsToRules(t *testing.T) {
	allocations := testAllocations(t)
	rule := testRule("any", config.ActionVPN,
		cidrCondition("10.0.0.0/8"), portCondition(config.ProtocolUDP, 53))
	rule.MatchMode = config.MatchAny

	compiled := mustCompile(t, includeConfig(rule))
	plan, err := compilePolicy(compiled, testOptions(), allocations)
	require.NoError(t, err)

	vpnMark := allocations.byClass[classVPN].mark.Value
	count := 0
	for _, nftRule := range plan.nft.rules {
		if nftRule.mark == vpnMark {
			count++
		}
	}
	assert.Equal(t, 2, count, "an any rule must expand to one rule per branch")
}

func findRuleWithMark(t *testing.T, plan *policyPlan, mark uint32) nftRule {
	t.Helper()
	for _, rule := range plan.nft.rules {
		if rule.mark == mark {
			return rule
		}
	}
	require.FailNow(t, "no classification rule found", "mark %#x", mark)
	return nftRule{}
}

func TestCompilePolicyAllocatorUsage(t *testing.T) {
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	plan, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.NoError(t, err)

	expected := map[routeClass]struct {
		table    TableID
		priority RulePriority
		mark     uint32
	}{
		classVPN:    {table: TableID(splitTableBase), priority: RulePriority(splitPriorityBase), mark: nbnet.ControlPlaneMark | 1},
		classDirect: {table: TableID(splitTableBase + 1), priority: RulePriority(splitPriorityBase + 1), mark: nbnet.ControlPlaneMark | 2},
		classBlock:  {table: TableID(splitTableBase + 2), priority: RulePriority(splitPriorityBase + 2), mark: nbnet.ControlPlaneMark | 3},
		classExit:   {table: TableID(splitTableBase + 3), priority: RulePriority(splitPriorityBase + 3), mark: nbnet.ControlPlaneMark | 4},
	}

	for class, want := range expected {
		allocation := testAllocations(t).byClass[class]
		assert.Equal(t, want.table, allocation.table, "class %s table", class)
		assert.Equal(t, want.priority, allocation.priority, "class %s priority", class)
		assert.Equal(t, want.mark, allocation.mark.Value, "class %s mark", class)
		assert.Equal(t, ^uint32(0), allocation.mark.Mask)
	}

	for _, routeClass := range plan.route.classes {
		allocation := routeClass.allocation
		assert.GreaterOrEqual(t, allocation.table, TableID(splitTableBase))
		assert.Less(t, allocation.table, TableID(splitTableBase+splitTableSlots))
		assert.Greater(t, allocation.priority, upstreamMainPriority)
		assert.Less(t, allocation.priority, upstreamVPNPriority)
	}
}

func TestCompilePolicyBypassRulesComeFirst(t *testing.T) {
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.0.0.0/8")),
	))
	plan, err := compilePolicy(compiled, testOptions(), testAllocations(t))
	require.NoError(t, err)

	require.Len(t, plan.nft.rules, len(bypassPrefixes)+2)
	for i, prefix := range bypassPrefixes {
		assert.True(t, plan.nft.rules[i].bypass)
		assert.Equal(t, prefix, plan.nft.rules[i].matches[0].prefix)
	}
}

func TestCompilePolicyDisabledReturnsEmptyPlan(t *testing.T) {
	compiled := &policy.CompiledPolicy{Enabled: false, Mode: config.ModeStandard}
	plan, err := compilePolicy(compiled, backend.PolicyOptions{}, testAllocations(t))
	require.NoError(t, err)
	assert.Empty(t, plan.nft.rules)
	assert.Empty(t, plan.route.classes)
}

func TestCompilePolicyProtocolRulePrefixesStayOutOfActionSet(t *testing.T) {
	allocations := testAllocations(t)
	compiled := mustCompile(t, includeConfig(
		testRule("vpn", config.ActionVPN, cidrCondition("10.9.3.0/24")),
		testRule("vpn-udp", config.ActionVPN,
			cidrCondition("10.9.6.0/24"), portCondition(config.ProtocolUDP, 5353)),
	))

	plan, err := compilePolicy(compiled, testOptions(), allocations)
	require.NoError(t, err)

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.9.3.0/24")},
		plan.nft.sets[setVPN4],
		"a protocol-qualified prefix must not widen an unrelated prefix-only rule")

	foundLiteral := false
	for _, rule := range plan.nft.rules {
		if rule.mark != allocations.byClass[classVPN].mark.Value {
			continue
		}
		for _, match := range rule.matches {
			if match.prefix == netip.MustParsePrefix("10.9.6.0/24") {
				foundLiteral = true
			}
		}
	}
	assert.True(t, foundLiteral, "the protocol rule must use a literal prefix match")
}
