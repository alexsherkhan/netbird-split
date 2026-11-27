//go:build linux && !android

package linux

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func killSwitchTestConfig(mode config.KillSwitchMode, ipv6 bool) *config.Config {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeInclude,
			DefaultAction: config.ActionDirect,
			KillSwitch:    mode,
			IPv6:          ipv6,
			Rules: []config.Rule{
				testRule("vpn", config.ActionVPN, cidrCondition("10.9.3.0/24")),
				testRule("exit", config.ActionExitNode, cidrCondition("10.9.1.0/24")),
				testRule("direct", config.ActionDirect, cidrCondition("10.9.4.0/24")),
				testRule("block", config.ActionBlock, cidrCondition("10.9.2.0/24")),
			},
		},
	}
	cfg.SplitTunnel.Rules[1].ExitNodeID = "exit-1"
	return cfg
}

func killSwitchCompile(t *testing.T, cfg *config.Config) *policyPlan {
	t.Helper()

	compiled, err := policy.CompileWith(cfg, policy.Constraints{
		ControlPrefixes: []netip.Prefix{
			netip.MustParsePrefix("10.9.7.0/24"),
			netip.MustParsePrefix("fd00:9:7::/64"),
		},
	})
	require.NoError(t, err)

	target6 := backend.RouteTarget6{
		Interface: "wt0",
		Source:    netip.MustParseAddr("fd00:3::1"),
	}
	options := backend.PolicyOptions{
		VPN:     backend.RouteTarget{Interface: "wt0"},
		Direct:  backend.RouteTarget{Interface: "eth0"},
		VPN6:    backend.RouteTarget6{Interface: "wt0", Source: netip.MustParseAddr("fd00:3::1")},
		Direct6: backend.RouteTarget6{Interface: "eth0", Source: netip.MustParseAddr("fd00:1::1")},
		ExitNode: &backend.ExitNode{
			ID:      "exit-1",
			Target:  backend.RouteTarget{Interface: "wt0"},
			Target6: &target6,
		},
		DNSResolvers: []netip.Prefix{
			netip.MustParsePrefix("10.0.1.53/32"),
			netip.MustParsePrefix("fd00:1::53/128"),
		},
	}

	plan, err := compilePolicy(compiled, options, testAllocations(t))
	require.NoError(t, err)
	return plan
}

func killRulesForFamily(rules []nftKillRule, family nftFamily) []nftKillRule {
	var out []nftKillRule
	for _, rule := range rules {
		if rule.family == family {
			out = append(out, rule)
		}
	}
	return out
}

func findKillRule(rules []nftKillRule, predicate func(nftKillRule) bool) (nftKillRule, bool) {
	for _, rule := range rules {
		if predicate(rule) {
			return rule, true
		}
	}
	return nftKillRule{}, false
}

func killRuleMatchesSet(rule nftKillRule, set setName) bool {
	for _, match := range rule.matches {
		if match.set == set {
			return true
		}
	}
	return false
}

func TestKillSwitchDisabledEmitsNoRules(t *testing.T) {
	for _, mode := range []config.KillSwitchMode{config.KillSwitchDisabled, ""} {
		cfg := killSwitchTestConfig(mode, true)
		cfg.SplitTunnel.KillSwitch = mode
		plan := killSwitchCompile(t, cfg)

		assert.Empty(t, plan.nft.killswitch, "mode %q must not install kill switch rules", mode)
	}
}

func TestKillSwitchSelectiveRuleSet(t *testing.T) {
	plan := killSwitchCompile(t, killSwitchTestConfig(config.KillSwitchSelective, false))
	rules := plan.nft.killswitch
	require.NotEmpty(t, rules)
	for _, rule := range rules {
		assert.Equal(t, family4, rule.family, "IPv6 is disabled in this policy")
	}

	_, ok := findKillRule(rules, func(rule nftKillRule) bool {
		return rule.verdict == verdictDrop && len(rule.matches) == 0 && rule.mark == nil
	})
	assert.False(t, ok, "selective mode must not drop unmatched traffic")

	dropSets := make(map[setName]bool)
	for _, rule := range rules {
		if rule.verdict != verdictDrop {
			continue
		}
		require.Len(t, rule.matches, 1)
		dropSets[rule.matches[0].set] = true
	}
	assert.True(t, dropSets[setVPN4], "VPN destinations must be blocked without the protected mark")
	assert.True(t, dropSets[setExit4], "exit destinations must be blocked without the protected mark")
	assert.True(t, dropSets[setBlocked4], "blocked destinations must stay blocked")
	assert.True(t, dropSets[setDomains4], "VPN domains must be blocked without the protected mark")
	assert.False(t, dropSets[setDirect4], "DIRECT destinations must stay available")

	allocations := testAllocations(t)
	for _, class := range []routeClass{classVPN, classExit} {
		mark := allocations.byClass[class].mark.Value
		_, ok := findKillRule(rules, func(rule nftKillRule) bool {
			return rule.verdict == verdictAccept && rule.mark != nil && *rule.mark == mark
		})
		assert.True(t, ok, "%s traffic must be accepted and left to the protected route table", class)
	}

	loopback, ok := findKillRule(rules, func(rule nftKillRule) bool {
		return rule.verdict == verdictAccept &&
			len(rule.matches) == 1 &&
			rule.matches[0].prefix == netip.MustParsePrefix("127.0.0.0/8")
	})
	require.True(t, ok, "loopback must never be blocked")
	assert.Equal(t, verdictAccept, loopback.verdict)
}

func TestKillSwitchGlobalRuleSet(t *testing.T) {
	plan := killSwitchCompile(t, killSwitchTestConfig(config.KillSwitchGlobal, true))
	for _, family := range []nftFamily{family4, family6} {
		rules := killRulesForFamily(plan.nft.killswitch, family)
		require.NotEmpty(t, rules)
		last := rules[len(rules)-1]
		assert.Equal(t, verdictDrop, last.verdict, "%v must end with a drop-all rule", family)
		assert.Empty(t, last.matches)
		assert.Nil(t, last.mark)

		_, ok := findKillRule(rules, func(rule nftKillRule) bool {
			return rule.verdict == verdictAccept &&
				killRuleMatchesSet(rule, killSwitchControlSet(family))
		})
		assert.True(t, ok, "%v must allow control and transport prefixes", family)

		_, ok = findKillRule(rules, func(rule nftKillRule) bool {
			return rule.verdict == verdictAccept &&
				killRuleMatchesSet(rule, setForClassFamily(classDirect, family))
		})
		assert.False(t, ok, "global mode must not allow general DIRECT traffic")

		resolver := netip.MustParsePrefix("10.0.1.53/32")
		if family == family6 {
			resolver = netip.MustParsePrefix("fd00:1::53/128")
		}
		for _, protocol := range []config.Protocol{config.ProtocolUDP, config.ProtocolTCP} {
			_, ok := findKillRule(rules, func(rule nftKillRule) bool {
				return rule.verdict == verdictAccept &&
					len(rule.matches) == 1 &&
					rule.matches[0].prefix == resolver &&
					rule.matches[0].protocol == protocol &&
					rule.matches[0].port == 53
			})
			assert.True(t, ok, "%v DNS %s resolver must be reachable", family, protocol)
		}
	}

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.9.7.0/24")},
		plan.nft.sets[setKillSwitchControl4])
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("fd00:9:7::/64")},
		plan.nft.sets[setKillSwitchControl6])
}

func TestKillSwitchStrictAllowsExplicitDirect(t *testing.T) {
	plan := killSwitchCompile(t, killSwitchTestConfig(config.KillSwitchStrict, false))
	rules := plan.nft.killswitch

	_, ok := findKillRule(rules, func(rule nftKillRule) bool {
		return rule.verdict == verdictAccept && killRuleMatchesSet(rule, setDirect4)
	})
	assert.True(t, ok, "strict mode must allow explicitly configured DIRECT prefixes")

	_, ok = findKillRule(rules, func(rule nftKillRule) bool {
		return rule.verdict == verdictAccept && killRuleMatchesSet(rule, setDomainDirect4)
	})
	assert.True(t, ok, "strict mode must allow resolved DIRECT domains")

	last := rules[len(rules)-1]
	assert.Equal(t, verdictDrop, last.verdict, "strict mode must end with a drop-all rule")
}

func TestKillSwitchIPv6DisabledSkipsV6(t *testing.T) {
	plan := killSwitchCompile(t, killSwitchTestConfig(config.KillSwitchGlobal, false))

	for _, rule := range plan.nft.killswitch {
		assert.Equal(t, family4, rule.family, "a disabled IPv6 policy must not emit v6 kill switch rules")
	}
	_, ok := plan.nft.sets[setKillSwitchControl6]
	assert.False(t, ok, "a disabled IPv6 policy must not populate the v6 control set")
}

func TestKillSwitchUsesOnlyOwnedSets(t *testing.T) {
	owned := make(map[setName]struct{}, len(policySetNames())+len(domainSetNames()))
	for _, name := range policySetNames() {
		owned[name] = struct{}{}
	}
	for _, name := range domainSetNames() {
		owned[name] = struct{}{}
	}

	for _, mode := range []config.KillSwitchMode{
		config.KillSwitchSelective,
		config.KillSwitchGlobal,
		config.KillSwitchStrict,
	} {
		plan := killSwitchCompile(t, killSwitchTestConfig(mode, true))
		for _, rule := range plan.nft.killswitch {
			for _, match := range rule.matches {
				if match.set == "" {
					continue
				}
				_, ok := owned[match.set]
				assert.True(t, ok, "kill switch rule references unowned set %q", match.set)
			}
		}
	}
}

func TestKillSwitchRejectsInvalidState(t *testing.T) {
	cfg := killSwitchTestConfig(config.KillSwitchGlobal, false)
	compiled := mustCompile(t, cfg)
	invalid := *compiled
	invalid.KillSwitch = config.KillSwitchMode("sometimes")

	_, _, err := compileKillSwitch(&invalid, testOptions(), testAllocations(t), false)
	require.ErrorIs(t, err, backend.ErrInvalidPolicyOption)

	options := testOptions()
	options.DNSResolvers = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	_, _, err = compileKillSwitch(compiled, options, testAllocations(t), false)
	require.ErrorIs(t, err, backend.ErrInvalidPolicyOption,
		"a DNS resolver with host bits set must be rejected")
}

func TestKillSwitchDisabledPolicyEmitsNoRules(t *testing.T) {
	cfg := killSwitchTestConfig(config.KillSwitchGlobal, false)
	cfg.SplitTunnel.Enabled = false
	cfg.SplitTunnel.Mode = config.ModeStandard
	cfg.SplitTunnel.DefaultAction = config.ActionDefault
	cfg.SplitTunnel.Rules = nil
	compiled := mustCompile(t, cfg)

	rules, sets, err := compileKillSwitch(compiled, testOptions(), testAllocations(t), false)
	require.NoError(t, err)
	assert.Empty(t, rules)
	assert.Empty(t, sets)
}

func TestKillSwitchRuleExpressions(t *testing.T) {
	sets := map[setName]*nftables.Set{
		setKillSwitchControl4: {Name: string(setKillSwitchControl4), ID: 7},
		setVPN4:               {Name: string(setVPN4), ID: 8},
	}
	mark := uint32(0x10)

	rule := nftKillRule{family: family4, mark: &mark, verdict: verdictDrop}
	exprs, err := nftKillRuleExprs(rule, sets)
	require.NoError(t, err)
	verdict, ok := exprs[len(exprs)-1].(*expr.Verdict)
	require.True(t, ok)
	assert.Equal(t, expr.VerdictDrop, verdict.Kind)

	markMatches := 0
	for _, item := range exprs {
		if cmp, ok := item.(*expr.Cmp); ok && len(cmp.Data) == 4 &&
			binaryutil.NativeEndian.Uint32(cmp.Data) == mark {
			markMatches++
		}
	}
	assert.Equal(t, 1, markMatches, "a kill switch rule must match the protected mark exactly once")

	for _, verdictKind := range []struct {
		verdict nftVerdict
		kind    expr.VerdictKind
	}{
		{verdictAccept, expr.VerdictAccept},
		{verdictReturn, expr.VerdictReturn},
	} {
		exprs, err := nftKillRuleExprs(nftKillRule{family: family4, verdict: verdictKind.verdict}, sets)
		require.NoError(t, err)
		verdict, ok := exprs[len(exprs)-1].(*expr.Verdict)
		require.True(t, ok)
		assert.Equal(t, verdictKind.kind, verdict.Kind)
	}
}

func TestKillSwitchRuleExpressionRejectsForeignSet(t *testing.T) {
	rule := nftKillRule{
		family:  family4,
		matches: []nftMatch{{set: setVPN6}},
		verdict: verdictDrop,
	}
	_, err := nftKillRuleExprs(rule, map[setName]*nftables.Set{
		setVPN6: {Name: string(setVPN6), ID: 1},
	})
	require.Error(t, err, "a v6 set must not be used in a v4 kill switch rule")

	_, err = nftKillRuleExprs(nftKillRule{
		family:  family4,
		matches: []nftMatch{{set: setKillSwitchControl4}},
		verdict: verdictDrop,
	}, nil)
	require.Error(t, err, "a missing owned set must fail closed")
}
