package domain

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func TestRulesFromPolicyExtractsExactAndWildcard(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{
				{
					ID:        "exact",
					Name:      "exact",
					Enabled:   true,
					Priority:  10,
					MatchMode: config.MatchAll,
					Action:    config.ActionVPN,
					Conditions: []config.Condition{{
						Type:   config.ConditionDomain,
						Domain: "api.example.com",
					}},
				},
				{
					ID:        "wild",
					Name:      "wild",
					Enabled:   true,
					Priority:  20,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:     config.ConditionWildcardDomain,
						Wildcard: "example.com",
					}},
				},
				{
					ID:        "cidr",
					Name:      "cidr",
					Enabled:   true,
					Priority:  30,
					MatchMode: config.MatchAll,
					Action:    config.ActionVPN,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.0.0.0/8"),
					}},
				},
			},
		},
	}
	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)

	rules, conflicts, err := RulesFromPolicy(compiled)
	require.NoError(t, err)
	assert.Empty(t, conflicts)
	assert.Equal(t, 2, rules.Count())

	rule, ok := rules.Match("api.example.com")
	require.True(t, ok)
	assert.Equal(t, config.ActionVPN, rule.Action)

	rule, ok = rules.Match("sub.example.com")
	require.True(t, ok)
	assert.Equal(t, config.ActionDirect, rule.Action)

	if _, ok := rules.Match("example.com"); ok {
		t.Fatal("wildcard must not match the apex")
	}
}

func TestRulesFromPolicyRejectsMultipleDomains(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{{
				ID:        "two",
				Name:      "two",
				Enabled:   true,
				Priority:  10,
				MatchMode: config.MatchAll,
				Action:    config.ActionVPN,
				Conditions: []config.Condition{
					{Type: config.ConditionDomain, Domain: "a.example.com"},
					{Type: config.ConditionDomain, Domain: "b.example.com"},
				},
			}},
		},
	}
	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)

	_, _, err = RulesFromPolicy(compiled)
	require.Error(t, err)
}

func TestRulesFromPolicyRejectsDomainExitNode(t *testing.T) {
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
				Conditions: []config.Condition{{
					Type:   config.ConditionDomain,
					Domain: "example.com",
				}},
			}},
		},
	}
	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)

	_, _, err = RulesFromPolicy(compiled)
	require.Error(t, err)
}

func TestRulesFromPolicyReportsRuleConflict(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{
				{
					ID:        "vpn",
					Name:      "vpn",
					Enabled:   true,
					Priority:  10,
					MatchMode: config.MatchAll,
					Action:    config.ActionVPN,
					Conditions: []config.Condition{{
						Type:   config.ConditionDomain,
						Domain: "example.com",
					}},
				},
				{
					ID:        "direct",
					Name:      "direct",
					Enabled:   true,
					Priority:  20,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:   config.ConditionDomain,
						Domain: "example.com",
					}},
				},
			},
		},
	}
	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)

	rules, conflicts, err := RulesFromPolicy(compiled)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.Equal(t, "example.com", conflicts[0].Pattern)
	assert.Equal(t, []config.Action{config.ActionVPN, config.ActionDirect}, conflicts[0].Actions)

	rule, ok := rules.Match("example.com")
	require.True(t, ok)
	assert.Equal(t, config.ActionVPN, rule.Action, "the first rule keeps precedence")
}

func TestRulesHandleIDNAndPunycode(t *testing.T) {
	rules := NewRules()
	rules.add(Rule{
		Pattern: Pattern{Name: "xn--mnchen-3ya.example"},
		Action:  config.ActionVPN,
		RuleID:  "idn",
	}, 0)

	unicodeName, err := Normalize("münchen.example")
	require.NoError(t, err)
	rule, ok := rules.Match(unicodeName)
	require.True(t, ok)
	assert.Equal(t, config.ActionVPN, rule.Action)
}
