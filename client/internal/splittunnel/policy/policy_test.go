package policy

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

func TestCompileDeterministic(t *testing.T) {
	cfg := testConfig(
		testRule("rule-b", 50, config.ActionVPN, domainCondition("b.example.com")),
		testRule("rule-a", 50, config.ActionVPN, domainCondition("a.example.com")),
		testRule("rule-c", 10, config.ActionDirect, wildcardCondition("*.example.com")),
	)
	cfg.SplitTunnel.KillSwitch = config.KillSwitchStrict
	cfg.SplitTunnel.IPv6 = true

	first, err := Compile(cfg)
	require.NoError(t, err)
	second, err := Compile(cfg)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(first, second))
	assert.True(t, first.Enabled)
	assert.Equal(t, config.KillSwitchStrict, first.KillSwitch)
	assert.True(t, first.IPv6)
	require.Len(t, first.Rules, 3)
	assert.Equal(t, config.RuleID("rule-c"), first.Rules[0].ID)
	assert.Equal(t, config.RuleID("rule-a"), first.Rules[1].ID)
	assert.Equal(t, config.RuleID("rule-b"), first.Rules[2].ID)
}

func TestCompilePartitionsAndResolves(t *testing.T) {
	exitID := config.ExitNodeID("exit-1")
	defaultRule := testRule("default-rule", 500, config.ActionDefault,
		domainCondition("default.example"))
	disabled := testRule("disabled", 1, config.ActionVPN, domainCondition("disabled.example"))
	disabled.Enabled = false
	exitRule := testRule("exit", 400, config.ActionExitNode, domainCondition("exit.example"))
	exitRule.ExitNodeID = exitID

	cfg := testConfig(
		testRule("block", 100, config.ActionBlock, domainCondition("blocked.example")),
		testRule("vpn", 200, config.ActionVPN, domainCondition("vpn.example")),
		defaultRule,
		disabled,
		exitRule,
	)
	cfg.SplitTunnel.DefaultAction = config.ActionDirect

	compiled, err := Compile(cfg)
	require.NoError(t, err)

	require.Len(t, compiled.BlockRules, 1)
	assert.Equal(t, config.RuleID("block"), compiled.BlockRules[0].ID)
	require.Len(t, compiled.Rules, 3)
	assert.Equal(t, config.RuleID("vpn"), compiled.Rules[0].ID)
	assert.Equal(t, config.RuleID("exit"), compiled.Rules[1].ID)
	assert.Equal(t, config.RuleID("default-rule"), compiled.Rules[2].ID)
	assert.Equal(t, config.ActionDirect, compiled.Rules[2].Action,
		"default action rule must resolve to the global default")
	assert.Equal(t, config.ActionExitNode, compiled.Rules[1].Action)
	assert.Equal(t, exitID, compiled.Rules[1].ExitNodeID)

	for _, rule := range compiled.Rules {
		assert.NotEqual(t, config.RuleID("disabled"), rule.ID)
	}
}

func TestCompileStandardMode(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Mode: config.ModeStandard,
		},
	}
	compiled, err := Compile(cfg)
	require.NoError(t, err)
	assert.False(t, compiled.Enabled)
	assert.Equal(t, config.ActionDefault, compiled.DefaultAction)
	assert.Equal(t, config.KillSwitchDisabled, compiled.KillSwitch)
	assert.Empty(t, compiled.Rules)
	assert.Empty(t, compiled.BlockRules)

	decision := compiled.Evaluate(Flow{})
	assert.Equal(t, config.ActionDefault, decision.Action)
	assert.Equal(t, LayerDefault, decision.Layer)
}

func TestCompileDisabledEngineRetainsRules(t *testing.T) {
	cfg := testConfig(testRule("vpn", 1, config.ActionVPN, domainCondition("vpn.example")))
	cfg.SplitTunnel.Mode = config.ModeInclude
	cfg.SplitTunnel.DefaultAction = config.ActionDirect
	cfg.SplitTunnel.Enabled = false

	compiled, err := Compile(cfg)
	require.NoError(t, err)
	assert.False(t, compiled.Enabled)
	assert.Len(t, compiled.Rules, 1)
}

func TestCompileRejects(t *testing.T) {
	invalid := testConfig(
		testRule("same", 1, config.ActionVPN, domainCondition("a.example")),
		testRule("same", 2, config.ActionVPN, domainCondition("b.example")),
	)
	tests := []struct {
		name        string
		cfg         *config.Config
		constraints Constraints
		wantErr     string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: "config is nil",
		},
		{
			name:    "invalid config",
			cfg:     invalid,
			wantErr: "duplicate rule ID",
		},
		{
			name:        "invalid prefix",
			cfg:         testConfig(),
			constraints: Constraints{ControlPrefixes: []netip.Prefix{{}}},
			wantErr:     "prefix is invalid",
		},
		{
			name:        "prefix with host bits",
			cfg:         testConfig(),
			constraints: Constraints{ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}},
			wantErr:     "host bits",
		},
		{
			name:        "mapped prefix",
			cfg:         testConfig(),
			constraints: Constraints{PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}},
			wantErr:     "plain IPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileWith(tt.cfg, tt.constraints)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestCompileConstraints(t *testing.T) {
	cfg := testConfig()
	compiled, err := CompileWith(cfg, Constraints{
		ControlPrefixes: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		PrivatePrefixes: []netip.Prefix{
			netip.MustParsePrefix("172.16.0.0/12"),
		},
	})
	require.NoError(t, err)

	require.Len(t, compiled.Control, 2)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), compiled.Control[0].Prefix)
	assert.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), compiled.Control[1].Prefix)
	assert.Equal(t, config.ActionDirect, compiled.Control[0].Action)
	require.Len(t, compiled.Mandatory, 1)
	assert.Equal(t, config.ActionVPN, compiled.Mandatory[0].Action)
}

func TestCompileAllowsControlAndPrivateOverlap(t *testing.T) {
	cfg := testConfig()
	compiled, err := CompileWith(cfg, Constraints{
		ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/32")},
		PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	require.NoError(t, err)

	decision := compiled.Evaluate(Flow{Destination: netip.MustParseAddr("10.1.2.3")})
	assert.Equal(t, config.ActionDirect, decision.Action)
	assert.Equal(t, LayerControl, decision.Layer)

	decision = compiled.Evaluate(Flow{Destination: netip.MustParseAddr("10.9.9.9")})
	assert.Equal(t, config.ActionVPN, decision.Action)
	assert.Equal(t, LayerMandatory, decision.Layer)
}

func TestCompileConflicts(t *testing.T) {
	t.Run("same match different actions", func(t *testing.T) {
		cfg := testConfig(
			testRule("a", 10, config.ActionVPN, domainCondition("same.example")),
			testRule("b", 20, config.ActionDirect, domainCondition("same.example")),
		)
		compiled, err := Compile(cfg)
		require.NoError(t, err)
		require.Len(t, compiled.Conflicts, 1)
		assert.Equal(t, config.RuleID("b"), compiled.Conflicts[0].RuleID)
		assert.Equal(t, config.RuleID("a"), compiled.Conflicts[0].OtherRuleID)
		assert.Equal(t, ConflictSameMatchDifferentAction, compiled.Conflicts[0].Reason)
	})

	t.Run("condition order is irrelevant", func(t *testing.T) {
		cfg := testConfig(
			testRule("a", 10, config.ActionVPN,
				domainCondition("same.example"), cidrCondition("192.0.2.0/24")),
			testRule("b", 20, config.ActionDirect,
				cidrCondition("192.0.2.0/24"), domainCondition("same.example")),
		)
		compiled, err := Compile(cfg)
		require.NoError(t, err)
		require.Len(t, compiled.Conflicts, 1)
		assert.Equal(t, ConflictSameMatchDifferentAction, compiled.Conflicts[0].Reason)
	})

	t.Run("block shadows rule", func(t *testing.T) {
		cfg := testConfig(
			testRule("vpn", 1, config.ActionVPN, domainCondition("blocked.example")),
			testRule("block", 100, config.ActionBlock, domainCondition("blocked.example")),
		)
		compiled, err := Compile(cfg)
		require.NoError(t, err)
		require.Len(t, compiled.Conflicts, 1)
		assert.Equal(t, config.RuleID("vpn"), compiled.Conflicts[0].RuleID)
		assert.Equal(t, config.RuleID("block"), compiled.Conflicts[0].OtherRuleID)
		assert.Equal(t, ConflictBlockOverrides, compiled.Conflicts[0].Reason)
	})

	t.Run("same action is not a conflict", func(t *testing.T) {
		cfg := testConfig(
			testRule("a", 10, config.ActionVPN, domainCondition("same.example")),
			testRule("b", 20, config.ActionVPN, domainCondition("same.example")),
		)
		compiled, err := Compile(cfg)
		require.NoError(t, err)
		assert.Empty(t, compiled.Conflicts)
	})

	t.Run("different exit nodes conflict", func(t *testing.T) {
		first := testRule("a", 10, config.ActionExitNode, domainCondition("exit.example"))
		first.ExitNodeID = "exit-a"
		second := testRule("b", 20, config.ActionExitNode, domainCondition("exit.example"))
		second.ExitNodeID = "exit-b"
		compiled, err := Compile(testConfig(first, second))
		require.NoError(t, err)
		require.Len(t, compiled.Conflicts, 1)
		assert.Equal(t, ConflictSameMatchDifferentAction, compiled.Conflicts[0].Reason)
		assert.Contains(t, compiled.Conflicts[0].Detail, "exit-a")
		assert.Contains(t, compiled.Conflicts[0].Detail, "exit-b")
	})

	t.Run("mandatory constraint", func(t *testing.T) {
		cfg := testConfig(
			testRule("direct", 10, config.ActionDirect, cidrCondition("10.1.0.0/16")),
			testRule("vpn", 20, config.ActionVPN, cidrCondition("10.2.0.0/16")),
		)
		compiled, err := CompileWith(cfg, Constraints{
			PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		})
		require.NoError(t, err)
		require.Len(t, compiled.Conflicts, 1)
		assert.Equal(t, config.RuleID("direct"), compiled.Conflicts[0].RuleID)
		assert.Equal(t, ConflictMandatoryOverrides, compiled.Conflicts[0].Reason)
	})

	t.Run("mandatory conflicts are deduplicated", func(t *testing.T) {
		cfg := testConfig(
			testRule("direct", 10, config.ActionDirect, cidrCondition("10.1.0.0/16")),
		)
		compiled, err := CompileWith(cfg, Constraints{
			PrivatePrefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("10.1.0.0/16"),
			},
		})
		require.NoError(t, err)
		require.Len(t, compiled.Conflicts, 1)
		assert.Equal(t, ConflictMandatoryOverrides, compiled.Conflicts[0].Reason)
	})

	t.Run("control constraint", func(t *testing.T) {
		cfg := testConfig(
			testRule("vpn", 10, config.ActionVPN, cidrCondition("192.0.2.0/24")),
		)
		compiled, err := CompileWith(cfg, Constraints{
			ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		})
		require.NoError(t, err)
		require.Len(t, compiled.Conflicts, 1)
		assert.Equal(t, ConflictControlOverrides, compiled.Conflicts[0].Reason)
	})

	t.Run("composite cidr is not a structural constraint conflict", func(t *testing.T) {
		cfg := testConfig(testRule("composite", 10, config.ActionDirect, config.Condition{
			Type: config.ConditionAll,
			Children: []config.Condition{
				cidrCondition("10.1.0.0/16"),
			},
		}))
		compiled, err := CompileWith(cfg, Constraints{
			PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		})
		require.NoError(t, err)
		assert.Empty(t, compiled.Conflicts)
	})
}

func TestCompileCloneIsolation(t *testing.T) {
	uid := config.UID(1000)
	cfg := testConfig(testRule("rule", 1, config.ActionVPN, config.Condition{
		Type: config.ConditionUID,
		UID:  &uid,
	}))
	compiled, err := Compile(cfg)
	require.NoError(t, err)

	*cfg.SplitTunnel.Rules[0].Conditions[0].UID = 2000
	cfg.SplitTunnel.Rules[0].Conditions[0].Type = config.ConditionSnapID

	require.Len(t, compiled.Rules, 1)
	require.Len(t, compiled.Rules[0].Conditions, 1)
	assert.Equal(t, config.ConditionUID, compiled.Rules[0].Conditions[0].Type)
	require.NotNil(t, compiled.Rules[0].Conditions[0].UID)
	assert.Equal(t, config.UID(1000), *compiled.Rules[0].Conditions[0].UID)
}

func TestCompileEmptyRules(t *testing.T) {
	compiled, err := Compile(testConfig())
	require.NoError(t, err)
	assert.Empty(t, compiled.Rules)
	assert.Empty(t, compiled.BlockRules)
	assert.Empty(t, compiled.Conflicts)
	assert.Equal(t, config.ActionDirect, compiled.DefaultAction)
}

func TestRuleSignatureOrderIndependent(t *testing.T) {
	first := testRule("a", 1, config.ActionVPN,
		domainCondition("same.example"), cidrCondition("192.0.2.0/24"))
	second := testRule("b", 2, config.ActionVPN,
		cidrCondition("192.0.2.0/24"), domainCondition("same.example"))

	cfg := testConfig(first, second)
	compiled, err := Compile(cfg)
	require.NoError(t, err)
	require.Len(t, compiled.Rules, 2)
	assert.Equal(t, compiled.Rules[0].signature, compiled.Rules[1].signature)
}

func TestConditionSignaturesDistinguishValues(t *testing.T) {
	values := []config.Condition{
		domainCondition("a.example"),
		domainCondition("b.example"),
		cidrCondition("192.0.2.0/24"),
		cidrCondition("192.0.2.0/25"),
		portCondition("tcp", 443),
		portCondition("udp", 443),
		uidCondition(0),
		uidCondition(1000),
	}
	seen := make(map[string]struct{}, len(values))
	for i := range values {
		signature := conditionSignature(&values[i])
		_, duplicate := seen[signature]
		assert.False(t, duplicate, "duplicate signature for %+v", values[i])
		seen[signature] = struct{}{}
	}

	unknown := config.Condition{Type: "unknown"}
	assert.Equal(t, `unknown=""`, conditionSignature(&unknown))
	assert.Empty(t, conditionValue(&unknown))
}

func TestConflictReasonStrings(t *testing.T) {
	reasons := []ConflictReason{
		ConflictSameMatchDifferentAction,
		ConflictBlockOverrides,
		ConflictMandatoryOverrides,
		ConflictControlOverrides,
	}
	seen := make(map[string]struct{}, len(reasons))
	for _, reason := range reasons {
		require.NotEmpty(t, string(reason))
		_, duplicate := seen[string(reason)]
		assert.False(t, duplicate)
		seen[string(reason)] = struct{}{}
	}
}

func testConfig(rules ...config.Rule) *config.Config {
	return &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			KillSwitch:    config.KillSwitchSelective,
			IPv6:          true,
			DNS: config.DNSSettings{
				TrackingEnabled: true,
				RespectTTL:      true,
				ConflictPolicy:  config.ConflictVPN,
			},
			Rules: rules,
		},
	}
}

func testRule(
	id string,
	priority int,
	action config.Action,
	conditions ...config.Condition,
) config.Rule {
	return config.Rule{
		ID:         config.RuleID(id),
		Name:       id,
		Enabled:    true,
		Priority:   priority,
		MatchMode:  config.MatchAll,
		Conditions: conditions,
		Action:     action,
	}
}

func domainCondition(name string) config.Condition {
	domain, err := config.NormalizeDomain(name)
	if err != nil {
		panic(err)
	}
	return config.Condition{Type: config.ConditionDomain, Domain: domain}
}

func wildcardCondition(pattern string) config.Condition {
	wildcard, err := config.NormalizeWildcardDomain(pattern)
	if err != nil {
		panic(err)
	}
	return config.Condition{Type: config.ConditionWildcardDomain, Wildcard: wildcard}
}

func cidrCondition(prefix string) config.Condition {
	return config.Condition{Type: config.ConditionCIDR, Prefix: netip.MustParsePrefix(prefix)}
}

func portCondition(protocol string, port uint16) config.Condition {
	return config.Condition{
		Type:     config.ConditionProtocolPort,
		Protocol: config.Protocol(protocol),
		Port:     port,
	}
}

func uidCondition(value uint32) config.Condition {
	uid := config.UID(value)
	return config.Condition{Type: config.ConditionUID, UID: &uid}
}

func desktopCondition(id string) config.Condition {
	return config.Condition{Type: config.ConditionDesktopID, DesktopID: config.DesktopID(id)}
}

func executableCondition(path string) config.Condition {
	return config.Condition{Type: config.ConditionExecutable, Executable: config.Executable(path)}
}

func flatpakCondition(id string) config.Condition {
	return config.Condition{Type: config.ConditionFlatpakID, FlatpakID: config.FlatpakID(id)}
}

func snapCondition(id string) config.Condition {
	return config.Condition{Type: config.ConditionSnapID, SnapID: config.SnapID(id)}
}

func allCondition(children ...config.Condition) config.Condition {
	return config.Condition{Type: config.ConditionAll, Children: children}
}

func anyCondition(children ...config.Condition) config.Condition {
	return config.Condition{Type: config.ConditionAny, Children: children}
}

func mustUID(t *testing.T, value uint32) *config.UID {
	t.Helper()
	uid := config.UID(value)
	return &uid
}

func hasConflict(conflicts []Conflict, ruleID config.RuleID, reason ConflictReason) bool {
	for _, conflict := range conflicts {
		if conflict.RuleID == ruleID && conflict.Reason == reason {
			return true
		}
	}
	return false
}

func winner(t *testing.T, decision Decision) TraceEntry {
	t.Helper()
	var winners []TraceEntry
	for _, entry := range decision.Trace {
		if entry.Won {
			winners = append(winners, entry)
		}
	}
	require.Len(t, winners, 1, "decision should have exactly one winning trace entry")
	return winners[0]
}

func repeatedRules(count int, action config.Action, conditions ...config.Condition) []config.Rule {
	rules := make([]config.Rule, 0, count)
	for i := 0; i < count; i++ {
		rule := testRule(fmt.Sprintf("rule-%02d", i), i, action, conditions...)
		rules = append(rules, rule)
	}
	return rules
}
