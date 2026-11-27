package policy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

func TestEvaluatePrecedence(t *testing.T) {
	cfg := testConfig(
		testRule("control-user", 1, config.ActionVPN, cidrCondition("192.0.2.0/24")),
		testRule("private-direct", 1, config.ActionDirect, cidrCondition("10.0.0.0/8")),
		testRule("private-vpn", 2, config.ActionVPN, cidrCondition("10.0.0.0/8")),
		testRule("block-rule", 1, config.ActionBlock, cidrCondition("203.0.113.0/24")),
		testRule("block-second", 9, config.ActionBlock, cidrCondition("203.0.113.0/24")),
		testRule("block-shadowed", 1, config.ActionVPN, cidrCondition("203.0.113.0/24")),
		testRule("high", 100, config.ActionVPN, domainCondition("app.example.com")),
		testRule("low", 200, config.ActionDirect, domainCondition("app.example.com")),
		testRule("tie-a", 50, config.ActionVPN, snapCondition("slack")),
		testRule("tie-b", 50, config.ActionDirect, snapCondition("slack")),
		exitRule("exit", 400, desktopCondition("exit.desktop"), "exit-1"),
		testRule("default-action", 500, config.ActionDefault, executableCondition("/usr/bin/curl")),
		testRule("any-rule", 600, config.ActionVPN,
			domainCondition("any.example.com"), snapCondition("anyapp")),
	)
	disabled := testRule("disabled", 1, config.ActionVPN, snapCondition("ignored"))
	disabled.Enabled = false
	cfg.SplitTunnel.Rules = append(cfg.SplitTunnel.Rules, disabled)
	cfg.SplitTunnel.Rules[len(cfg.SplitTunnel.Rules)-2].MatchMode = config.MatchAny

	compiled, err := CompileWith(cfg, Constraints{
		ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	require.NoError(t, err)

	tests := []struct {
		name         string
		flow         Flow
		wantAction   config.Action
		wantLayer    Layer
		wantRule     config.RuleID
		wantExit     config.ExitNodeID
		conflictRule config.RuleID
		conflict     ConflictReason
	}{
		{
			name:         "control traffic",
			flow:         Flow{Destination: netip.MustParseAddr("192.0.2.10")},
			wantAction:   config.ActionDirect,
			wantLayer:    LayerControl,
			conflictRule: "control-user",
			conflict:     ConflictControlOverrides,
		},
		{
			name:         "mandatory private route",
			flow:         Flow{Destination: netip.MustParseAddr("10.1.2.3")},
			wantAction:   config.ActionVPN,
			wantLayer:    LayerMandatory,
			conflictRule: "private-direct",
			conflict:     ConflictMandatoryOverrides,
		},
		{
			name:         "block rule",
			flow:         Flow{Destination: netip.MustParseAddr("203.0.113.7")},
			wantAction:   config.ActionBlock,
			wantLayer:    LayerBlock,
			wantRule:     "block-rule",
			conflictRule: "block-shadowed",
			conflict:     ConflictBlockOverrides,
		},
		{
			name:         "priority order",
			flow:         Flow{Domain: "app.example.com"},
			wantAction:   config.ActionVPN,
			wantLayer:    LayerRule,
			wantRule:     "high",
			conflictRule: "low",
			conflict:     ConflictSameMatchDifferentAction,
		},
		{
			name:         "stable ID tie-break",
			flow:         Flow{Application: Application{SnapID: "slack"}},
			wantAction:   config.ActionVPN,
			wantLayer:    LayerRule,
			wantRule:     "tie-a",
			conflictRule: "tie-b",
			conflict:     ConflictSameMatchDifferentAction,
		},
		{
			name:       "exit node",
			flow:       Flow{Application: Application{DesktopID: "exit.desktop"}},
			wantAction: config.ActionExitNode,
			wantLayer:  LayerRule,
			wantRule:   "exit",
			wantExit:   "exit-1",
		},
		{
			name:       "default action rule",
			flow:       Flow{Application: Application{Executable: "/usr/bin/curl"}},
			wantAction: config.ActionDirect,
			wantLayer:  LayerRule,
			wantRule:   "default-action",
		},
		{
			name:       "rule match any",
			flow:       Flow{Application: Application{SnapID: "anyapp"}},
			wantAction: config.ActionVPN,
			wantLayer:  LayerRule,
			wantRule:   "any-rule",
		},
		{
			name:       "disabled rule ignored",
			flow:       Flow{Application: Application{SnapID: "ignored"}},
			wantAction: config.ActionDirect,
			wantLayer:  LayerDefault,
		},
		{
			name:       "no match",
			flow:       Flow{Domain: "none.example"},
			wantAction: config.ActionDirect,
			wantLayer:  LayerDefault,
		},
		{
			name:       "empty flow",
			flow:       Flow{},
			wantAction: config.ActionDirect,
			wantLayer:  LayerDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := compiled.Evaluate(tt.flow)
			assert.Equal(t, tt.wantAction, decision.Action)
			assert.Equal(t, tt.wantLayer, decision.Layer)
			assert.Equal(t, tt.wantRule, decision.RuleID)
			assert.Equal(t, tt.wantExit, decision.ExitNodeID)

			winnerEntry := winner(t, decision)
			assert.Equal(t, tt.wantLayer, winnerEntry.Layer)
			assert.Equal(t, tt.wantRule, winnerEntry.RuleID)
			if tt.conflict != "" {
				assert.True(t, hasConflict(decision.Conflicts, tt.conflictRule, tt.conflict),
					"expected conflict %q for %q, got %+v",
					tt.conflict, tt.conflictRule, decision.Conflicts)
			}
		})
	}
}

func TestEvaluateMandatoryAgreement(t *testing.T) {
	cfg := testConfig(
		testRule("private-direct", 1, config.ActionDirect, cidrCondition("10.0.0.0/8")),
		testRule("private-vpn", 2, config.ActionVPN, cidrCondition("10.0.0.0/8")),
	)
	compiled, err := CompileWith(cfg, Constraints{
		PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	require.NoError(t, err)

	decision := compiled.Evaluate(Flow{Destination: netip.MustParseAddr("10.1.2.3")})
	assert.Equal(t, LayerMandatory, decision.Layer)
	assert.Equal(t, config.ActionVPN, decision.Action)
	assert.True(t, hasConflict(decision.Conflicts, "private-direct", ConflictMandatoryOverrides))
	assert.False(t, hasConflict(decision.Conflicts, "private-vpn", ConflictMandatoryOverrides))
}

func TestEvaluateConditions(t *testing.T) {
	cfg := testConfig(
		testRule("domain", 10, config.ActionVPN, domainCondition("example.com")),
		testRule("wildcard", 20, config.ActionVPN, wildcardCondition("*.example.com")),
		testRule("cidr4", 30, config.ActionDirect, cidrCondition("192.168.0.0/16")),
		testRule("cidr6", 40, config.ActionDirect, cidrCondition("2001:db8::/32")),
		testRule("ip", 50, config.ActionVPN, cidrCondition("8.8.8.8/32")),
		testRule("port", 60, config.ActionVPN, portCondition("tcp", 443)),
		testRule("uid", 70, config.ActionVPN, uidCondition(1000)),
		testRule("desktop", 80, config.ActionVPN, desktopCondition("firefox.desktop")),
		testRule("executable", 90, config.ActionVPN, executableCondition("/usr/bin/firefox")),
		testRule("flatpak", 100, config.ActionVPN, flatpakCondition("org.mozilla.firefox")),
		testRule("snap", 110, config.ActionVPN, snapCondition("firefox")),
		testRule("all", 120, config.ActionVPN,
			allCondition(domainCondition("example.org"), cidrCondition("203.0.113.0/24"))),
		testRule("any", 130, config.ActionVPN,
			anyCondition(domainCondition("example.net"), snapCondition("slack"))),
	)
	matchAny := testRule("match-any", 140, config.ActionVPN,
		domainCondition("a.test"), snapCondition("b"))
	matchAny.MatchMode = config.MatchAny
	cfg.SplitTunnel.Rules = append(cfg.SplitTunnel.Rules, matchAny)
	cfg.SplitTunnel.DefaultAction = config.ActionBlock

	compiled, err := Compile(cfg)
	require.NoError(t, err)

	tests := []struct {
		name     string
		flow     Flow
		wantRule config.RuleID
		want     config.Action
	}{
		{name: "exact domain normalized", flow: Flow{Domain: "Example.COM."}, wantRule: "domain", want: config.ActionVPN},
		{name: "wildcard subdomain", flow: Flow{Domain: "a.example.com"}, wantRule: "wildcard", want: config.ActionVPN},
		{name: "wildcard deep", flow: Flow{Domain: "a.b.example.com"}, wantRule: "wildcard", want: config.ActionVPN},
		{name: "wildcard does not match apex", flow: Flow{Domain: "example.com"}, wantRule: "domain", want: config.ActionVPN},
		{name: "wildcard does not match suffix trick", flow: Flow{Domain: "badexample.com"}, want: config.ActionBlock},
		{name: "ipv4 prefix", flow: Flow{Destination: netip.MustParseAddr("192.168.1.1")}, wantRule: "cidr4", want: config.ActionDirect},
		{name: "mapped ipv4", flow: Flow{Destination: netip.MustParseAddr("::ffff:192.168.1.1")}, wantRule: "cidr4", want: config.ActionDirect},
		{name: "ipv6 prefix", flow: Flow{Destination: netip.MustParseAddr("2001:db8::1")}, wantRule: "cidr6", want: config.ActionDirect},
		{name: "single ip", flow: Flow{Destination: netip.MustParseAddr("8.8.8.8")}, wantRule: "ip", want: config.ActionVPN},
		{
			name:     "protocol and port normalized",
			flow:     Flow{Protocol: "TCP", Port: 443},
			wantRule: "port",
			want:     config.ActionVPN,
		},
		{name: "wrong protocol", flow: Flow{Protocol: "udp", Port: 443}, want: config.ActionBlock},
		{name: "wrong port", flow: Flow{Protocol: "tcp", Port: 80}, want: config.ActionBlock},
		{name: "uid", flow: Flow{UID: mustUID(t, 1000)}, wantRule: "uid", want: config.ActionVPN},
		{name: "wrong uid", flow: Flow{UID: mustUID(t, 1001)}, want: config.ActionBlock},
		{name: "unknown uid", flow: Flow{}, want: config.ActionBlock},
		{
			name:     "desktop id",
			flow:     Flow{Application: Application{DesktopID: "firefox.desktop"}},
			wantRule: "desktop",
			want:     config.ActionVPN,
		},
		{
			name:     "executable",
			flow:     Flow{Application: Application{Executable: "/usr/bin/firefox"}},
			wantRule: "executable",
			want:     config.ActionVPN,
		},
		{
			name:     "flatpak",
			flow:     Flow{Application: Application{FlatpakID: "org.mozilla.firefox"}},
			wantRule: "flatpak",
			want:     config.ActionVPN,
		},
		{
			name:     "snap",
			flow:     Flow{Application: Application{SnapID: "firefox"}},
			wantRule: "snap",
			want:     config.ActionVPN,
		},
		{
			name: "all composite",
			flow: Flow{
				Domain:      "example.org",
				Destination: netip.MustParseAddr("203.0.113.5"),
			},
			wantRule: "all",
			want:     config.ActionVPN,
		},
		{
			name: "all composite partial",
			flow: Flow{Domain: "example.org"},
			want: config.ActionBlock,
		},
		{name: "any composite domain", flow: Flow{Domain: "example.net"}, wantRule: "any", want: config.ActionVPN},
		{
			name:     "any composite app",
			flow:     Flow{Application: Application{SnapID: "slack"}},
			wantRule: "any",
			want:     config.ActionVPN,
		},
		{
			name:     "rule match any",
			flow:     Flow{Application: Application{SnapID: "b"}},
			wantRule: "match-any",
			want:     config.ActionVPN,
		},
		{name: "rule match any miss", flow: Flow{Application: Application{SnapID: "c"}}, want: config.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := compiled.Evaluate(tt.flow)
			assert.Equal(t, tt.want, decision.Action)
			assert.Equal(t, tt.wantRule, decision.RuleID)
			winner(t, decision)
		})
	}
}

func TestEvaluateNilPolicy(t *testing.T) {
	var compiled *CompiledPolicy
	decision := compiled.Evaluate(Flow{})
	assert.Equal(t, config.ActionDefault, decision.Action)
	assert.Equal(t, LayerDefault, decision.Layer)
	assert.Empty(t, decision.Trace)
}

func TestEvaluateManualOverlap(t *testing.T) {
	compiled := &CompiledPolicy{
		DefaultAction: config.ActionDirect,
		Control: []PrefixRule{{
			Prefix: netip.MustParsePrefix("10.0.0.0/8"),
			Action: config.ActionDirect,
		}},
		Mandatory: []PrefixRule{{
			Prefix: netip.MustParsePrefix("10.0.0.0/8"),
			Action: config.ActionVPN,
		}},
	}
	decision := compiled.Evaluate(Flow{Destination: netip.MustParseAddr("10.1.2.3")})
	assert.Equal(t, LayerControl, decision.Layer)
	assert.Equal(t, config.ActionDirect, decision.Action)

	mandatoryEntry := findEntry(t, decision.Trace, LayerMandatory)
	assert.False(t, mandatoryEntry.Won)
	assert.Contains(t, mandatoryEntry.Detail, "overridden by control")
}

func TestEvaluateTraceTruncation(t *testing.T) {
	rules := repeatedRules(maxTraceEntries+6, config.ActionVPN, domainCondition("many.example"))
	compiled, err := Compile(testConfig(rules...))
	require.NoError(t, err)

	decision := compiled.Evaluate(Flow{Domain: "many.example"})
	assert.True(t, decision.TraceTruncated)
	assert.Len(t, decision.Trace, maxTraceEntries)
	assert.Equal(t, config.RuleID("rule-00"), decision.RuleID)
	winner(t, decision)
}

func TestEvaluateConflictTruncation(t *testing.T) {
	rules := repeatedRules(maxDecisionConflicts+6, config.ActionDirect, cidrCondition("10.0.0.0/8"))
	compiled, err := CompileWith(testConfig(rules...), Constraints{
		PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	require.NoError(t, err)

	decision := compiled.Evaluate(Flow{Destination: netip.MustParseAddr("10.1.2.3")})
	assert.Equal(t, LayerMandatory, decision.Layer)
	assert.True(t, decision.ConflictsTruncated)
	assert.Len(t, decision.Conflicts, maxDecisionConflicts)
}

func TestMatchConditionEdges(t *testing.T) {
	flow := &Flow{}
	assert.False(t, matchCondition(&config.Condition{Type: "unknown"}, flow))
	assert.False(t, matchCondition(&config.Condition{Type: config.ConditionAll}, flow))
	assert.False(t, matchCondition(&config.Condition{Type: config.ConditionAny}, flow))
	assert.False(t, matchWildcard("", "example.com"))
	assert.False(t, matchWildcard("example.com", ""))
}

func exitRule(id string, priority int, condition config.Condition, exitID config.ExitNodeID) config.Rule {
	rule := testRule(id, priority, config.ActionExitNode, condition)
	rule.ExitNodeID = exitID
	return rule
}

func findEntry(t *testing.T, trace []TraceEntry, layer Layer) TraceEntry {
	t.Helper()
	for _, entry := range trace {
		if entry.Layer == layer {
			return entry
		}
	}
	require.FailNow(t, "trace entry not found", string(layer))
	return TraceEntry{}
}
