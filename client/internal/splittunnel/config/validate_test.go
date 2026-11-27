package config

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "valid"},
		{
			name: "wrong schema version",
			mutate: func(c *Config) {
				c.SchemaVersion = 2
			},
			wantErr: "must be 1",
		},
		{
			name: "invalid mode",
			mutate: func(c *Config) {
				c.SplitTunnel.Mode = "turbo"
			},
			wantErr: "unsupported mode",
		},
		{
			name: "standard enabled",
			mutate: func(c *Config) {
				c.SplitTunnel.Mode = ModeStandard
				c.SplitTunnel.DefaultAction = ""
			},
			wantErr: "must be false in standard mode",
		},
		{
			name: "standard default action",
			mutate: func(c *Config) {
				c.SplitTunnel.Enabled = false
				c.SplitTunnel.Mode = ModeStandard
				c.SplitTunnel.DefaultAction = ActionVPN
			},
			wantErr: "standard mode",
		},
		{
			name: "include default action",
			mutate: func(c *Config) {
				c.SplitTunnel.Mode = ModeInclude
				c.SplitTunnel.DefaultAction = ActionVPN
			},
			wantErr: "include mode",
		},
		{
			name: "exclude default action",
			mutate: func(c *Config) {
				c.SplitTunnel.Mode = ModeExclude
				c.SplitTunnel.DefaultAction = ActionDirect
			},
			wantErr: "exclude mode",
		},
		{
			name: "custom default action",
			mutate: func(c *Config) {
				c.SplitTunnel.DefaultAction = ActionExitNode
			},
			wantErr: "must be vpn, direct or block",
		},
		{
			name: "custom default omitted",
			mutate: func(c *Config) {
				c.SplitTunnel.DefaultAction = ""
			},
			wantErr: "must be vpn, direct or block",
		},
		{
			name: "invalid kill switch",
			mutate: func(c *Config) {
				c.SplitTunnel.KillSwitch = "sometimes"
			},
			wantErr: "unsupported kill switch",
		},
		{
			name: "invalid conflict policy",
			mutate: func(c *Config) {
				c.SplitTunnel.DNS.ConflictPolicy = "random"
			},
			wantErr: "unsupported conflict policy",
		},
		{
			name: "duplicate rule id",
			mutate: func(c *Config) {
				addRule(c, "rule-1")
			},
			wantErr: "duplicate rule ID",
		},
		{
			name: "empty rule id",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].ID = ""
			},
			wantErr: "is required",
		},
		{
			name: "invalid rule id",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].ID = "rule/one"
			},
			wantErr: "invalid character",
		},
		{
			name: "long rule id",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].ID = RuleID(strings.Repeat("a", 129))
			},
			wantErr: "longer than 128",
		},
		{
			name: "empty name",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Name = ""
			},
			wantErr: "is required",
		},
		{
			name: "long name",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Name = strings.Repeat("a", 257)
			},
			wantErr: "longer than 256",
		},
		{
			name: "control character in name",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Name = "bad\nname"
			},
			wantErr: "control characters",
		},
		{
			name: "long description",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Description = strings.Repeat("a", 1025)
			},
			wantErr: "longer than 1024",
		},
		{
			name: "negative priority",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Priority = -1
			},
			wantErr: "between 0 and",
		},
		{
			name: "large priority",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Priority = maxPriority + 1
			},
			wantErr: "between 0 and",
		},
		{
			name: "invalid match mode",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].MatchMode = "some"
			},
			wantErr: "unsupported match mode",
		},
		{
			name: "invalid action",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Action = "proxy"
			},
			wantErr: "unsupported action",
		},
		{
			name: "enabled rule in standard mode",
			mutate: func(c *Config) {
				c.SplitTunnel.Enabled = false
				c.SplitTunnel.Mode = ModeStandard
				c.SplitTunnel.DefaultAction = ""
			},
			wantErr: "not evaluated in standard mode",
		},
		{
			name: "default action rule in include mode",
			mutate: func(c *Config) {
				c.SplitTunnel.Mode = ModeInclude
				c.SplitTunnel.DefaultAction = ActionDirect
				c.SplitTunnel.Rules[0].Action = ActionDefault
			},
			wantErr: "duplicates the global default",
		},
		{
			name: "default action rule in exclude mode",
			mutate: func(c *Config) {
				c.SplitTunnel.Mode = ModeExclude
				c.SplitTunnel.DefaultAction = ActionVPN
				c.SplitTunnel.Rules[0].Action = ActionDefault
			},
			wantErr: "duplicates the global default",
		},
		{
			name: "exit node without id",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Action = ActionExitNode
			},
			wantErr: "is required",
		},
		{
			name: "invalid exit node id",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Action = ActionExitNode
				c.SplitTunnel.Rules[0].ExitNodeID = "exit/one"
			},
			wantErr: "invalid character",
		},
		{
			name: "exit node id on other action",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].ExitNodeID = "exit-1"
			},
			wantErr: "only valid with the exit_node action",
		},
		{
			name: "no conditions",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Conditions = nil
			},
			wantErr: "at least one condition",
		},
		{
			name: "invalid condition type",
			mutate: func(c *Config) {
				condition(c).Type = "process"
			},
			wantErr: "unsupported condition type",
		},
		{
			name: "condition without value",
			mutate: func(c *Config) {
				condition(c).DesktopID = ""
			},
			wantErr: "exactly one condition value",
		},
		{
			name: "condition with two values",
			mutate: func(c *Config) {
				condition(c).Executable = "/usr/bin/firefox"
			},
			wantErr: "exactly one condition value",
		},
		{
			name: "invalid desktop id",
			mutate: func(c *Config) {
				condition(c).DesktopID = "firefox"
			},
			wantErr: "must end with .desktop",
		},
		{
			name: "desktop id path",
			mutate: func(c *Config) {
				condition(c).DesktopID = "../firefox.desktop"
			},
			wantErr: `must not contain a path separator or ".."`,
		},
		{
			name: "relative executable",
			mutate: func(c *Config) {
				condition(c).Type = ConditionExecutable
				condition(c).DesktopID = ""
				condition(c).Executable = "firefox"
			},
			wantErr: "must be absolute",
		},
		{
			name: "non canonical executable",
			mutate: func(c *Config) {
				condition(c).Type = ConditionExecutable
				condition(c).DesktopID = ""
				condition(c).Executable = "/usr//bin/firefox"
			},
			wantErr: "must be canonical",
		},
		{
			name: "invalid flatpak id",
			mutate: func(c *Config) {
				condition(c).Type = ConditionFlatpakID
				condition(c).DesktopID = ""
				condition(c).FlatpakID = "firefox"
			},
			wantErr: "at least two components",
		},
		{
			name: "invalid snap id",
			mutate: func(c *Config) {
				condition(c).Type = ConditionSnapID
				condition(c).DesktopID = ""
				condition(c).SnapID = "Firefox"
			},
			wantErr: "invalid character",
		},
		{
			name: "invalid domain",
			mutate: func(c *Config) {
				condition(c).Type = ConditionDomain
				condition(c).DesktopID = ""
				condition(c).Domain = "bad_domain"
			},
			wantErr: "invalid character",
		},
		{
			name: "non normalized domain",
			mutate: func(c *Config) {
				condition(c).Type = ConditionDomain
				condition(c).DesktopID = ""
				condition(c).Domain = "Example.COM"
			},
			wantErr: "must be normalized",
		},
		{
			name: "non normalized wildcard",
			mutate: func(c *Config) {
				condition(c).Type = ConditionWildcardDomain
				condition(c).DesktopID = ""
				condition(c).Wildcard = "Example.COM"
			},
			wantErr: "must be normalized",
		},
		{
			name: "host bits in prefix",
			mutate: func(c *Config) {
				condition(c).Type = ConditionCIDR
				condition(c).DesktopID = ""
				condition(c).Prefix = netip.MustParsePrefix("192.168.1.5/16")
			},
			wantErr: "host bits",
		},
		{
			name: "mapped ipv4 prefix",
			mutate: func(c *Config) {
				condition(c).Type = ConditionCIDR
				condition(c).DesktopID = ""
				condition(c).Prefix = netip.MustParsePrefix("::ffff:192.168.0.0/112")
			},
			wantErr: "plain IPv4",
		},
		{
			name: "invalid protocol",
			mutate: func(c *Config) {
				condition(c).Type = ConditionProtocolPort
				condition(c).DesktopID = ""
				condition(c).Protocol = "icmp"
				condition(c).Port = 1
			},
			wantErr: "unsupported protocol",
		},
		{
			name: "zero port",
			mutate: func(c *Config) {
				condition(c).Type = ConditionProtocolPort
				condition(c).DesktopID = ""
				condition(c).Protocol = ProtocolTCP
			},
			wantErr: "port must be between",
		},
		{
			name: "composite without children",
			mutate: func(c *Config) {
				condition(c).Type = ConditionAll
				condition(c).DesktopID = ""
			},
			wantErr: "exactly one condition value",
		},
		{
			name: "empty rule set allowed",
			mutate: func(c *Config) {
				c.SplitTunnel.Rules = nil
			},
		},
		{
			name: "disabled rules in standard mode",
			mutate: func(c *Config) {
				c.SplitTunnel.Enabled = false
				c.SplitTunnel.Mode = ModeStandard
				c.SplitTunnel.DefaultAction = ""
				c.SplitTunnel.Rules[0].Enabled = false
				c.SplitTunnel.Rules[0].Action = ActionDirect
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			if tt.mutate != nil {
				tt.mutate(cfg)
			}
			err := cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateLimits(t *testing.T) {
	tests := []struct {
		name    string
		limits  Limits
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:   "rule count",
			limits: Limits{MaxRules: 1},
			mutate: func(c *Config) {
				addRule(c, "rule-2")
			},
			wantErr: "limit is 1",
		},
		{
			name:   "conditions per rule",
			limits: Limits{MaxConditionsPerRule: 1},
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Conditions = append(
					c.SplitTunnel.Rules[0].Conditions,
					Condition{Type: ConditionSnapID, SnapID: "firefox"},
				)
			},
			wantErr: "conditions, limit is 1",
		},
		{
			name:   "total conditions",
			limits: Limits{MaxTotalConditions: 1},
			mutate: func(c *Config) {
				addRule(c, "rule-2")
			},
			wantErr: "limit is 1",
		},
		{
			name:   "composite depth",
			limits: Limits{MaxCompositeDepth: 1},
			mutate: func(c *Config) {
				c.SplitTunnel.Rules[0].Conditions = []Condition{{
					Type: ConditionAll,
					Children: []Condition{{
						Type: ConditionAny,
						Children: []Condition{{
							Type:   ConditionSnapID,
							SnapID: "firefox",
						}},
					}},
				}}
			},
			wantErr: "exceeds depth 1",
		},
		{
			name:   "custom value length",
			limits: Limits{MaxValueLength: 3},
			mutate: func(c *Config) {
				condition(c).DesktopID = "firefox.desktop"
			},
			wantErr: "longer than 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			if tt.mutate != nil {
				tt.mutate(cfg)
			}
			err := cfg.ValidateWithLimits(tt.limits)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestDefaultLimitsSupportSpecRuleScale(t *testing.T) {
	cfg := validConfig()
	cfg.SplitTunnel.Rules = make([]Rule, 10_000)
	for i := range cfg.SplitTunnel.Rules {
		cfg.SplitTunnel.Rules[i] = Rule{
			ID:        RuleID("rule-" + strconv.Itoa(i)),
			Name:      "rule",
			Enabled:   true,
			Priority:  i,
			MatchMode: MatchAll,
			Conditions: []Condition{{
				Type:   ConditionCIDR,
				Prefix: netip.MustParsePrefix("10.0.0.0/8"),
			}},
			Action: ActionVPN,
		}
	}

	require.NoError(t, cfg.Validate())
}

func TestValidateNilConfig(t *testing.T) {
	var cfg *Config
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is nil")
}

func TestNormalizeDomain(t *testing.T) {
	domain, err := NormalizeDomain(" Example.COM. ")
	require.Error(t, err)
	assert.Empty(t, domain)

	domain, err = NormalizeDomain("Example.COM.")
	require.NoError(t, err)
	assert.Equal(t, Domain("example.com"), domain)

	_, err = NormalizeDomain("8.8.8.8")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IP literal")

	_, err = NormalizeDomain("example..com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty label")

	_, err = NormalizeDomain(strings.Repeat("a", 64) + ".com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "longer than")
}

func TestNormalizeWildcardDomain(t *testing.T) {
	wildcard, err := NormalizeWildcardDomain("*.Example.COM.")
	require.NoError(t, err)
	assert.Equal(t, WildcardDomain("example.com"), wildcard)

	tests := []struct {
		pattern string
		wantErr string
	}{
		{pattern: "", wantErr: "empty"},
		{pattern: "example.com", wantErr: `must start with "*."`},
		{pattern: "*example.com", wantErr: `must start with "*."`},
		{pattern: "*.*.example.com", wantErr: "exactly one wildcard"},
		{pattern: "*.", wantErr: "wildcard base"},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			_, err := NormalizeWildcardDomain(tt.pattern)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func validConfig() *Config {
	return &Config{
		SchemaVersion: CurrentSchemaVersion,
		SplitTunnel: SplitTunnel{
			Enabled:       true,
			Mode:          ModeCustom,
			DefaultAction: ActionDirect,
			KillSwitch:    KillSwitchSelective,
			IPv6:          true,
			DNS: DNSSettings{
				TrackingEnabled: true,
				RespectTTL:      true,
				ConflictPolicy:  ConflictVPN,
			},
			Rules: []Rule{{
				ID:        "rule-1",
				Name:      "Firefox",
				Enabled:   true,
				Priority:  100,
				MatchMode: MatchAll,
				Conditions: []Condition{{
					Type:      ConditionDesktopID,
					DesktopID: "firefox.desktop",
				}},
				Action: ActionVPN,
			}},
		},
	}
}

func addRule(cfg *Config, id RuleID) {
	rule := cfg.SplitTunnel.Rules[0]
	rule.ID = id
	cfg.SplitTunnel.Rules = append(cfg.SplitTunnel.Rules, rule)
}

func condition(cfg *Config) *Condition {
	return &cfg.SplitTunnel.Rules[0].Conditions[0]
}
