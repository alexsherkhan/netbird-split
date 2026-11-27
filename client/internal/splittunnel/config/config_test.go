package config

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validDocument = `{
  "schemaVersion": 1,
  "splitTunnel": {
    "enabled": true,
    "mode": "custom",
    "defaultAction": "direct",
    "killSwitch": "selective",
    "ipv6": true,
    "dns": {
      "trackingEnabled": true,
      "respectTTL": true,
      "conflictPolicy": "vpn",
      "strictMode": false
    },
    "rules": [
      {
        "id": "rule-desktop",
        "name": "Firefox",
        "enabled": true,
        "priority": 100,
        "matchMode": "all",
        "conditions": [{"type": "desktop_id", "value": "firefox.desktop"}],
        "action": "vpn"
      },
      {
        "id": "rule-apps",
        "name": "Other applications",
        "enabled": true,
        "priority": 150,
        "matchMode": "all",
        "conditions": [
          {"type": "executable", "value": "/usr/bin/curl"},
          {"type": "flatpak_id", "value": "org.mozilla.firefox"},
          {"type": "snap_id", "value": "firefox"},
          {"type": "uid", "value": "1000"}
        ],
        "action": "vpn"
      },
      {
        "id": "rule-domains",
        "name": "Domains",
        "enabled": true,
        "priority": 200,
        "matchMode": "any",
        "conditions": [
          {"type": "domain", "value": "Example.COM."},
          {"type": "domain", "value": "*.openai.com"},
          {"type": "wildcard_domain", "value": "*.example.org"}
        ],
        "action": "vpn"
      },
      {
        "id": "rule-networks",
        "name": "Networks",
        "enabled": true,
        "priority": 10,
        "matchMode": "all",
        "conditions": [
          {"type": "cidr", "value": "192.168.0.0/16"},
          {"type": "cidr", "value": "10.0.0.1"},
          {"type": "cidr", "value": "2001:db8::/32"},
          {"type": "protocol_port", "value": "TCP/443"}
        ],
        "action": "direct"
      },
      {
        "id": "rule-composite",
        "name": "Composite",
        "enabled": true,
        "priority": 300,
        "matchMode": "all",
        "conditions": [
          {
            "type": "all",
            "conditions": [
              {"type": "domain", "value": "example.net"},
              {
                "type": "any",
                "conditions": [
                  {"type": "cidr", "value": "203.0.113.0/24"},
                  {"type": "snap_id", "value": "slack"}
                ]
              }
            ]
          }
        ],
        "action": "block"
      },
      {
        "id": "rule-exit",
        "name": "Exit node",
        "enabled": true,
        "priority": 400,
        "matchMode": "all",
        "conditions": [{"type": "snap_id", "value": "spotify"}],
        "action": "exit_node",
        "exitNodeId": "exit-1"
      },
      {
        "id": "rule-default",
        "name": "Default fallback",
        "enabled": true,
        "priority": 500,
        "matchMode": "all",
        "conditions": [{"type": "flatpak_id", "value": "com.spotify.Client"}],
        "action": "default"
      }
    ]
  }
}`

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validDocument))
	require.NoError(t, err)

	assert.Equal(t, CurrentSchemaVersion, cfg.SchemaVersion)
	assert.True(t, cfg.SplitTunnel.Enabled)
	assert.Equal(t, ModeCustom, cfg.SplitTunnel.Mode)
	assert.Equal(t, ActionDirect, cfg.SplitTunnel.DefaultAction)
	assert.Equal(t, KillSwitchSelective, cfg.SplitTunnel.KillSwitch)
	assert.True(t, cfg.SplitTunnel.IPv6)
	assert.Equal(t, ConflictVPN, cfg.SplitTunnel.DNS.ConflictPolicy)
	require.Len(t, cfg.SplitTunnel.Rules, 7)

	domains := findRule(t, cfg, "rule-domains")
	require.Len(t, domains.Conditions, 3)
	assert.Equal(t, ConditionDomain, domains.Conditions[0].Type)
	assert.Equal(t, Domain("example.com"), domains.Conditions[0].Domain)
	assert.Equal(t, ConditionWildcardDomain, domains.Conditions[1].Type)
	assert.Equal(t, WildcardDomain("openai.com"), domains.Conditions[1].Wildcard)
	assert.Equal(t, ConditionWildcardDomain, domains.Conditions[2].Type)
	assert.Equal(t, WildcardDomain("example.org"), domains.Conditions[2].Wildcard)

	networks := findRule(t, cfg, "rule-networks")
	require.Len(t, networks.Conditions, 4)
	assert.Equal(t, netip.MustParsePrefix("192.168.0.0/16"), networks.Conditions[0].Prefix)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.1/32"), networks.Conditions[1].Prefix)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::/32"), networks.Conditions[2].Prefix)
	assert.Equal(t, ProtocolTCP, networks.Conditions[3].Protocol)
	assert.Equal(t, uint16(443), networks.Conditions[3].Port)

	apps := findRule(t, cfg, "rule-apps")
	require.NotNil(t, apps.Conditions[3].UID)
	assert.Equal(t, UID(1000), *apps.Conditions[3].UID)

	composite := findRule(t, cfg, "rule-composite")
	require.Len(t, composite.Conditions, 1)
	assert.Equal(t, ConditionAll, composite.Conditions[0].Type)
	require.Len(t, composite.Conditions[0].Children, 2)
	assert.Equal(t, ConditionAny, composite.Conditions[0].Children[1].Type)
	assert.Len(t, composite.Conditions[0].Children[1].Children, 2)
}

func TestEncodeRoundTrip(t *testing.T) {
	cfg, err := Parse([]byte(validDocument))
	require.NoError(t, err)

	encoded, err := cfg.Encode()
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(string(encoded), "\n"))
	assert.Contains(t, string(encoded), `"wildcard_domain"`)

	again, err := Parse(encoded)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(cfg, again), "encoded config should round-trip")
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name     string
		document string
		wantErr  string
	}{
		{
			name: "unknown root field",
			document: strings.Replace(validDocument, `"schemaVersion": 1,`,
				`"schemaVersion": 1, "unknown": true,`, 1),
			wantErr: "unknown field",
		},
		{
			name: "unknown split tunnel field",
			document: strings.Replace(validDocument, `"enabled": true,`,
				`"enabled": true, "unknown": true,`, 1),
			wantErr: "unknown field",
		},
		{
			name: "unknown rule field",
			document: strings.Replace(validDocument, `"name": "Firefox",`,
				`"name": "Firefox", "unknown": true,`, 1),
			wantErr: "unknown field",
		},
		{
			name: "unknown dns field",
			document: strings.Replace(validDocument, `"trackingEnabled": true,`,
				`"trackingEnabled": true, "unknown": true,`, 1),
			wantErr: "unknown field",
		},
		{
			name: "unknown condition field",
			document: strings.Replace(validDocument, `{"type": "desktop_id", "value": "firefox.desktop"}`,
				`{"type": "desktop_id", "value": "firefox.desktop", "unknown": true}`, 1),
			wantErr: "unknown field",
		},
		{
			name:     "missing schema version",
			document: `{"splitTunnel":{"enabled":false,"mode":"standard","ipv6":false,"dns":{}}}`,
			wantErr:  "schemaVersion is required",
		},
		{
			name:     "zero schema version",
			document: `{"schemaVersion":0,"splitTunnel":{"enabled":false,"mode":"standard","ipv6":false,"dns":{}}}`,
			wantErr:  "must be positive",
		},
		{
			name:     "newer schema version",
			document: `{"schemaVersion":2,"splitTunnel":{"enabled":false,"mode":"standard","ipv6":false,"dns":{}}}`,
			wantErr:  "newer than supported",
		},
		{
			name:     "schema version wrong type",
			document: `{"schemaVersion":"one","splitTunnel":{}}`,
			wantErr:  "cannot unmarshal",
		},
		{
			name:     "malformed json",
			document: `{"schemaVersion":1,`,
			wantErr:  "unexpected",
		},
		{
			name:     "trailing value",
			document: validDocument + `{}`,
			wantErr:  "trailing JSON value",
		},
		{
			name:     "unknown condition type",
			document: compactDocument(`{"type":"process","value":"firefox"}`),
			wantErr:  "unknown condition type",
		},
		{
			name:     "condition without type",
			document: compactDocument(`{"value":"firefox.desktop"}`),
			wantErr:  "condition type is required",
		},
		{
			name:     "condition without value",
			document: compactDocument(`{"type":"desktop_id"}`),
			wantErr:  "requires a value",
		},
		{
			name:     "condition with value and children",
			document: compactDocument(`{"type":"desktop_id","value":"a.desktop","conditions":[{"type":"snap_id","value":"a"}]}`),
			wantErr:  "must not have children",
		},
		{
			name:     "composite with value",
			document: compactDocument(`{"type":"all","value":"x","conditions":[{"type":"snap_id","value":"a"}]}`),
			wantErr:  "must not have a value",
		},
		{
			name:     "composite without children",
			document: compactDocument(`{"type":"any"}`),
			wantErr:  "requires conditions",
		},
		{
			name:     "composite with empty children",
			document: compactDocument(`{"type":"any","conditions":[]}`),
			wantErr:  "at least one child",
		},
		{
			name:     "null condition value",
			document: compactDocument(`{"type":"snap_id","value":null}`),
			wantErr:  "requires a value",
		},
		{
			name:     "null composite children",
			document: compactDocument(`{"type":"all","conditions":null}`),
			wantErr:  "requires conditions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.document))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseWithLimits(t *testing.T) {
	cfg, err := ParseWithLimits([]byte(validDocument), Limits{})
	require.NoError(t, err)
	require.NotNil(t, cfg)

	_, err = ParseWithLimits([]byte(validDocument), Limits{MaxConfigBytes: 16})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit is 16")
}

func TestParseStandardDisabled(t *testing.T) {
	document := `{"schemaVersion":1,"splitTunnel":{"enabled":false,"mode":"standard","ipv6":false,"dns":{}}}`
	cfg, err := Parse([]byte(document))
	require.NoError(t, err)
	assert.False(t, cfg.SplitTunnel.Enabled)
	assert.Equal(t, ModeStandard, cfg.SplitTunnel.Mode)
	assert.Empty(t, cfg.SplitTunnel.Rules)
}

func TestFieldError(t *testing.T) {
	err := fail("splitTunnel.mode", "bad %s", "mode")
	var fieldErr *FieldError
	require.ErrorAs(t, err, &fieldErr)
	assert.Equal(t, "splitTunnel.mode", fieldErr.Path)
	assert.Contains(t, err.Error(), "bad mode")
	assert.Equal(t, fieldErr.Err, fieldErr.Unwrap())
}

func findRule(t *testing.T, cfg *Config, id RuleID) *Rule {
	t.Helper()
	for i := range cfg.SplitTunnel.Rules {
		if cfg.SplitTunnel.Rules[i].ID == id {
			return &cfg.SplitTunnel.Rules[i]
		}
	}
	require.FailNow(t, "rule not found", string(id))
	return nil
}

func compactDocument(condition string) string {
	return `{"schemaVersion":1,"splitTunnel":{"enabled":true,"mode":"custom",` +
		`"defaultAction":"direct","killSwitch":"disabled","ipv6":true,"dns":{},` +
		`"rules":[{"id":"rule-1","name":"Rule","enabled":true,"priority":1,` +
		`"matchMode":"all","conditions":[` + condition + `],"action":"vpn"}]}}`
}
