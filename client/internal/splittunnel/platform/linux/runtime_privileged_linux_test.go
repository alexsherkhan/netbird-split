//go:build linux && !android && privileged

package linux

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func TestIPv4RuntimeConstraintsKeepControlDirectAndPrivateVPN(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeExclude,
			DefaultAction: config.ActionVPN,
			Rules: []config.Rule{
				{
					ID:        "excluded",
					Name:      "excluded",
					Enabled:   true,
					Priority:  10,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.9.4.0/24"),
					}},
				},
				{
					ID:        "private-direct",
					Name:      "private-direct",
					Enabled:   true,
					Priority:  20,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:   config.ConditionCIDR,
						Prefix: netip.MustParsePrefix("10.9.9.0/24"),
					}},
				},
			},
		},
	}
	compiled, err := policy.CompileWith(cfg, policy.Constraints{
		ControlPrefixes: []netip.Prefix{netip.MustParsePrefix("10.9.8.0/24")},
		PrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")},
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
	}
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	assertEgress := func(t *testing.T, destination string, wantDirect, wantVPN bool) {
		t.Helper()
		before := counters(t, names)
		require.NoError(t, sendUDP(destination, 9999))
		after := counters(t, names)
		if wantDirect {
			assert.Equal(t, before.direct+1, after.direct, "destination %s", destination)
		} else {
			assert.Equal(t, before.direct, after.direct, "destination %s", destination)
		}
		if wantVPN {
			assert.Equal(t, before.vpn+1, after.vpn, "destination %s", destination)
		} else {
			assert.Equal(t, before.vpn, after.vpn, "destination %s", destination)
		}
	}

	t.Run("control prefix stays direct", func(t *testing.T) {
		assertEgress(t, "10.9.8.1", true, false)
	})
	t.Run("private prefix overrides a direct rule", func(t *testing.T) {
		assertEgress(t, "10.9.9.1", false, true)
	})
	t.Run("excluded rule uses the physical path", func(t *testing.T) {
		assertEgress(t, "10.9.4.1", true, false)
	})
	t.Run("default vpn uses the overlay", func(t *testing.T) {
		assertEgress(t, "10.9.5.1", false, true)
	})
}
