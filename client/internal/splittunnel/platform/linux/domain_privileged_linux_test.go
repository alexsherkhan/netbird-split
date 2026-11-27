//go:build linux && !android && privileged

package linux

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/domain"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

type backendDomainUpdater struct {
	backend *Backend
}

func (u backendDomainUpdater) UpdateDomainSets(ctx context.Context, updates []backend.DomainSetUpdate) error {
	return u.backend.UpdateDomainSets(ctx, updates)
}

func TestDomainRoutingEgressInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	b := startM04Backend(t)

	compiled, options := m08DomainPolicy(t, names)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))

	tracker, err := domain.NewTrackerForPolicy(backendDomainUpdater{backend: b}, compiled, domain.Options{
		ConflictPolicy: config.ConflictVPN,
	})
	require.NoError(t, err)

	observe(t, tracker, "exact.example.test", "10.9.7.1")
	observe(t, tracker, "sub.wild.example.test", "10.9.7.2")
	observe(t, tracker, "direct.example.test", "10.9.7.3")
	observe(t, tracker, "wild.example.test", "10.9.7.4") // wildcard apex is not covered
	observe(t, tracker, "blocked.example.test", "10.9.7.5")

	t.Run("exact domain uses the overlay path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.7.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.vpn+1, after.vpn)
		assert.Equal(t, before.direct, after.direct)
	})

	t.Run("wildcard subdomain uses the overlay path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.7.2", 9999))
		after := counters(t, names)

		assert.Equal(t, before.vpn+1, after.vpn)
		assert.Equal(t, before.direct, after.direct)
	})

	t.Run("direct domain uses the physical path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.7.3", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct+1, after.direct)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("wildcard apex falls back to the default path", func(t *testing.T) {
		before := counters(t, names)
		require.NoError(t, sendUDP("10.9.7.4", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct+1, after.direct,
			"a wildcard must not cover the apex name")
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("blocked domain does not leave the host", func(t *testing.T) {
		before := counters(t, names)
		requireUnreachable(t, sendUDP("10.9.7.5", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.vpn, after.vpn)
	})
}

func m08DomainPolicy(t *testing.T, names testInterfaces) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			DNS: config.DNSSettings{
				TrackingEnabled: true,
				ConflictPolicy:  config.ConflictVPN,
			},
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
						Domain: "exact.example.test",
					}},
				},
				{
					ID:        "wildcard",
					Name:      "wildcard",
					Enabled:   true,
					Priority:  20,
					MatchMode: config.MatchAll,
					Action:    config.ActionVPN,
					Conditions: []config.Condition{{
						Type:     config.ConditionWildcardDomain,
						Wildcard: "wild.example.test",
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
						Type:   config.ConditionDomain,
						Domain: "direct.example.test",
					}},
				},
				{
					ID:        "blocked",
					Name:      "blocked",
					Enabled:   true,
					Priority:  40,
					MatchMode: config.MatchAll,
					Action:    config.ActionBlock,
					Conditions: []config.Condition{{
						Type:   config.ConditionDomain,
						Domain: "blocked.example.test",
					}},
				},
			},
		},
	}

	compiled, err := policy.Compile(cfg)
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
	return compiled, options
}

func observe(t *testing.T, tracker *domain.Tracker, name, address string) {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	qtype := uint16(dns.TypeA)
	if netip.MustParseAddr(address).Is6() {
		qtype = dns.TypeAAAA
		req.SetQuestion(dns.Fqdn(name), qtype)
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN %s %s",
		dns.Fqdn(name), dns.TypeToString[qtype], address))
	require.NoError(t, err)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{rr}
	require.NoError(t, tracker.ObserveResponse(req, resp))
}
