package backend

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

func TestRouteTarget6Validate(t *testing.T) {
	valid := RouteTarget6{
		Interface: "eth0",
		Gateway:   netip.MustParseAddr("fe80::1"),
		Source:    netip.MustParseAddr("2001:db8::2"),
	}
	assert.NoError(t, valid.Validate())
	assert.False(t, valid.IsZero())

	assert.NoError(t, RouteTarget6{Interface: "eth0"}.Validate(),
		"a link-scope overlay interface needs no gateway or source")

	tests := []struct {
		name   string
		target RouteTarget6
	}{
		{name: "empty interface", target: RouteTarget6{Source: netip.MustParseAddr("2001:db8::2")}},
		{name: "IPv4 gateway", target: RouteTarget6{Interface: "eth0", Gateway: netip.MustParseAddr("10.0.0.1")}},
		{name: "IPv4 source", target: RouteTarget6{Interface: "eth0", Source: netip.MustParseAddr("10.0.0.2")}},
		{name: "v4-mapped address", target: RouteTarget6{Interface: "eth0", Gateway: netip.MustParseAddr("::ffff:10.0.0.1")}},
		{name: "zone", target: RouteTarget6{Interface: "eth0", Gateway: netip.MustParseAddr("fe80::1%eth0")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, tt.target.Validate())
		})
	}

	assert.True(t, RouteTarget6{}.IsZero())
	assert.False(t, RouteTarget6{Interface: "eth0"}.IsZero())
}

func TestRouteTargetRejectsIPv6Address(t *testing.T) {
	target := RouteTarget{
		Interface: "eth0",
		Gateway:   netip.MustParseAddr("2001:db8::1"),
	}
	require.ErrorIs(t, target.Validate(), ErrIPv6Unsupported)
}

func TestCapabilitiesLookup(t *testing.T) {
	capabilities := Capabilities{Items: []Capability{
		{ID: CapabilityNFTables, State: CapabilityAvailable},
		{ID: CapabilityCgroupV2, State: CapabilityUnavailable, Detail: "not mounted"},
	}}

	item, ok := capabilities.Get(CapabilityNFTables)
	require.True(t, ok)
	assert.Equal(t, CapabilityAvailable, item.State)

	_, ok = capabilities.Get(CapabilityIPv6)
	assert.False(t, ok, "an unprobed capability must not be reported as present")
	assert.Equal(t, CapabilityUnknown, capabilities.StateOf(CapabilityIPv6))
	assert.Equal(t, CapabilityUnavailable, capabilities.StateOf(CapabilityCgroupV2))
	assert.True(t, capabilities.Degraded())
}

func TestCapabilitiesMissing(t *testing.T) {
	capabilities := Capabilities{Items: []Capability{
		{ID: CapabilityNFTables, State: CapabilityAvailable},
		{ID: CapabilityNetlink, State: CapabilityUnavailable, Detail: "denied"},
	}}

	missing := capabilities.Missing(CapabilityNFTables, CapabilityNetlink, CapabilityIPv6)
	require.Len(t, missing, 2)
	assert.Equal(t, CapabilityNetlink, missing[0].ID)
	assert.Equal(t, CapabilityIPv6, missing[1].ID)
	assert.Equal(t, CapabilityUnknown, missing[1].State)
	assert.Empty(t, capabilities.Missing(CapabilityNFTables), "available capability must not be missing")
}

func TestCapabilitiesCloneIsIndependent(t *testing.T) {
	original := Capabilities{Items: []Capability{
		{ID: CapabilityNFTables, State: CapabilityAvailable},
	}}

	copied := original.Clone()
	copied.Items[0].State = CapabilityUnavailable

	assert.Equal(t, CapabilityAvailable, original.Items[0].State)
	assert.Equal(t, CapabilityUnavailable, copied.Items[0].State)
}

func TestCapabilityErrorUnwraps(t *testing.T) {
	err := &CapabilityError{
		Capability: CapabilityNFTables,
		State:      CapabilityUnavailable,
		Detail:     "requires CAP_NET_ADMIN",
	}

	assert.ErrorIs(t, err, ErrCapabilityUnavailable)
	assert.Contains(t, err.Error(), "nftables")
	assert.Contains(t, err.Error(), "requires CAP_NET_ADMIN")
}

func TestNotImplementedErrorUnwraps(t *testing.T) {
	err := &NotImplementedError{Operation: "apply policy"}

	assert.ErrorIs(t, err, ErrNotImplemented)
	assert.Contains(t, err.Error(), "apply policy")
}

func TestOwnedObjectsCloneIsIndependent(t *testing.T) {
	original := OwnedObjects{
		Table:  "netbird_split",
		Chains: []string{"classify_output"},
		Sets:   []string{"vpn4"},
	}

	copied := original.Clone()
	copied.Chains[0] = "changed"
	copied.Sets[0] = "changed"

	assert.Equal(t, "classify_output", original.Chains[0])
	assert.Equal(t, "vpn4", original.Sets[0])
}

func TestDomainSetUpdateValidate(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	valid := DomainSetUpdate{
		Action: config.ActionVPN,
		Entries: []DomainEntry{
			{Prefix: netip.MustParsePrefix("10.0.0.0/8"), ExpiresAt: expires},
			{Prefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	assert.NoError(t, valid.Validate())

	tests := []struct {
		name   string
		update DomainSetUpdate
	}{
		{
			name:   "unsupported action",
			update: DomainSetUpdate{Action: config.ActionDefault},
		},
		{
			name:   "exit node domains are not supported",
			update: DomainSetUpdate{Action: config.ActionExitNode},
		},
		{
			name: "duplicate prefix",
			update: DomainSetUpdate{
				Action: config.ActionDirect,
				Entries: []DomainEntry{
					{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
					{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
				},
			},
		},
		{
			name: "host bits set",
			update: DomainSetUpdate{
				Action:  config.ActionBlock,
				Entries: []DomainEntry{{Prefix: netip.MustParsePrefix("10.1.2.3/8")}},
			},
		},
		{
			name: "v4 mapped address",
			update: DomainSetUpdate{
				Action:  config.ActionVPN,
				Entries: []DomainEntry{{Prefix: netip.MustParsePrefix("::ffff:10.0.0.0/104")}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, tt.update.Validate())
		})
	}
}

func TestStateValid(t *testing.T) {
	for _, state := range []State{
		StateUninitialized,
		StateInitializing,
		StateReady,
		StateDegraded,
		StateCleaning,
		StateFailed,
		StateClosed,
	} {
		assert.True(t, state.Valid(), "state %q should be valid", state)
		assert.Equal(t, string(state), state.String())
	}
	assert.False(t, State("unknown").Valid())
}
