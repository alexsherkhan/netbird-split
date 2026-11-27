package dns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
)

func TestResolverPrefixes(t *testing.T) {
	groups := []*nbdns.NameServerGroup{
		{
			Enabled: true,
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("10.0.0.53")},
				{IP: netip.MustParseAddr("10.0.0.53")},
			},
		},
		{
			Enabled: true,
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("fd00::53")},
			},
		},
		{
			Enabled: false,
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("10.0.0.99")},
			},
		},
	}

	prefixes := resolverPrefixes(groups)
	require.Len(t, prefixes, 2)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.53/32"), prefixes[0])
	assert.Equal(t, netip.MustParsePrefix("fd00::53/128"), prefixes[1])
}

func TestDefaultServerResolverPrefixesReturnsCopy(t *testing.T) {
	server := &DefaultServer{resolvers: []netip.Prefix{netip.MustParsePrefix("10.0.0.53/32")}}
	prefixes := server.ResolverPrefixes()
	require.Len(t, prefixes, 1)
	prefixes[0] = netip.Prefix{}

	assert.Equal(t, netip.MustParsePrefix("10.0.0.53/32"), server.ResolverPrefixes()[0])
}
