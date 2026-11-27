//go:build linux && !android

package linux

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

func TestIPv4PrefixExprs(t *testing.T) {
	t.Run("host prefix", func(t *testing.T) {
		exprs := ipv4PrefixExprs(netip.MustParsePrefix("10.0.0.1/32"))
		require.Len(t, exprs, 2)

		payload, ok := exprs[0].(*expr.Payload)
		require.True(t, ok)
		assert.Equal(t, uint32(ipv4DestinationOffset), payload.Offset)
		assert.Equal(t, uint32(ipv4AddressLength), payload.Len)

		cmp, ok := exprs[1].(*expr.Cmp)
		require.True(t, ok)
		assert.Equal(t, []byte{10, 0, 0, 1}, cmp.Data)
	})

	t.Run("network prefix", func(t *testing.T) {
		exprs := ipv4PrefixExprs(netip.MustParsePrefix("10.0.0.0/24"))
		require.Len(t, exprs, 3)

		bitwise, ok := exprs[1].(*expr.Bitwise)
		require.True(t, ok)
		assert.Equal(t, []byte(net.CIDRMask(24, 32)), bitwise.Mask)
		assert.Equal(t, make([]byte, 4), bitwise.Xor)

		cmp, ok := exprs[2].(*expr.Cmp)
		require.True(t, ok)
		assert.Equal(t, []byte{10, 0, 0, 0}, cmp.Data)
	})
}

func TestProtocolPortExprs(t *testing.T) {
	exprs, err := protocolPortExprs(config.ProtocolTCP, 443)
	require.NoError(t, err)
	require.Len(t, exprs, 4)

	meta, ok := exprs[0].(*expr.Meta)
	require.True(t, ok)
	assert.Equal(t, expr.MetaKeyL4PROTO, meta.Key)

	cmp, ok := exprs[1].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, []byte{6}, cmp.Data, "tcp protocol number")

	payload, ok := exprs[2].(*expr.Payload)
	require.True(t, ok)
	assert.Equal(t, uint32(ipv4TransportPortOffset), payload.Offset)

	cmp, ok = exprs[3].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, binaryutil.BigEndian.PutUint16(443), cmp.Data)

	_, err = protocolPortExprs(config.Protocol("icmp"), 1)
	require.Error(t, err)

	_, err = protocolPortExprs(config.ProtocolUDP, 0)
	require.Error(t, err)
}

func TestPrefixSetElements(t *testing.T) {
	elements := prefixSetElements([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	require.Len(t, elements, 2)
	assert.Equal(t, []byte{10, 0, 0, 0}, elements[0].Key)
	assert.False(t, elements[0].IntervalEnd)
	assert.Equal(t, []byte{10, 0, 1, 0}, elements[1].Key)
	assert.True(t, elements[1].IntervalEnd)

	elements = prefixSetElements([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")})
	require.Len(t, elements, 2)
	assert.Equal(t, []byte{10, 0, 0, 1}, elements[0].Key)
	assert.Equal(t, []byte{10, 0, 0, 2}, elements[1].Key)

	elements = prefixSetElements([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	require.Len(t, elements, 2)
	assert.Equal(t, []byte{0, 0, 0, 0}, elements[0].Key)
	assert.Equal(t, []byte{0, 0, 0, 0}, elements[1].Key)
	assert.True(t, elements[1].IntervalEnd)
}

func TestPrefixLastKeyWrapsMaximumAddress(t *testing.T) {
	assert.Equal(t, make([]byte, 4),
		prefixLastKey(netip.MustParsePrefix("255.255.255.255/32")))
}

func TestNftRuleExprsMarksAndReturns(t *testing.T) {
	sets := map[setName]*nftables.Set{
		setVPN4: {ID: 7, Name: string(setVPN4)},
	}
	rule := nftRule{matches: []nftMatch{{set: setVPN4}}, mark: 0x1BD01}

	exprs, err := nftRuleExprs(rule, sets)
	require.NoError(t, err)
	require.Len(t, exprs, 9)

	meta, ok := exprs[0].(*expr.Meta)
	require.True(t, ok)
	assert.Equal(t, expr.MetaKeyNFPROTO, meta.Key)

	cmp, ok := exprs[1].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, binaryutil.NativeEndian.PutUint32(unix.NFPROTO_IPV4), cmp.Data,
		"classification must stay IPv4-only")

	meta, ok = exprs[2].(*expr.Meta)
	require.True(t, ok)
	assert.Equal(t, expr.MetaKeyMARK, meta.Key)

	cmp, ok = exprs[3].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, binaryutil.NativeEndian.PutUint32(0), cmp.Data,
		"classification must not overwrite a pre-existing mark")

	payload, ok := exprs[4].(*expr.Payload)
	require.True(t, ok)
	assert.Equal(t, uint32(ipv4DestinationOffset), payload.Offset)

	lookup, ok := exprs[5].(*expr.Lookup)
	require.True(t, ok)
	assert.Equal(t, uint32(7), lookup.SetID)
	assert.Equal(t, string(setVPN4), lookup.SetName)

	immediate, ok := exprs[6].(*expr.Immediate)
	require.True(t, ok)
	assert.Equal(t, binaryutil.NativeEndian.PutUint32(0x1BD01), immediate.Data)

	verdict, ok := exprs[8].(*expr.Verdict)
	require.True(t, ok)
	assert.Equal(t, expr.VerdictReturn, verdict.Kind)
}

func TestNftRuleExprsBypassReturnsWithoutMark(t *testing.T) {
	rule := nftRule{
		matches: []nftMatch{{prefix: netip.MustParsePrefix("127.0.0.0/8")}},
		bypass:  true,
	}
	exprs, err := nftRuleExprs(rule, nil)
	require.NoError(t, err)
	require.NotEmpty(t, exprs)

	verdict, ok := exprs[len(exprs)-1].(*expr.Verdict)
	require.True(t, ok)
	assert.Equal(t, expr.VerdictReturn, verdict.Kind)
	for _, item := range exprs {
		_, isImmediate := item.(*expr.Immediate)
		assert.False(t, isImmediate, "bypass rules must not set a mark")
	}
}

func TestNftRuleExprsCombinesPrefixAndProtocol(t *testing.T) {
	rule := nftRule{
		matches: []nftMatch{
			{prefix: netip.MustParsePrefix("10.0.0.1/32")},
			{protocol: config.ProtocolTCP, port: 443},
		},
		mark: 0x1BD01,
	}
	exprs, err := nftRuleExprs(rule, nil)
	require.NoError(t, err)
	require.Len(t, exprs, 4+2+4+3,
		"IPv4 and mark guard, literal prefix, protocol port, then mark and return")

	verdict, ok := exprs[len(exprs)-1].(*expr.Verdict)
	require.True(t, ok)
	assert.Equal(t, expr.VerdictReturn, verdict.Kind)
}

func TestNftRuleExprsRejectsMissingSet(t *testing.T) {
	_, err := nftRuleExprs(nftRule{matches: []nftMatch{{set: setVPN4}}}, nil)
	require.Error(t, err)
}

func TestPolicySetNamesOwnsExitSet(t *testing.T) {
	assert.Contains(t, policySetNames(), setExit4)
	assert.Contains(t, policySetNames(), setVPN4)
	assert.Contains(t, policySetNames(), setDirect4)
	assert.Contains(t, policySetNames(), setBlocked4)
}
