//go:build linux && !android

package linux

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithClassificationCounterInsertsBeforeVerdict(t *testing.T) {
	rule := nftRule{
		family:  family4,
		matches: []nftMatch{{prefix: netip.MustParsePrefix("10.0.0.0/8")}},
		mark:    0x1BD01,
	}
	exprs, err := nftRuleExprs(rule, nil)
	require.NoError(t, err)

	counted := withClassificationCounter(rule, exprs)
	require.Len(t, counted, len(exprs)+1)

	counterIndex, verdictIndex := -1, -1
	for i, expression := range counted {
		switch expression.(type) {
		case *expr.Counter:
			require.Equal(t, -1, counterIndex, "exactly one counter must be inserted")
			counterIndex = i
		case *expr.Verdict:
			verdictIndex = i
		}
	}
	require.NotEqual(t, -1, counterIndex, "a classification rule must carry a counter")
	require.NotEqual(t, -1, verdictIndex)
	assert.Less(t, counterIndex, verdictIndex, "the counter must run before the verdict")
}

func TestWithClassificationCounterSkipsBypassAndUnmarkedRules(t *testing.T) {
	bypass, err := nftRuleExprs(nftRule{
		family:  family4,
		matches: []nftMatch{{prefix: netip.MustParsePrefix("127.0.0.0/8")}},
		bypass:  true,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, bypass, withClassificationCounter(nftRule{bypass: true}, bypass))

	unmarked, err := nftRuleExprs(nftRule{family: family4}, nil)
	require.NoError(t, err)
	assert.Equal(t, unmarked, withClassificationCounter(nftRule{}, unmarked))
}

func TestRuleMarkAndCounterParsing(t *testing.T) {
	const mark = uint32(0x1BD02)
	rule := &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		&expr.Counter{Bytes: 512, Packets: 4},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}}

	got, ok := ruleMark(rule)
	require.True(t, ok)
	assert.Equal(t, mark, got)

	counter := ruleCounter(rule)
	require.NotNil(t, counter)
	assert.Equal(t, uint64(4), counter.Packets)
	assert.Equal(t, uint64(512), counter.Bytes)

	_, ok = ruleMark(&nftables.Rule{Exprs: []expr.Any{
		&expr.Verdict{Kind: expr.VerdictReturn},
	}})
	assert.False(t, ok, "a rule without a mark must not be attributed to a class")
}
