//go:build linux && !android && privileged

package linux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/internal/splittunnel/diagnostics"
)

func TestTrafficCountersReadsKernelCounter(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}

	tableName := fmt.Sprintf("netbird_split_m16_%d", os.Getpid())
	removeTable(t, tableName)
	t.Cleanup(func() { removeTable(t, tableName) })

	manager, err := newNFTablesManager(tableName)
	require.NoError(t, err)
	if err := manager.Ensure(context.Background()); err != nil {
		t.Skipf("nftables counters are unavailable in this environment: %v", err)
	}

	chains, err := manager.chainsInTable()
	require.NoError(t, err)
	var classify *nftables.Chain
	for _, chain := range chains {
		if chain.Name == string(chainClassifyOutput) {
			classify = chain
			break
		}
	}
	require.NotNil(t, classify, "the owned classification chain must exist")

	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(lo))

	const mark = uint32(0x1BD0F)
	rule := nftRule{
		family:  family4,
		matches: []nftMatch{{prefix: netip.MustParsePrefix("127.0.0.1/32")}},
		mark:    mark,
	}
	exprs, err := nftRuleExprs(rule, nil)
	require.NoError(t, err)
	exprs = withClassificationCounter(rule, exprs)
	manager.conn.AddRule(&nftables.Rule{
		Table:    manager.table,
		Chain:    classify,
		Exprs:    exprs,
		UserData: ownedRuleUserData,
	})
	require.NoError(t, manager.conn.Flush())

	conn, err := net.Dial("udp", "127.0.0.1:9")
	require.NoError(t, err)
	_, err = conn.Write([]byte("netbird diagnostics counter"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	time.Sleep(50 * time.Millisecond)

	sample, err := manager.TrafficCounters(context.Background(),
		map[uint32]diagnostics.TrafficClass{mark: diagnostics.ClassVPN})
	require.NoError(t, err)
	require.Contains(t, sample.Classes, diagnostics.ClassVPN)
	assert.GreaterOrEqual(t, sample.Classes[diagnostics.ClassVPN].Packets, uint64(1),
		"the owned counter must observe the egress packet")
	assert.GreaterOrEqual(t, sample.RuleHits, uint64(1))
}
