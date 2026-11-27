//go:build linux && !android

package linux

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbnet "github.com/netbirdio/netbird/client/net"
)

func TestTableAllocatorIsDeterministicAndReleases(t *testing.T) {
	allocator := NewTableAllocator()

	vpn, err := allocator.Allocate("vpn")
	require.NoError(t, err)
	again, err := allocator.Allocate("vpn")
	require.NoError(t, err)
	assert.Equal(t, vpn, again, "repeating a key must return the same table ID")

	direct, err := allocator.Allocate("direct")
	require.NoError(t, err)
	assert.NotEqual(t, vpn, direct)

	assert.True(t, allocator.Release("vpn"))
	assert.False(t, allocator.Release("vpn"), "release must be idempotent")

	_, ok := allocator.Lookup("vpn")
	assert.False(t, ok)
	assert.True(t, allocator.Release("direct"))
}

func TestTableAllocatorRejectsEmptyKeyAndExhaustion(t *testing.T) {
	allocator := newTableAllocator(0x2000, 2)

	_, err := allocator.Allocate("")
	require.ErrorIs(t, err, ErrAllocatorKeyEmpty)

	_, err = allocator.Allocate("a")
	require.NoError(t, err)
	_, err = allocator.Allocate("b")
	require.NoError(t, err)

	_, err = allocator.Allocate("c")
	require.ErrorIs(t, err, ErrAllocatorExhausted)

	assert.True(t, allocator.Release("a"))
	_, err = allocator.Allocate("c")
	require.NoError(t, err)
}

func TestDefaultTableRangeAvoidsUpstream(t *testing.T) {
	allocator := NewTableAllocator()
	seen := make(map[TableID]struct{}, splitTableSlots)

	for i := uint64(0); i < splitTableSlots; i++ {
		id, err := allocator.Allocate(fmt.Sprintf("table-%d", i))
		require.NoError(t, err)
		assert.False(t, isUpstreamTableID(id), "table %#x must not collide with upstream", id)
		assert.GreaterOrEqual(t, id, TableID(splitTableBase))
		assert.Less(t, id, TableID(splitTableBase+splitTableSlots))
		_, duplicate := seen[id]
		assert.False(t, duplicate, "table %#x was allocated twice", id)
		seen[id] = struct{}{}
	}

	_, err := allocator.Allocate("one-too-many")
	require.ErrorIs(t, err, ErrAllocatorExhausted)
}

func TestTableAllocatorConcurrentIdempotency(t *testing.T) {
	allocator := NewTableAllocator()
	results := make(chan TableID, 64)

	var group sync.WaitGroup
	for i := 0; i < 64; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			id, err := allocator.Allocate("shared")
			if err != nil {
				results <- 0
				return
			}
			results <- id
		}()
	}
	group.Wait()
	close(results)

	var first TableID
	for id := range results {
		require.NotZero(t, id, "every concurrent allocation must succeed")
		if first == 0 {
			first = id
			continue
		}
		assert.Equal(t, first, id)
	}
}

func TestPriorityAllocatorStaysBetweenUpstreamRules(t *testing.T) {
	allocator := NewPriorityAllocator()
	seen := make(map[RulePriority]struct{}, splitPrioritySlots)

	for i := uint64(0); i < splitPrioritySlots; i++ {
		priority, err := allocator.Allocate(fmt.Sprintf("class-%d", i))
		require.NoError(t, err)
		assert.Greater(t, priority, upstreamMainPriority)
		assert.Less(t, priority, upstreamVPNPriority)
		assert.False(t, isUpstreamPriority(priority))
		_, duplicate := seen[priority]
		assert.False(t, duplicate)
		seen[priority] = struct{}{}
	}

	_, err := allocator.Allocate("one-too-many")
	require.ErrorIs(t, err, ErrAllocatorExhausted)

	first, ok := allocator.Lookup("class-0")
	require.True(t, ok)
	again, err := allocator.Allocate("class-0")
	require.NoError(t, err)
	assert.Equal(t, first, again)
	assert.True(t, allocator.Release("class-0"))
	_, ok = allocator.Lookup("class-0")
	assert.False(t, ok)
}

func TestFwmarkAllocatorReservesUpstreamMarks(t *testing.T) {
	allocator, err := NewFwmarkAllocator()
	require.NoError(t, err)

	base := allocator.baseValue()
	assert.Equal(t, nbnet.ControlPlaneMark, base, "control plane uses offset zero")
	assert.Equal(t, nbnet.DataPlaneMarkLower, base|0x10)

	seen := make(map[uint32]struct{}, splitFwmarkSlots)
	for i := uint64(0); i < splitFwmarkSlots; i++ {
		mark, err := allocator.Allocate(fmt.Sprintf("class-%d", i))
		require.NoError(t, err)
		assert.Equal(t, base|uint32(i+splitFwmarkFirstOffset), mark.Value)
		assert.Equal(t, ^uint32(0), mark.Mask, "split rules match the whole mark")
		assert.NotEqual(t, nbnet.ControlPlaneMark, mark.Value)
		assert.False(t, nbnet.IsDataPlaneMark(mark.Value))
		_, duplicate := seen[mark.Value]
		assert.False(t, duplicate, "mark %#x was allocated twice", mark.Value)
		seen[mark.Value] = struct{}{}
	}

	_, err = allocator.Allocate("one-too-many")
	require.ErrorIs(t, err, ErrAllocatorExhausted)

	first, ok := allocator.Lookup("class-0")
	require.True(t, ok)
	again, err := allocator.Allocate("class-0")
	require.NoError(t, err)
	assert.Equal(t, first, again)
	assert.True(t, allocator.Release("class-0"))
	_, ok = allocator.Lookup("class-0")
	assert.False(t, ok)
}

func TestFwmarkAllocatorRejectsInvalidBase(t *testing.T) {
	_, err := newFwmarkAllocatorAt(0)
	require.Error(t, err)

	_, err = newFwmarkAllocatorAt(nbnet.ControlPlaneMark | 0x1)
	require.Error(t, err)
}

func TestFwmarkOverlaps(t *testing.T) {
	exact := func(value uint32) Fwmark {
		return Fwmark{Value: value, Mask: ^uint32(0)}
	}

	assert.True(t, exact(0x1BD01).Overlaps(exact(0x1BD01)))
	assert.False(t, exact(0x1BD01).Overlaps(exact(0x1BD02)))

	lowByte := func(value uint32) Fwmark {
		return Fwmark{Value: value, Mask: 0xFF}
	}
	assert.True(t, lowByte(0x1BD01).Overlaps(lowByte(0x1BD101)))
	assert.False(t, lowByte(0x1BD01).Overlaps(lowByte(0x1BD02)))
	assert.False(t, Fwmark{Value: 0x1, Mask: 0}.Overlaps(exact(0x1)))
}
