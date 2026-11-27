//go:build linux && !android

package linux

import (
	"errors"
	"fmt"
	"sync"

	nbnet "github.com/netbirdio/netbird/client/net"
)

var (
	// ErrAllocatorExhausted reports that every slot in a range is allocated.
	ErrAllocatorExhausted = errors.New("allocator exhausted")
	// ErrAllocatorKeyEmpty reports an allocation without a caller key.
	ErrAllocatorKeyEmpty = errors.New("allocator key is empty")
)

const (
	splitTableBase  uint64 = 0x1BE0
	splitTableSlots uint64 = 32

	splitPriorityBase  uint64 = 106
	splitPrioritySlots uint64 = 4

	splitFwmarkFirstOffset uint64 = 0x01
	splitFwmarkSlots       uint64 = 0x0F
	fwmarkBaseMask         uint32 = 0xFF

	upstreamVPNTableID     TableID      = 0x1BD0
	upstreamMainTableID    TableID      = 254
	upstreamDefaultTableID TableID      = 253
	upstreamMainPriority   RulePriority = 105
	upstreamVPNPriority    RulePriority = 110
)

// TableID is a Linux policy routing table ID.
type TableID uint32

// RulePriority is a Linux policy rule priority. Lower values run first.
type RulePriority int

// Fwmark is a packet mark and the bit mask a policy rule matches.
type Fwmark struct {
	Value uint32
	Mask  uint32
}

// Overlaps reports whether two mark/mask pairs can match the same mark.
func (m Fwmark) Overlaps(other Fwmark) bool {
	mask := m.Mask & other.Mask
	if mask == 0 {
		return false
	}
	return m.Value&mask == other.Value&mask
}

type rangeAllocator struct {
	mu      sync.Mutex
	base    uint64
	count   uint64
	byKey   map[string]uint64
	bySlot  map[uint64]string
	nextNew uint64
}

func newRangeAllocator(base, count uint64) *rangeAllocator {
	return &rangeAllocator{
		base:   base,
		count:  count,
		byKey:  make(map[string]uint64),
		bySlot: make(map[uint64]string),
	}
}

func (a *rangeAllocator) allocate(key string) (uint64, bool, error) {
	if key == "" {
		return 0, false, ErrAllocatorKeyEmpty
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if slot, ok := a.byKey[key]; ok {
		return slot, false, nil
	}

	for offset := uint64(0); offset < a.count; offset++ {
		slot := (a.nextNew + offset) % a.count
		if _, used := a.bySlot[slot]; used {
			continue
		}
		a.byKey[key] = slot
		a.bySlot[slot] = key
		a.nextNew = (slot + 1) % a.count
		return slot, true, nil
	}
	return 0, false, fmt.Errorf("%w: %d slots", ErrAllocatorExhausted, a.count)
}

func (a *rangeAllocator) release(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	slot, ok := a.byKey[key]
	if !ok {
		return false
	}
	delete(a.byKey, key)
	delete(a.bySlot, slot)
	return true
}

func (a *rangeAllocator) lookup(key string) (uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	slot, ok := a.byKey[key]
	return slot, ok
}

// TableAllocator allocates split policy routing table IDs from a range that
// does not include upstream NetBird, main or default tables.
type TableAllocator struct {
	inner *rangeAllocator
}

// NewTableAllocator returns the default split table ID allocator.
func NewTableAllocator() *TableAllocator {
	return &TableAllocator{inner: newRangeAllocator(splitTableBase, splitTableSlots)}
}

func newTableAllocator(base TableID, slots uint64) *TableAllocator {
	return &TableAllocator{inner: newRangeAllocator(uint64(base), slots)}
}

// Allocate returns the table ID for a key. Repeating a key returns the same ID.
func (a *TableAllocator) Allocate(key string) (TableID, error) {
	slot, _, err := a.inner.allocate(key)
	if err != nil {
		return 0, err
	}
	return TableID(a.inner.base + slot), nil
}

// Lookup returns the table ID already allocated to a key.
func (a *TableAllocator) Lookup(key string) (TableID, bool) {
	slot, ok := a.inner.lookup(key)
	if !ok {
		return 0, false
	}
	return TableID(a.inner.base + slot), true
}

// Release frees a key and its table ID.
func (a *TableAllocator) Release(key string) bool {
	return a.inner.release(key)
}

// PriorityAllocator allocates policy rule priorities strictly between the
// upstream main rule at 105 and the upstream VPN rule at 110.
type PriorityAllocator struct {
	inner *rangeAllocator
}

// NewPriorityAllocator returns the default split rule priority allocator.
func NewPriorityAllocator() *PriorityAllocator {
	return &PriorityAllocator{inner: newRangeAllocator(splitPriorityBase, splitPrioritySlots)}
}

// Allocate returns the rule priority for a key. Repeating a key returns the
// same priority.
func (a *PriorityAllocator) Allocate(key string) (RulePriority, error) {
	slot, _, err := a.inner.allocate(key)
	if err != nil {
		return 0, err
	}
	return RulePriority(a.inner.base + slot), nil
}

// Lookup returns the rule priority already allocated to a key.
func (a *PriorityAllocator) Lookup(key string) (RulePriority, bool) {
	slot, ok := a.inner.lookup(key)
	if !ok {
		return 0, false
	}
	return RulePriority(a.inner.base + slot), true
}

// Release frees a key and its rule priority.
func (a *PriorityAllocator) Release(key string) bool {
	return a.inner.release(key)
}

// FwmarkAllocator allocates split marks from the low offsets of the upstream
// fwmark base. Control plane (0x00) and data plane (0x10 and above) marks are
// reserved.
type FwmarkAllocator struct {
	inner *rangeAllocator
	base  uint32
}

// NewFwmarkAllocator returns a split mark allocator derived from the active
// upstream NB_FWMARK_BASE range.
func NewFwmarkAllocator() (*FwmarkAllocator, error) {
	return newFwmarkAllocatorAt(nbnet.ControlPlaneMark &^ fwmarkBaseMask)
}

func newFwmarkAllocatorAt(base uint32) (*FwmarkAllocator, error) {
	if base == 0 {
		return nil, errors.New("fwmark base is zero")
	}
	if base&fwmarkBaseMask != 0 {
		return nil, fmt.Errorf("fwmark base %#x must leave the low byte free", base)
	}
	if base|0x10 != nbnet.DataPlaneMarkLower {
		return nil, fmt.Errorf(
			"fwmark base %#x is inconsistent with the upstream data plane range %#x",
			base, nbnet.DataPlaneMarkLower)
	}
	return &FwmarkAllocator{
		inner: newRangeAllocator(splitFwmarkFirstOffset, splitFwmarkSlots),
		base:  base,
	}, nil
}

// Allocate returns the split mark for a key. Repeating a key returns the same
// mark. The mask matches the whole mark so a foreign base with the same low
// byte cannot be captured by a split rule.
func (a *FwmarkAllocator) Allocate(key string) (Fwmark, error) {
	slot, _, err := a.inner.allocate(key)
	if err != nil {
		return Fwmark{}, err
	}
	return Fwmark{
		Value: a.base | uint32(slot+splitFwmarkFirstOffset),
		Mask:  ^uint32(0),
	}, nil
}

// Lookup returns the split mark already allocated to a key.
func (a *FwmarkAllocator) Lookup(key string) (Fwmark, bool) {
	slot, ok := a.inner.lookup(key)
	if !ok {
		return Fwmark{}, false
	}
	return Fwmark{
		Value: a.base | uint32(slot+splitFwmarkFirstOffset),
		Mask:  ^uint32(0),
	}, true
}

// Release frees a key and its split mark.
func (a *FwmarkAllocator) Release(key string) bool {
	return a.inner.release(key)
}

func (a *FwmarkAllocator) baseValue() uint32 {
	return a.base
}

func isUpstreamTableID(id TableID) bool {
	return id == upstreamVPNTableID || id == upstreamMainTableID || id == upstreamDefaultTableID
}

func isUpstreamPriority(priority RulePriority) bool {
	return priority == upstreamMainPriority || priority == upstreamVPNPriority
}
