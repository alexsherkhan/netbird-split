//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
)

type recordedRouter struct {
	linkByName func(string) (netlink.Link, error)
	links      []string
	routes     []*netlink.Route
	rules      []*netlink.Rule
}

func newRecordedRouter() *recordedRouter {
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 7, Flags: net.FlagUp},
	}
	router := &recordedRouter{}
	router.linkByName = func(name string) (netlink.Link, error) {
		router.links = append(router.links, name)
		if name != "eth0" {
			return nil, errors.New("link not found")
		}
		return link, nil
	}
	return router
}

func (r *recordedRouter) router() *netlinkRouter {
	return &netlinkRouter{
		linkByName: r.linkByName,
		routeReplace: func(route *netlink.Route) error {
			copied := *route
			r.routes = append(r.routes, &copied)
			return nil
		},
		ruleAdd: func(rule *netlink.Rule) error {
			copied := *rule
			r.rules = append(r.rules, &copied)
			return nil
		},
		ruleList: func(int) ([]netlink.Rule, error) { return nil, nil },
		ruleDel:  func(*netlink.Rule) error { return nil },
		routeListFiltered: func(int, *netlink.Route, uint64) ([]netlink.Route, error) {
			return nil, nil
		},
		routeDel: func(*netlink.Route) error { return nil },
	}
}

func TestNetlinkRouterApplyInstallsFailClosedRoutesAndRules(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()

	plan := routePlan{classes: []classRoute{
		{
			class:      classDirect,
			allocation: allocations.byClass[classDirect],
			target: backend.RouteTarget{
				Interface: "eth0",
				Source:    netip.MustParseAddr("10.0.0.2"),
			},
		},
		{
			class:      classExit,
			allocation: allocations.byClass[classExit],
			target:     backend.RouteTarget{Interface: "missing"},
			protected:  true,
		},
		{
			class:      classBlock,
			allocation: allocations.byClass[classBlock],
			protected:  true,
			blackhole:  true,
		},
	}}

	require.NoError(t, recorded.router().Apply(context.Background(), plan))
	require.Len(t, recorded.routes, 3)

	direct := recorded.routes[0]
	assert.Equal(t, int(allocations.byClass[classDirect].table), direct.Table)
	assert.Equal(t, 7, direct.LinkIndex)
	assert.Equal(t, netlink.SCOPE_LINK, direct.Scope)
	assert.Equal(t, []byte{10, 0, 0, 2}, []byte(direct.Src.To4()))
	assert.Equal(t, unix.RTN_UNICAST, direct.Type)

	exit := recorded.routes[1]
	assert.Equal(t, int(allocations.byClass[classExit].table), exit.Table)
	assert.Equal(t, unix.RTN_UNREACHABLE, exit.Type)

	block := recorded.routes[2]
	assert.Equal(t, int(allocations.byClass[classBlock].table), block.Table)
	assert.Equal(t, unix.RTN_UNREACHABLE, block.Type)
	assert.Equal(t, protectedFallbackMetric, block.Priority)

	require.Len(t, recorded.rules, 3)
	for i, class := range plan.classes {
		rule := recorded.rules[i]
		assert.Equal(t, netlink.FAMILY_V4, rule.Family)
		assert.Equal(t, int(class.allocation.table), rule.Table)
		assert.Equal(t, int(class.allocation.priority), rule.Priority)
		assert.Equal(t, class.allocation.mark.Value, rule.Mark)
		require.NotNil(t, rule.Mask)
		assert.Equal(t, class.allocation.mark.Mask, *rule.Mask)
	}
}

func TestNetlinkRouterProtectedClassKeepsUnreachableFallback(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()

	plan := routePlan{classes: []classRoute{{
		class:      classExit,
		allocation: allocations.byClass[classExit],
		target:     backend.RouteTarget{Interface: "eth0"},
		protected:  true,
	}}}

	require.NoError(t, recorded.router().Apply(context.Background(), plan))
	require.Len(t, recorded.routes, 2)

	unicast := recorded.routes[0]
	assert.Equal(t, unix.RTN_UNICAST, unicast.Type)
	assert.Equal(t, int(allocations.byClass[classExit].table), unicast.Table)
	assert.Equal(t, 7, unicast.LinkIndex)
	assert.Equal(t, protectedPrimaryMetric, unicast.Priority,
		"the primary default states its metric so the kernel cannot reassign one")

	fallback := recorded.routes[1]
	assert.Equal(t, unix.RTN_UNREACHABLE, fallback.Type)
	assert.Equal(t, int(allocations.byClass[classExit].table), fallback.Table)
	assert.Equal(t, protectedFallbackMetric, fallback.Priority,
		"the fallback stays behind the real default while the target exists")
}

func TestNetlinkRouterDirectMissingTargetReturnsError(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()

	plan := routePlan{classes: []classRoute{{
		class:      classDirect,
		allocation: allocations.byClass[classDirect],
		target:     backend.RouteTarget{Interface: "missing"},
	}}}

	err := recorded.router().Apply(context.Background(), plan)
	require.Error(t, err)
	assert.Empty(t, recorded.routes)
	assert.Empty(t, recorded.rules)
}

func TestNetlinkRouterDirectEmptyTargetReturnsError(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()

	plan := routePlan{classes: []classRoute{{
		class:      classDirect,
		allocation: allocations.byClass[classDirect],
	}}}

	err := recorded.router().Apply(context.Background(), plan)
	require.ErrorIs(t, err, backend.ErrInvalidPolicyOption)
	assert.Empty(t, recorded.routes)
}

func TestNetlinkRouterApplyIsIdempotent(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()
	plan := routePlan{classes: []classRoute{{
		class:      classVPN,
		allocation: allocations.byClass[classVPN],
		target:     backend.RouteTarget{Interface: "eth0"},
		protected:  true,
	}}}
	router := recorded.router()

	require.NoError(t, router.Apply(context.Background(), plan))
	require.NoError(t, router.Apply(context.Background(), plan))

	assert.Len(t, recorded.routes, 4,
		"each apply reconciles the real default and its unreachable fallback")
	assert.Len(t, recorded.rules, 2, "reconciliation uses idempotent rule adds")
}

func TestNetlinkRouterRemoveOnlyOwnedState(t *testing.T) {
	allocations := testAllocations(t)

	ours := netlink.NewRule()
	ours.Family = netlink.FAMILY_V4
	ours.Table = int(allocations.byClass[classDirect].table)
	ours.Priority = int(allocations.byClass[classDirect].priority)
	ours.Mark = allocations.byClass[classDirect].mark.Value
	mask := allocations.byClass[classDirect].mark.Mask
	ours.Mask = &mask

	foreign := netlink.NewRule()
	foreign.Family = netlink.FAMILY_V4
	foreign.Table = 254
	foreign.Priority = 100
	foreign.Mark = 0x1234

	var deletedRules []netlink.Rule
	var deletedRoutes []netlink.Route
	defaultRoute := netlink.Route{
		Table: int(allocations.byClass[classDirect].table),
		Type:  unix.RTN_UNREACHABLE,
	}
	specificRoute := netlink.Route{
		Table: int(allocations.byClass[classDirect].table),
		Dst:   &net.IPNet{IP: net.IPv4(10, 1, 0, 0).To4(), Mask: net.CIDRMask(16, 32)},
	}

	router := &netlinkRouter{
		linkByName:   func(string) (netlink.Link, error) { return nil, errors.New("unused") },
		routeReplace: func(*netlink.Route) error { return nil },
		ruleAdd:      func(*netlink.Rule) error { return nil },
		ruleList: func(family int) ([]netlink.Rule, error) {
			if family == netlink.FAMILY_V4 {
				return []netlink.Rule{*ours, *foreign}, nil
			}
			return nil, nil
		},
		ruleDel: func(rule *netlink.Rule) error {
			deletedRules = append(deletedRules, *rule)
			return nil
		},
		routeListFiltered: func(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
			if family == netlink.FAMILY_V4 &&
				filter.Table == int(allocations.byClass[classDirect].table) {
				return []netlink.Route{defaultRoute, specificRoute}, nil
			}
			return nil, nil
		},
		routeDel: func(route *netlink.Route) error {
			deletedRoutes = append(deletedRoutes, *route)
			return nil
		},
	}

	require.NoError(t, router.Remove(context.Background(), allocations))

	require.Len(t, deletedRules, 1)
	assert.Equal(t, int(allocations.byClass[classDirect].priority), deletedRules[0].Priority)
	require.Len(t, deletedRoutes, 1, "a foreign specific route must be left alone")
	assert.Equal(t, unix.RTN_UNREACHABLE, deletedRoutes[0].Type)
}

func TestNetlinkRouterRemoveIsIdempotent(t *testing.T) {
	allocations := testAllocations(t)
	router := &netlinkRouter{
		linkByName:   func(string) (netlink.Link, error) { return nil, errors.New("unused") },
		routeReplace: func(*netlink.Route) error { return nil },
		ruleAdd:      func(*netlink.Rule) error { return nil },
		ruleList:     func(int) ([]netlink.Rule, error) { return nil, nil },
		ruleDel:      func(*netlink.Rule) error { return nil },
		routeListFiltered: func(int, *netlink.Route, uint64) ([]netlink.Route, error) {
			return nil, nil
		},
		routeDel: func(*netlink.Route) error { return nil },
	}

	require.NoError(t, router.Remove(context.Background(), allocations))
	require.NoError(t, router.Remove(context.Background(), allocations))
}

func TestNetlinkRouterAcceptsIdempotentRuleCollision(t *testing.T) {
	allocations := testAllocations(t)
	allocation := allocations.byClass[classVPN]

	existing := netlink.NewRule()
	existing.Family = netlink.FAMILY_V4
	existing.Table = int(allocation.table)
	existing.Priority = int(allocation.priority)
	existing.Mark = allocation.mark.Value
	mask := allocation.mark.Mask
	existing.Mask = &mask

	router := &netlinkRouter{
		linkByName:   func(string) (netlink.Link, error) { return nil, errors.New("unused") },
		routeReplace: func(*netlink.Route) error { return nil },
		ruleAdd:      func(*netlink.Rule) error { return syscall.EEXIST },
		ruleList:     func(int) ([]netlink.Rule, error) { return []netlink.Rule{*existing}, nil },
		ruleDel:      func(*netlink.Rule) error { return nil },
		routeListFiltered: func(int, *netlink.Route, uint64) ([]netlink.Route, error) {
			return nil, nil
		},
		routeDel: func(*netlink.Route) error { return nil },
	}

	require.NoError(t, router.ensureRuleFor(allocation, routeFamily4))
}

func TestNetlinkRouterRejectsForeignRuleCollision(t *testing.T) {
	allocations := testAllocations(t)
	allocation := allocations.byClass[classVPN]

	foreign := netlink.NewRule()
	foreign.Family = netlink.FAMILY_V4
	foreign.Table = 254
	foreign.Priority = int(allocation.priority)
	foreign.Mark = 0x1234

	router := &netlinkRouter{
		linkByName:   func(string) (netlink.Link, error) { return nil, errors.New("unused") },
		routeReplace: func(*netlink.Route) error { return nil },
		ruleAdd:      func(*netlink.Rule) error { return syscall.EEXIST },
		ruleList:     func(int) ([]netlink.Rule, error) { return []netlink.Rule{*foreign}, nil },
		ruleDel:      func(*netlink.Rule) error { return nil },
		routeListFiltered: func(int, *netlink.Route, uint64) ([]netlink.Route, error) {
			return nil, nil
		},
		routeDel: func(*netlink.Route) error { return nil },
	}

	err := router.ensureRuleFor(allocation, routeFamily4)
	require.ErrorIs(t, err, backend.ErrForeignObject)
}

func TestNetlinkRouterSourceSelectionDropsStaleSource(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()
	router := recorded.router()
	router.addrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.9")}}}, nil
	}

	plan := routePlan{classes: []classRoute{{
		class:      classDirect,
		allocation: allocations.byClass[classDirect],
		target: backend.RouteTarget{
			Interface: "eth0",
			Source:    netip.MustParseAddr("10.0.0.2"),
		},
	}}}

	require.NoError(t, router.Apply(context.Background(), plan))
	require.Len(t, recorded.routes, 1)
	assert.Nil(t, recorded.routes[0].Src,
		"a source address that is no longer assigned must not be installed")
}

func TestNetlinkRouterProtectedClassWithoutAddressFailsClosed(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()
	router := recorded.router()
	router.addrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return nil, nil
	}

	plan := routePlan{classes: []classRoute{{
		class:      classExit,
		allocation: allocations.byClass[classExit],
		target: backend.RouteTarget{
			Interface: "eth0",
			Source:    netip.MustParseAddr("10.0.0.2"),
		},
		protected: true,
	}}}

	require.NoError(t, router.Apply(context.Background(), plan))
	require.Len(t, recorded.routes, 1)
	assert.Equal(t, unix.RTN_UNREACHABLE, recorded.routes[0].Type)
}

func TestNetlinkRouterProtectedClassWithDownLinkFailsClosed(t *testing.T) {
	allocations := testAllocations(t)
	recorded := newRecordedRouter()
	down := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 7},
	}
	recorded.linkByName = func(string) (netlink.Link, error) { return down, nil }
	router := recorded.router()

	plan := routePlan{classes: []classRoute{{
		class:      classExit,
		allocation: allocations.byClass[classExit],
		target:     backend.RouteTarget{Interface: "eth0"},
		protected:  true,
	}}}

	require.NoError(t, router.Apply(context.Background(), plan))
	require.Len(t, recorded.routes, 1)
	assert.Equal(t, unix.RTN_UNREACHABLE, recorded.routes[0].Type,
		"a down exit interface must leave only the fail-closed default")
}
