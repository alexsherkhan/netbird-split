//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/hashicorp/go-multierror"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

// routeClass is one split traffic class. Every class has a fixed mark, table
// and policy-rule priority allocated from the M03 ranges.
type routeClass string

const (
	classVPN    routeClass = "vpn"
	classDirect routeClass = "direct"
	classBlock  routeClass = "block"
	classExit   routeClass = "exit"
)

var splitClasses = []routeClass{classVPN, classDirect, classBlock, classExit}

// routeFamily is the address family of a policy route and rule. IPv4 and IPv6
// policy rules are independent, so the same table ID and mark can be reused for
// both families without one family's rule selecting the other's traffic.
type routeFamily uint8

const (
	routeFamily4 routeFamily = iota
	routeFamily6
)

func routeFamilyOf(family nftFamily) routeFamily {
	if family == family6 {
		return routeFamily6
	}
	return routeFamily4
}

func (f routeFamily) netlinkFamily() int {
	if f == routeFamily6 {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

func (f routeFamily) isIPv6() bool {
	return f == routeFamily6
}

func (f routeFamily) String() string {
	if f == routeFamily6 {
		return "IPv6"
	}
	return "IPv4"
}

func classForAction(action config.Action) (routeClass, bool) {
	switch action {
	case config.ActionVPN:
		return classVPN, true
	case config.ActionDirect:
		return classDirect, true
	case config.ActionBlock:
		return classBlock, true
	case config.ActionExitNode:
		return classExit, true
	default:
		return "", false
	}
}

func setForClassFamily(class routeClass, family nftFamily) setName {
	switch class {
	case classVPN:
		if family == family6 {
			return setVPN6
		}
		return setVPN4
	case classDirect:
		if family == family6 {
			return setDirect6
		}
		return setDirect4
	case classBlock:
		if family == family6 {
			return setBlocked6
		}
		return setBlocked4
	case classExit:
		if family == family6 {
			return setExit6
		}
		return setExit4
	default:
		return ""
	}
}

func classKey(class routeClass) string {
	return "split-" + string(class)
}

type classAllocation struct {
	class    routeClass
	mark     Fwmark
	table    TableID
	priority RulePriority
}

type allocations struct {
	byClass map[routeClass]classAllocation
}

func newAllocations() (allocations, error) {
	marks, err := NewFwmarkAllocator()
	if err != nil {
		return allocations{}, fmt.Errorf("create split mark allocator: %w", err)
	}
	tables := NewTableAllocator()
	priorities := NewPriorityAllocator()

	byClass := make(map[routeClass]classAllocation, len(splitClasses))
	for _, class := range splitClasses {
		key := classKey(class)

		mark, err := marks.Allocate(key)
		if err != nil {
			return allocations{}, fmt.Errorf("allocate %s mark: %w", class, err)
		}
		table, err := tables.Allocate(key)
		if err != nil {
			return allocations{}, fmt.Errorf("allocate %s table: %w", class, err)
		}
		priority, err := priorities.Allocate(key)
		if err != nil {
			return allocations{}, fmt.Errorf("allocate %s priority: %w", class, err)
		}

		byClass[class] = classAllocation{
			class:    class,
			mark:     mark,
			table:    table,
			priority: priority,
		}
	}
	return allocations{byClass: byClass}, nil
}

func (a allocations) get(class routeClass) (classAllocation, bool) {
	alloc, ok := a.byClass[class]
	return alloc, ok
}

type routePlan struct {
	classes  []classRoute
	classes6 []classRoute
}

type classRoute struct {
	class      routeClass
	allocation classAllocation
	family     routeFamily
	target     backend.RouteTarget
	protected  bool
	blackhole  bool
}

type routeManager interface {
	Apply(ctx context.Context, plan routePlan) error
	Remove(ctx context.Context, allocations allocations) error
}

type netlinkRouter struct {
	linkByName        func(string) (netlink.Link, error)
	routeReplace      func(*netlink.Route) error
	ruleAdd           func(*netlink.Rule) error
	ruleList          func(int) ([]netlink.Rule, error)
	ruleDel           func(*netlink.Rule) error
	routeListFiltered func(int, *netlink.Route, uint64) ([]netlink.Route, error)
	routeDel          func(*netlink.Route) error
}

func newNetlinkRouter() *netlinkRouter {
	return &netlinkRouter{
		linkByName:        netlink.LinkByName,
		routeReplace:      netlink.RouteReplace,
		ruleAdd:           netlink.RuleAdd,
		ruleList:          netlink.RuleList,
		ruleDel:           netlink.RuleDel,
		routeListFiltered: netlink.RouteListFiltered,
		routeDel:          netlink.RouteDel,
	}
}

func (r *netlinkRouter) Apply(ctx context.Context, plan routePlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	for _, class := range plan.classes {
		if err := r.applyRoute(class); err != nil {
			return fmt.Errorf("apply %s route: %w", class.class, err)
		}
	}
	for _, class := range plan.classes6 {
		if err := r.applyRoute(class); err != nil {
			return fmt.Errorf("apply %s IPv6 route: %w", class.class, err)
		}
	}
	for _, class := range plan.classes {
		if err := r.ensureRuleFor(class.allocation, class.family); err != nil {
			return fmt.Errorf("apply %s policy rule: %w", class.class, err)
		}
	}
	for _, class := range plan.classes6 {
		if err := r.ensureRuleFor(class.allocation, class.family); err != nil {
			return fmt.Errorf("apply %s IPv6 policy rule: %w", class.class, err)
		}
	}
	return nil
}

// The kernel assigns a default metric (1024) to an IPv6 default route when the
// request carries none, so every installed default states its metric
// explicitly. The fallback metric keeps an unreachable default behind the real
// route: if the target link disappears, the kernel removes the real route and
// marked traffic hits the unreachable route instead of a physical table.
const (
	protectedPrimaryMetric  = 1
	protectedFallbackMetric = 1000
)

func (r *netlinkRouter) applyRoute(class classRoute) error {
	table := class.allocation.table
	family := class.family
	if class.blackhole {
		return r.reconcileRoutes(table, family, []*netlink.Route{
			unreachableDefaultRoute(table, family, protectedFallbackMetric),
		})
	}

	target := class.target
	if target.Interface == "" {
		if class.protected {
			return r.reconcileRoutes(table, family, []*netlink.Route{
				unreachableDefaultRoute(table, family, protectedFallbackMetric),
			})
		}
		return fmt.Errorf("%w: %s interface is empty", backend.ErrInvalidPolicyOption, class.class)
	}

	link, err := r.linkByName(target.Interface)
	if err != nil {
		if class.protected {
			return r.reconcileRoutes(table, family, []*netlink.Route{
				unreachableDefaultRoute(table, family, protectedFallbackMetric),
			})
		}
		return fmt.Errorf("resolve interface %q: %w", target.Interface, err)
	}

	desired := []*netlink.Route{unicastDefaultRoute(table, family, link, target)}
	if class.protected {
		desired = append(desired, unreachableDefaultRoute(table, family, protectedFallbackMetric))
	}
	return r.reconcileRoutes(table, family, desired)
}

func unicastDefaultRoute(
	table TableID,
	family routeFamily,
	link netlink.Link,
	target backend.RouteTarget,
) *netlink.Route {
	route := &netlink.Route{
		Type:      unix.RTN_UNICAST,
		Family:    family.netlinkFamily(),
		Table:     int(table),
		Dst:       defaultRouteDestinationFor(family),
		LinkIndex: link.Attrs().Index,
		Priority:  protectedPrimaryMetric,
		Scope:     netlink.SCOPE_LINK,
	}
	if target.Gateway.IsValid() {
		route.Gw = target.Gateway.AsSlice()
		route.Scope = netlink.SCOPE_UNIVERSE
	}
	if target.Source.IsValid() {
		route.Src = net.IP(target.Source.AsSlice())
	}
	return route
}

func unreachableDefaultRoute(table TableID, family routeFamily, metric int) *netlink.Route {
	return &netlink.Route{
		Type:     unix.RTN_UNREACHABLE,
		Family:   family.netlinkFamily(),
		Table:    int(table),
		Dst:      defaultRouteDestinationFor(family),
		Priority: metric,
	}
}

func (r *netlinkRouter) reconcileRoutes(
	table TableID,
	family routeFamily,
	desired []*netlink.Route,
) error {
	for _, route := range desired {
		if err := r.routeReplace(route); err != nil {
			return fmt.Errorf("replace default route: %w", err)
		}
	}

	current, err := r.routeListFiltered(family.netlinkFamily(),
		&netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes in table %d: %w", table, err)
	}
	for i := range current {
		if !isDefaultRoute(&current[i]) || routeInDesired(&current[i], desired) {
			continue
		}
		if err := r.routeDel(&current[i]); err != nil &&
			!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("delete stale default route: %w", err)
		}
	}
	return nil
}

func routeInDesired(route *netlink.Route, desired []*netlink.Route) bool {
	for _, want := range desired {
		if normalizeRouteType(route.Type) != normalizeRouteType(want.Type) ||
			route.Priority != want.Priority {
			continue
		}
		// An unreachable route is not bound to a link; the kernel reports it
		// with lo even though it was installed without one.
		if normalizeRouteType(route.Type) == unix.RTN_UNREACHABLE {
			return true
		}
		if route.LinkIndex == want.LinkIndex && gatewayEqual(route.Gw, want.Gw) {
			return true
		}
	}
	return false
}

func gatewayEqual(left, right net.IP) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == len(right)
	}
	return left.Equal(right)
}

func defaultRouteDestinationFor(family routeFamily) *net.IPNet {
	if family.isIPv6() {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
}

func (r *netlinkRouter) ensureRuleFor(allocation classAllocation, family routeFamily) error {
	rule := netlink.NewRule()
	rule.Family = family.netlinkFamily()
	rule.Table = int(allocation.table)
	rule.Priority = int(allocation.priority)
	rule.Mark = allocation.mark.Value
	mask := allocation.mark.Mask
	rule.Mask = &mask

	if err := r.ruleAdd(rule); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add fwmark %#x rule: %w", allocation.mark.Value, err)
	}

	// A repeated apply hits EEXIST. Confirm the priority is occupied by this
	// exact split rule and not by an upstream or third-party rule.
	existing, err := r.ruleList(rule.Family)
	if err != nil {
		return fmt.Errorf("list rules after collision at priority %d: %w", rule.Priority, err)
	}
	for i := range existing {
		if existing[i].Priority != rule.Priority {
			continue
		}
		if existing[i].Family == rule.Family &&
			existing[i].Table == rule.Table &&
			existing[i].Mark == rule.Mark &&
			existing[i].Mask != nil && *existing[i].Mask == mask {
			return nil
		}
		return fmt.Errorf("priority %d is used by a foreign policy rule: %w",
			rule.Priority, backend.ErrForeignObject)
	}
	return fmt.Errorf("priority %d could not be added and no rule was found: %w",
		rule.Priority, backend.ErrForeignObject)
}

func (r *netlinkRouter) Remove(ctx context.Context, allocations allocations) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var merr *multierror.Error

	for _, family := range []routeFamily{routeFamily4, routeFamily6} {
		rules, err := r.ruleList(family.netlinkFamily())
		if err != nil {
			merr = multierror.Append(merr,
				fmt.Errorf("list %v policy rules: %w", family, err))
			continue
		}
		for i := range rules {
			if !allocations.matchesRule(&rules[i]) {
				continue
			}
			if err := r.ruleDel(&rules[i]); err != nil &&
				!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
				merr = multierror.Append(merr,
					fmt.Errorf("delete policy rule %d: %w", rules[i].Priority, err))
			}
		}
	}

	for _, class := range splitClasses {
		allocation, ok := allocations.get(class)
		if !ok {
			continue
		}
		for _, family := range []routeFamily{routeFamily4, routeFamily6} {
			routes, err := r.routeListFiltered(family.netlinkFamily(),
				&netlink.Route{Table: int(allocation.table)}, netlink.RT_FILTER_TABLE)
			if err != nil {
				merr = multierror.Append(merr,
					fmt.Errorf("list routes in table %d: %w", allocation.table, err))
				continue
			}
			for i := range routes {
				if !isDefaultRoute(&routes[i]) {
					continue
				}
				if err := r.routeDel(&routes[i]); err != nil &&
					!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
					merr = multierror.Append(merr,
						fmt.Errorf("delete route in table %d: %w", allocation.table, err))
				}
			}
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (a allocations) matchesRule(rule *netlink.Rule) bool {
	if rule.Family != netlink.FAMILY_V4 && rule.Family != netlink.FAMILY_V6 {
		return false
	}
	for _, allocation := range a.byClass {
		if rule.Priority != int(allocation.priority) ||
			rule.Table != int(allocation.table) ||
			rule.Mark != allocation.mark.Value {
			continue
		}
		if rule.Mask == nil || *rule.Mask != allocation.mark.Mask {
			continue
		}
		return true
	}
	return false
}

func normalizeRouteType(routeType int) int {
	if routeType == 0 {
		return unix.RTN_UNICAST
	}
	return routeType
}

func isDefaultRoute(route *netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	ones, _ := route.Dst.Mask.Size()
	return ones == 0
}
