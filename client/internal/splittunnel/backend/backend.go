// Package backend defines the contract between the split tunnel engine and a
// platform network backend.
//
// It also holds the typed status, capability and error values shared by every
// implementation. Configuration and compiled policy come from the config and
// policy packages so a backend never restates the policy model.
package backend

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

var (
	// ErrNotImplemented reports an operation a backend accepts but has not
	// implemented yet. Callers must treat it as a failure, never as success.
	ErrNotImplemented = errors.New("not implemented")
	// ErrNotInitialized reports an operation that requires Initialize first.
	ErrNotInitialized = errors.New("backend is not initialized")
	// ErrClosed reports an operation on a backend that has been closed.
	ErrClosed = errors.New("backend is closed")
	// ErrCapabilityUnavailable reports a required kernel capability that the
	// backend cannot use.
	ErrCapabilityUnavailable = errors.New("capability unavailable")
	// ErrForeignObject reports an object inside a backend-owned container that
	// the backend did not create. The backend leaves it untouched.
	ErrForeignObject = errors.New("foreign object in a backend-owned object set")
	// ErrObjectMismatch reports an owned object whose definition differs from
	// the current backend version. The backend refuses to mutate it.
	ErrObjectMismatch = errors.New("owned object does not match its expected definition")
	// ErrUnsupportedCondition reports a policy condition the backend cannot
	// enforce yet. The backend rejects the whole policy instead of silently
	// ignoring the condition.
	ErrUnsupportedCondition = errors.New("unsupported split tunnel condition")
	// ErrIPv6Unsupported reports an IPv6 address supplied to an IPv4 target.
	// IPv6 egress paths use RouteTarget6 so the mismatch is caught at the API
	// boundary instead of producing a route the kernel cannot install.
	ErrIPv6Unsupported = errors.New("IPv6 address is not valid for an IPv4 target")
	// ErrExitNodeUnavailable reports an exit node that is not the single
	// authorized active exit node. Protected traffic must not fall back to
	// another path.
	ErrExitNodeUnavailable = errors.New("exit node is unavailable")
	// ErrInvalidPolicyOption reports a missing or malformed runtime route
	// target needed to enforce a compiled policy.
	ErrInvalidPolicyOption = errors.New("invalid split tunnel policy option")
)

// UnsupportedConditionError names the condition that a backend cannot enforce.
type UnsupportedConditionError struct {
	Condition config.ConditionType
	Reason    string
	IPv6      bool
}

// Error implements error.
func (e *UnsupportedConditionError) Error() string {
	reason := e.Reason
	if reason == "" {
		reason = "not implemented"
	}
	return fmt.Sprintf("condition %q: %s: %v", e.Condition, reason, ErrUnsupportedCondition)
}

// Unwrap reports the sentinel errors this condition matches.
func (e *UnsupportedConditionError) Unwrap() []error {
	if e.IPv6 {
		return []error{ErrUnsupportedCondition, ErrIPv6Unsupported}
	}
	return []error{ErrUnsupportedCondition}
}

// ExitNodeUnavailableError names the requested and active exit node IDs.
type ExitNodeUnavailableError struct {
	Requested config.ExitNodeID
	Active    config.ExitNodeID
}

// Error implements error.
func (e *ExitNodeUnavailableError) Error() string {
	return fmt.Sprintf("exit node %q is not the active exit node %q: %v",
		e.Requested, e.Active, ErrExitNodeUnavailable)
}

// Unwrap reports the sentinel exit-node-unavailable error.
func (e *ExitNodeUnavailableError) Unwrap() error {
	return ErrExitNodeUnavailable
}

// RouteTarget is a typed IPv4 egress path a backend uses for one traffic
// class. Interface is required. Gateway is empty for a link-scope route such as
// a point-to-point overlay interface. Source selects the preferred source
// address for the installed default route.
type RouteTarget struct {
	Interface string
	Gateway   netip.Addr
	Source    netip.Addr
}

// RouteTarget6 is the IPv6 counterpart of RouteTarget. It is a separate type so
// an IPv4 target can never be passed where an IPv6 egress path is required.
type RouteTarget6 struct {
	Interface string
	Gateway   netip.Addr
	Source    netip.Addr
}

// Validate checks that the target can be installed as an IPv6 route.
func (t RouteTarget6) Validate() error {
	if t.Interface == "" {
		return errors.New("interface is empty")
	}
	if err := validateTarget6Addr(t.Gateway, "gateway"); err != nil {
		return err
	}
	if err := validateTarget6Addr(t.Source, "source"); err != nil {
		return err
	}
	return nil
}

// IsZero reports whether the target carries no egress information at all. A
// zero target means the caller has no IPv6 path for the class.
func (t RouteTarget6) IsZero() bool {
	return t.Interface == "" && !t.Gateway.IsValid() && !t.Source.IsValid()
}

func validateTarget6Addr(addr netip.Addr, field string) error {
	if !addr.IsValid() {
		return nil
	}
	if addr.Is4In6() {
		return fmt.Errorf("%s must use a plain IPv6 address", field)
	}
	if !addr.Is6() {
		return fmt.Errorf("%s must be an IPv6 address", field)
	}
	if addr.Zone() != "" {
		return fmt.Errorf("%s must not contain a zone", field)
	}
	return nil
}

// Validate checks that the target can be installed as an IPv4 route.
func (t RouteTarget) Validate() error {
	if t.Interface == "" {
		return errors.New("interface is empty")
	}
	if err := validateTargetAddr(t.Gateway, "gateway"); err != nil {
		return err
	}
	if err := validateTargetAddr(t.Source, "source"); err != nil {
		return err
	}
	return nil
}

func validateTargetAddr(addr netip.Addr, field string) error {
	if !addr.IsValid() {
		return nil
	}
	if addr.Is4In6() {
		return fmt.Errorf("%s must use a plain IPv4 address", field)
	}
	if !addr.Is4() {
		return fmt.Errorf("%s: %w", field, ErrIPv6Unsupported)
	}
	if addr.Zone() != "" {
		return fmt.Errorf("%s must not contain a zone", field)
	}
	return nil
}

// ExitNode is the single authorized exit node a policy may use. Rules that
// target this ID route through Target; rules that target another ID are
// rejected so protected traffic never falls back to an unauthorized path.
// Target6 is nil when the exit node has no IPv6 egress; protected IPv6 is then
// installed fail-closed instead of using the physical default.
type ExitNode struct {
	ID      config.ExitNodeID
	Target  RouteTarget
	Target6 *RouteTarget6
}

// Validate checks the exit node identity and target.
func (e ExitNode) Validate() error {
	if e.ID == "" {
		return errors.New("exit node ID is empty")
	}
	if err := e.Target.Validate(); err != nil {
		return fmt.Errorf("exit node %q target: %w", e.ID, err)
	}
	return nil
}

// ApplicationIdentity is the stable identity a classified process was mapped
// to. Empty fields never match a policy condition.
type ApplicationIdentity struct {
	DesktopID  config.DesktopID
	Executable config.Executable
	FlatpakID  config.FlatpakID
	SnapID     config.SnapID
}

// ApplicationScope is a live application cgroup the classifier owns. CgroupPath
// is relative to the cgroup v2 mount point and identifies the scope a policy
// rule should match. UID separates concurrent user sessions that run the same
// application.
type ApplicationScope struct {
	Identity   ApplicationIdentity
	UID        config.UID
	CgroupPath string
}

// Validate checks that the scope can be turned into a socket cgroup match.
func (s ApplicationScope) Validate() error {
	if s.CgroupPath == "" {
		return errors.New("cgroup path is empty")
	}
	if len(s.CgroupPath) > 0 && s.CgroupPath[0] == '/' {
		return errors.New("cgroup path must be relative to the cgroup root")
	}
	if strings.Contains(s.CgroupPath, `\`) {
		return errors.New("cgroup path must use forward slashes")
	}
	parts := strings.Split(s.CgroupPath, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("cgroup path %q contains an invalid component %q", s.CgroupPath, part)
		}
	}
	return nil
}

// PolicyOptions are the runtime egress targets a backend needs to enforce a
// compiled policy. VPN and Direct are only required when the policy uses those
// actions. VPN6 and Direct6 are their IPv6 counterparts and are only required
// when the policy enables IPv6 and the corresponding class is used. ExitNode
// may be nil when no exit node is authorized; exit rules are then installed
// fail-closed. Applications are the live classified cgroup scopes for rules
// that select an application or a user ID.
type PolicyOptions struct {
	VPN          RouteTarget
	Direct       RouteTarget
	VPN6         RouteTarget6
	Direct6      RouteTarget6
	ExitNode     *ExitNode
	Applications []ApplicationScope
}

// State is the lifecycle state of a network backend.
type State string

const (
	// StateUninitialized means Initialize has not completed.
	StateUninitialized State = "uninitialized"
	// StateInitializing means Initialize is in progress.
	StateInitializing State = "initializing"
	// StateReady means the backend is initialized and every probed capability
	// is available.
	StateReady State = "ready"
	// StateDegraded means the backend is initialized but at least one probed
	// capability is unavailable.
	StateDegraded State = "degraded"
	// StateCleaning means cleanup is in progress.
	StateCleaning State = "cleaning"
	// StateFailed means the last initialization or cleanup failed.
	StateFailed State = "failed"
	// StateClosed means Close completed and the backend is terminal.
	StateClosed State = "closed"
)

// Valid reports whether the state is one of the defined values.
func (s State) Valid() bool {
	switch s {
	case StateUninitialized, StateInitializing, StateReady, StateDegraded,
		StateCleaning, StateFailed, StateClosed:
		return true
	default:
		return false
	}
}

// String returns the stable string form of the state.
func (s State) String() string {
	return string(s)
}

// CapabilityID identifies one probed kernel capability.
type CapabilityID string

const (
	// CapabilityNFTables is the nftables netlink interface.
	CapabilityNFTables CapabilityID = "nftables"
	// CapabilityNetlink is the generic netlink route socket.
	CapabilityNetlink CapabilityID = "netlink"
	// CapabilityPolicyRouting is IPv4 and IPv6 policy rule support.
	CapabilityPolicyRouting CapabilityID = "policy_routing"
	// CapabilityRouteOutputHook is the nftables route-type output hook.
	CapabilityRouteOutputHook CapabilityID = "route_output_hook"
	// CapabilityCgroupV2 is the cgroup v2 unified hierarchy.
	CapabilityCgroupV2 CapabilityID = "cgroup_v2"
	// CapabilitySocketCgroupV2 is the nftables socket cgroupv2 expression. It
	// is required only when a policy selects applications.
	CapabilitySocketCgroupV2 CapabilityID = "socket_cgroup_v2"
	// CapabilityEBPF reports optional kernel eBPF support. The classifier uses
	// cgroup v2 as its required path and never falls back to unclassified
	// routing when eBPF is unavailable.
	CapabilityEBPF CapabilityID = "ebpf"
	// CapabilityIPv6 is a usable local IPv6 network stack.
	CapabilityIPv6 CapabilityID = "ipv6"
)

// CapabilityState is the result of probing one capability.
type CapabilityState string

const (
	// CapabilityAvailable means the capability was detected and usable.
	CapabilityAvailable CapabilityState = "available"
	// CapabilityUnavailable means the capability is absent or unusable.
	CapabilityUnavailable CapabilityState = "unavailable"
	// CapabilityDegraded means the capability works with a documented
	// limitation.
	CapabilityDegraded CapabilityState = "degraded"
	// CapabilityUnknown means the capability could not be probed without a
	// state change.
	CapabilityUnknown CapabilityState = "unknown"
)

// Capability is one probe result.
type Capability struct {
	ID     CapabilityID
	State  CapabilityState
	Detail string
}

// Capabilities is a snapshot of every capability the backend probed.
type Capabilities struct {
	Items []Capability
}

// Get returns the result for one capability.
func (c Capabilities) Get(id CapabilityID) (Capability, bool) {
	for _, item := range c.Items {
		if item.ID == id {
			return item, true
		}
	}
	return Capability{}, false
}

// StateOf returns the state of one capability, or CapabilityUnknown when it
// was not probed.
func (c Capabilities) StateOf(id CapabilityID) CapabilityState {
	item, ok := c.Get(id)
	if !ok {
		return CapabilityUnknown
	}
	return item.State
}

// Degraded reports whether any required probed capability is not fully
// available. Optional eBPF support never makes a cgroup v2 backend degraded.
func (c Capabilities) Degraded() bool {
	for _, item := range c.Items {
		if item.ID == CapabilityEBPF {
			continue
		}
		if item.State != CapabilityAvailable {
			return true
		}
	}
	return false
}

// Missing returns the required capabilities that are not available.
func (c Capabilities) Missing(required ...CapabilityID) []Capability {
	var missing []Capability
	for _, id := range required {
		item, ok := c.Get(id)
		if !ok {
			missing = append(missing, Capability{
				ID:     id,
				State:  CapabilityUnknown,
				Detail: "capability was not probed",
			})
			continue
		}
		if item.State != CapabilityAvailable {
			missing = append(missing, item)
		}
	}
	return missing
}

// Clone returns a copy that callers can modify without changing the snapshot.
func (c Capabilities) Clone() Capabilities {
	items := make([]Capability, len(c.Items))
	copy(items, c.Items)
	return Capabilities{Items: items}
}

// CapabilityError reports a capability that prevents the backend from working.
type CapabilityError struct {
	Capability CapabilityID
	State      CapabilityState
	Detail     string
}

// Error implements error.
func (e *CapabilityError) Error() string {
	detail := e.Detail
	if detail == "" {
		detail = "no detail"
	}
	return fmt.Sprintf("%s capability %s: %s", e.State, e.Capability, detail)
}

// Unwrap reports the sentinel capability error.
func (e *CapabilityError) Unwrap() error {
	return ErrCapabilityUnavailable
}

// NotImplementedError names an operation that is accepted but not implemented.
type NotImplementedError struct {
	Operation string
}

// Error implements error.
func (e *NotImplementedError) Error() string {
	return fmt.Sprintf("%s: %v", e.Operation, ErrNotImplemented)
}

// Unwrap reports the sentinel not-implemented error.
func (e *NotImplementedError) Unwrap() error {
	return ErrNotImplemented
}

// OwnedObjects lists the kernel objects the backend owns and may remove.
type OwnedObjects struct {
	Table  string
	Chains []string
	Sets   []string
}

// Clone returns a copy that callers can modify without changing the snapshot.
func (o OwnedObjects) Clone() OwnedObjects {
	chains := make([]string, len(o.Chains))
	copy(chains, o.Chains)
	sets := make([]string, len(o.Sets))
	copy(sets, o.Sets)
	return OwnedObjects{Table: o.Table, Chains: chains, Sets: sets}
}

// Status is a point-in-time backend snapshot.
type Status struct {
	State         State
	Capabilities  Capabilities
	Owned         OwnedObjects
	PolicyApplied bool
	LastError     string
	UpdatedAt     time.Time
}

// DomainEntry is one address that a DNS name resolved to. ExpiresAt is zero
// when the caller wants the backend to use its default set timeout.
type DomainEntry struct {
	Prefix    netip.Prefix
	ExpiresAt time.Time
}

// Validate checks that the entry can be inserted into an owned set.
func (e DomainEntry) Validate() error {
	if !e.Prefix.IsValid() {
		return errors.New("prefix is invalid")
	}
	if e.Prefix.Addr().Is4In6() {
		return errors.New("prefix must use a plain IPv4 address")
	}
	if e.Prefix.Addr().Zone() != "" {
		return errors.New("prefix must not contain a zone")
	}
	if e.Prefix.Masked() != e.Prefix {
		return errors.New("prefix has host bits set")
	}
	return nil
}

// DomainSetUpdate replaces the resolved addresses for one policy action. The
// backend maps VPN, direct and block actions onto its owned timeout sets.
type DomainSetUpdate struct {
	Action  config.Action
	Entries []DomainEntry
}

// Validate checks the action and every entry before a backend touches a set.
func (u DomainSetUpdate) Validate() error {
	switch u.Action {
	case config.ActionVPN, config.ActionDirect, config.ActionBlock:
	case config.ActionExitNode:
		return errors.New("domain sets for exit nodes are not supported")
	default:
		return fmt.Errorf("unsupported domain set action %q", u.Action)
	}

	seen := make(map[netip.Prefix]struct{}, len(u.Entries))
	for i, entry := range u.Entries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if _, ok := seen[entry.Prefix]; ok {
			return fmt.Errorf("entry %d: duplicate prefix %s", i, entry.Prefix)
		}
		seen[entry.Prefix] = struct{}{}
	}
	return nil
}

// NetworkBackend is the platform surface used by the split tunnel engine.
//
// Initialize, Cleanup and Close are idempotent. ApplyPolicy and
// UpdateDomainSets must return ErrNotImplemented when a backend does not act
// on them; they must never report success without changing kernel state.
type NetworkBackend interface {
	// Initialize probes capabilities and creates the backend's owned objects.
	Initialize(ctx context.Context) error
	// ApplyPolicy installs a compiled policy using the runtime route targets in
	// options. It replaces any previously applied policy and must never report
	// success without changing kernel state.
	ApplyPolicy(ctx context.Context, compiled *policy.CompiledPolicy, options PolicyOptions) error
	// UpdateDomainSets replaces resolved domain addresses in the owned timeout
	// sets. It returns ErrNotImplemented until DNS tracking lands.
	UpdateDomainSets(ctx context.Context, updates []DomainSetUpdate) error
	// GetCapabilities probes kernel capabilities without changing state.
	GetCapabilities(ctx context.Context) (Capabilities, error)
	// GetStatus returns the current lifecycle state and owned objects.
	GetStatus(ctx context.Context) (Status, error)
	// Rollback discards applied policy state without removing baseline objects.
	Rollback(ctx context.Context) error
	// Cleanup removes owned objects and leaves unrelated objects untouched.
	Cleanup(ctx context.Context) error
	// Close performs cleanup and makes the backend terminal.
	Close(ctx context.Context) error
}
