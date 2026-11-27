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
)

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

// Degraded reports whether any probed capability is not fully available.
func (c Capabilities) Degraded() bool {
	for _, item := range c.Items {
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
	// ApplyPolicy installs a compiled policy. It returns ErrNotImplemented
	// until the backend supports policy enforcement.
	ApplyPolicy(ctx context.Context, compiled *policy.CompiledPolicy) error
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
