//go:build linux && !android

// Package linux implements the Linux split tunnel network backend.
//
// The backend owns one dedicated nftables table, allocates policy routing
// primitives that do not collide with upstream NetBird, and exposes a netlink
// monitor skeleton for later route reconciliation. M03 does not install
// routes, classify traffic or enforce a kill switch.
package linux

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

const defaultTableName = "netbird_split"

var requiredCapabilities = []backend.CapabilityID{
	backend.CapabilityNFTables,
	backend.CapabilityNetlink,
	backend.CapabilityPolicyRouting,
	backend.CapabilityRouteOutputHook,
}

type capabilityProber interface {
	Probe(ctx context.Context) (backend.Capabilities, error)
}

type nftManager interface {
	Ensure(ctx context.Context) error
	Cleanup(ctx context.Context) error
	CreatedTable() bool
	Owned() backend.OwnedObjects
}

// Backend is the Linux implementation of backend.NetworkBackend.
type Backend struct {
	mu sync.Mutex

	tableName    string
	probe        capabilityProber
	openNFTables func(table string) (nftManager, error)

	state         backend.State
	capabilities  backend.Capabilities
	nft           nftManager
	initialized   bool
	cleanupDone   bool
	closed        bool
	policyApplied bool
	lastError     string
	updatedAt     time.Time
}

var _ backend.NetworkBackend = (*Backend)(nil)

// New returns a Linux backend. It performs no privileged work until Initialize.
func New() *Backend {
	return newBackend(
		systemProber{},
		func(table string) (nftManager, error) {
			return newNFTablesManager(table)
		},
		defaultTableName,
	)
}

func newBackend(probe capabilityProber, openNFTables func(string) (nftManager, error), table string) *Backend {
	return &Backend{
		tableName:    table,
		probe:        probe,
		openNFTables: openNFTables,
		state:        backend.StateUninitialized,
		updatedAt:    time.Now().UTC(),
		capabilities: backend.Capabilities{},
	}
}

// Initialize probes capabilities and creates the owned nftables objects.
// Repeated calls after success are no-ops. A failed call removes only objects
// it created in that call.
func (b *Backend) Initialize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return backend.ErrClosed
	}
	if b.initialized {
		return nil
	}

	b.setStateLocked(backend.StateInitializing)
	b.cleanupDone = false
	b.policyApplied = false

	capabilities, err := b.probe.Probe(ctx)
	if err != nil {
		b.failLocked(fmt.Errorf("probe capabilities: %w", err))
		return fmt.Errorf("probe capabilities: %w", err)
	}
	b.capabilities = capabilities.Clone()

	if err := requireCapabilities(capabilities); err != nil {
		b.failLocked(err)
		return err
	}

	manager, err := b.openNFTables(b.tableName)
	if err != nil {
		b.failLocked(fmt.Errorf("open nftables: %w", err))
		return fmt.Errorf("open nftables: %w", err)
	}

	if err := manager.Ensure(ctx); err != nil {
		initErr := fmt.Errorf("initialize nftables objects: %w", err)
		if manager.CreatedTable() {
			if cleanupErr := manager.Cleanup(ctx); cleanupErr != nil {
				initErr = errors.Join(initErr,
					fmt.Errorf("roll back created nftables table: %w", cleanupErr))
			}
		}
		b.failLocked(initErr)
		return initErr
	}

	b.nft = manager
	b.initialized = true
	b.cleanupDone = false
	b.lastError = ""
	if capabilities.Degraded() {
		b.setStateLocked(backend.StateDegraded)
	} else {
		b.setStateLocked(backend.StateReady)
	}
	return nil
}

// ApplyPolicy is reserved for M04 and currently fails with ErrNotImplemented.
func (b *Backend) ApplyPolicy(ctx context.Context, compiled *policy.CompiledPolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return backend.ErrClosed
	}
	if !b.initialized {
		return backend.ErrNotInitialized
	}

	_ = compiled
	return &backend.NotImplementedError{Operation: "apply policy"}
}

// UpdateDomainSets is reserved for M08 and currently fails with
// ErrNotImplemented.
func (b *Backend) UpdateDomainSets(ctx context.Context, updates []backend.DomainSetUpdate) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return backend.ErrClosed
	}
	if !b.initialized {
		return backend.ErrNotInitialized
	}

	_ = updates
	return &backend.NotImplementedError{Operation: "update domain sets"}
}

// GetCapabilities probes kernel capabilities without changing kernel state.
func (b *Backend) GetCapabilities(ctx context.Context) (backend.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return backend.Capabilities{}, err
	}

	capabilities, err := b.probe.Probe(ctx)
	if err != nil {
		return backend.Capabilities{}, fmt.Errorf("probe capabilities: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.capabilities = capabilities.Clone()
	if b.initialized {
		if capabilities.Degraded() {
			b.setStateLocked(backend.StateDegraded)
		} else {
			b.setStateLocked(backend.StateReady)
		}
	}
	return capabilities.Clone(), nil
}

// GetStatus returns a snapshot of the lifecycle state, capabilities and owned
// objects.
func (b *Backend) GetStatus(ctx context.Context) (backend.Status, error) {
	if err := ctx.Err(); err != nil {
		return backend.Status{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var owned backend.OwnedObjects
	if b.nft != nil {
		owned = b.nft.Owned().Clone()
	}

	return backend.Status{
		State:         b.state,
		Capabilities:  b.capabilities.Clone(),
		Owned:         owned,
		PolicyApplied: b.policyApplied,
		LastError:     b.lastError,
		UpdatedAt:     b.updatedAt,
	}, nil
}

// Rollback discards applied policy state without removing baseline objects.
// M03 never applies policy, so it only clears the applied flag.
func (b *Backend) Rollback(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return backend.ErrClosed
	}
	if !b.initialized {
		return nil
	}

	b.policyApplied = false
	return nil
}

// Cleanup removes the backend's owned objects. It is safe to call without a
// successful Initialize, so a restart can remove state left by a crash.
func (b *Backend) Cleanup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	return b.cleanupLocked(ctx)
}

// Close removes owned objects and makes the backend terminal. Repeated calls
// return nil.
func (b *Backend) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	if err := b.cleanupLocked(ctx); err != nil {
		return err
	}

	b.closed = true
	b.setStateLocked(backend.StateClosed)
	return nil
}

func (b *Backend) cleanupLocked(ctx context.Context) error {
	if b.cleanupDone {
		return nil
	}

	manager := b.nft
	if manager == nil {
		var err error
		manager, err = b.openNFTables(b.tableName)
		if err != nil {
			b.failLocked(fmt.Errorf("open nftables for cleanup: %w", err))
			return fmt.Errorf("open nftables for cleanup: %w", err)
		}
	}

	b.setStateLocked(backend.StateCleaning)
	if err := manager.Cleanup(ctx); err != nil {
		cleanupErr := fmt.Errorf("cleanup nftables objects: %w", err)
		b.failLocked(cleanupErr)
		return cleanupErr
	}

	b.nft = nil
	b.initialized = false
	b.cleanupDone = true
	b.policyApplied = false
	b.lastError = ""
	b.setStateLocked(backend.StateUninitialized)
	return nil
}

func (b *Backend) failLocked(err error) {
	b.lastError = err.Error()
	b.setStateLocked(backend.StateFailed)
}

func (b *Backend) setStateLocked(state backend.State) {
	b.state = state
	b.updatedAt = time.Now().UTC()
}

func requireCapabilities(capabilities backend.Capabilities) error {
	missing := capabilities.Missing(requiredCapabilities...)
	if len(missing) == 0 {
		return nil
	}

	errs := make([]error, 0, len(missing))
	for _, item := range missing {
		errs = append(errs, &backend.CapabilityError{
			Capability: item.ID,
			State:      item.State,
			Detail:     item.Detail,
		})
	}
	return errors.Join(errs...)
}
