//go:build linux && !android

// Package linux implements the Linux split tunnel network backend.
//
// The backend owns one dedicated nftables table, allocates policy routing
// primitives that do not collide with upstream NetBird, and applies IPv4 and
// IPv6 include, exclude and custom policies. It installs only owned nftables
// rules tagged with the backend marker and only routes and policy rules
// allocated from the split ranges. The IPv6 path runs only when the policy
// enables it and the host has a usable IPv6 stack; otherwise IPv4 is applied
// unchanged. Resolved domain addresses are kept in owned timeout sets. The
// owned kill switch chain enforces the configured disabled, selective, global
// or strict mode. Applies are staged behind a persistent recovery journal so a
// crash either commits a verified intent or resolves to a fail-closed guard.
package linux

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
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
	ApplyPolicy(ctx context.Context, policy nftPolicy) error
	ApplyKillSwitch(ctx context.Context, controlSets map[setName][]netip.Prefix, rules []nftKillRule) error
	ApplyDomainSets(ctx context.Context, updates []backend.DomainSetUpdate) error
	ClearPolicy(ctx context.Context) error
	VerifyPolicy(ctx context.Context, policy nftPolicy) error
	Inspect(ctx context.Context) (nftObservation, error)
}

// Backend is the Linux implementation of backend.NetworkBackend.
type Backend struct {
	mu sync.Mutex

	tableName    string
	probe        capabilityProber
	openNFTables func(table string) (nftManager, error)
	router       routeManager

	state         backend.State
	capabilities  backend.Capabilities
	cgroupIDs     cgroupIDResolver
	nft           nftManager
	allocations   allocations
	allocated     bool
	initialized   bool
	cleanupDone   bool
	closed        bool
	policyApplied bool
	lastPolicy    *policy.CompiledPolicy
	lastOptions   backend.PolicyOptions
	lastPlan      *policyPlan
	hasPolicy     bool
	generation    uint64
	lastError     string
	updatedAt     time.Time

	journal             journalStore
	committed           *journalSnapshot
	journalState        JournalState
	journalRevision     uint64
	recoveryIssues      []string
	rollbackFailed      bool
	protectionPreserved bool
	retryAttempts       int
	retryDelay          time.Duration
	sleep               func(context.Context, time.Duration) error
	applyHook           func(applyPhase) error
}

var _ backend.NetworkBackend = (*Backend)(nil)

// applyPhase names a fault-injection point in the staged apply. Tests use it
// to simulate a crash or failure between journal transitions.
type applyPhase string

const (
	applyPhaseValidated applyPhase = "validated"
	applyPhasePreArmed  applyPhase = "pre_armed"
	applyPhaseStaged    applyPhase = "staged"
	applyPhaseApplied   applyPhase = "applied"
	applyPhaseVerified  applyPhase = "verified"
	applyPhaseCommitted applyPhase = "committed"
)

// New returns a Linux backend. It performs no privileged work until Initialize.
func New() *Backend {
	return newBackendWithJournal(
		systemProber{},
		func(table string) (nftManager, error) {
			return newNFTablesManager(table)
		},
		newNetlinkRouter(),
		defaultTableName,
		newFileJournal(defaultJournalPath),
	)
}

func newBackendWith(
	probe capabilityProber,
	openNFTables func(string) (nftManager, error),
	router routeManager,
	table string,
) *Backend {
	return newBackendWithJournal(probe, openNFTables, router, table, newMemoryJournal())
}

func newBackendWithJournal(
	probe capabilityProber,
	openNFTables func(string) (nftManager, error),
	router routeManager,
	table string,
	journal journalStore,
) *Backend {
	return &Backend{
		tableName:     table,
		probe:         probe,
		openNFTables:  openNFTables,
		router:        router,
		cgroupIDs:     newStatCgroupResolver(),
		state:         backend.StateUninitialized,
		updatedAt:     time.Now().UTC(),
		capabilities:  backend.Capabilities{},
		journal:       journal,
		retryAttempts: defaultRecoveryRetryAttempts,
		retryDelay:    defaultRecoveryRetryDelay,
	}
}

func (b *Backend) runApplyHookLocked(phase applyPhase) error {
	if b.applyHook == nil {
		return nil
	}
	return b.applyHook(phase)
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

// ApplyPolicy replaces the applied policy. A disabled policy, or a policy with
// no rules, only clears previously applied state. Conditions and targets the
// milestone cannot enforce are rejected before any kernel state is touched. A
// protected class whose target is absent is installed with an unreachable
// default instead of falling back to the physical path. IPv6 is applied only
// when the compiled policy enables it and the host has a usable IPv6 stack.
//
// The apply is staged through a durable recovery journal: the guard is armed
// or preserved before routes and classification change, the new kernel state is
// verified, and only then is the intent committed. A failed apply restores the
// previous policy or leaves a fail-closed guard installed. A successful apply
// becomes the policy that Reapply restores after a network change.
func (b *Backend) ApplyPolicy(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	return b.applyPolicyLocked(ctx, compiled, options)
}

// InstallProtection installs or replaces only the kill switch rules for the
// configured mode. It is the idempotent pre-arm path a caller uses before
// managed traffic: protection is in the kernel before routes and
// classification are applied. A disabled mode clears the rules. Selective
// protection refers to the destination sets that ApplyPolicy populates, so it
// becomes fully effective once that policy is applied; global and strict are
// effective immediately. The call does not remember a policy for Reapply, so
// boot ordering and delegated privilege remain the caller's responsibility.
func (b *Backend) InstallProtection(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
) error {
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
	if err := b.ensureAllocationsLocked(); err != nil {
		b.recordErrorLocked(err)
		return fmt.Errorf("allocate split policy routing primitives: %w", err)
	}

	enableIPv6 := compiled != nil && compiled.IPv6 && b.ipv6AvailableLocked()
	rules, controlSets, err := compileKillSwitch(compiled, options, b.allocations, enableIPv6)
	if err != nil {
		b.recordErrorLocked(err)
		return fmt.Errorf("compile kill switch: %w", err)
	}
	if err := b.nft.ApplyKillSwitch(ctx, controlSets, rules); err != nil {
		b.recordErrorLocked(err)
		return fmt.Errorf("install kill switch: %w", err)
	}

	b.updatedAt = time.Now().UTC()
	return nil
}

// EmergencyReset removes applied classification rules, protected routes and
// kill switch rules and forgets the last policy, restoring normal connectivity
// until ApplyPolicy arms protection again. It is idempotent and does not remove
// the baseline owned table.
func (b *Backend) EmergencyReset(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return backend.ErrClosed
	}
	if b.initialized {
		if err := b.rollbackPolicyLocked(ctx); err != nil {
			b.recordErrorLocked(err)
			return err
		}
	}
	if err := b.clearJournalLocked(); err != nil {
		b.recordErrorLocked(err)
		return err
	}

	b.lastPolicy = nil
	b.lastOptions = backend.PolicyOptions{}
	b.lastPlan = nil
	b.hasPolicy = false
	b.committed = nil
	b.journalState = ""
	b.journalRevision = 0
	b.policyApplied = false
	b.resetRecoveryDiagnosticsLocked()
	b.lastError = ""
	b.updatedAt = time.Now().UTC()
	return nil
}

// Reapply re-applies the last successfully applied policy. It is used by the
// netlink reconciler after interface, address, route or gateway changes. It
// returns nil before any policy has been applied and for a disabled policy.
func (b *Backend) Reapply(ctx context.Context) error {
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
	if !b.hasPolicy || b.lastPolicy == nil || !b.lastPolicy.Enabled {
		return nil
	}
	return b.applyPolicyLocked(ctx, b.lastPolicy, b.lastOptions)
}

func (b *Backend) applyPolicyLocked(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
) error {
	if b.closed {
		return backend.ErrClosed
	}
	if !b.initialized {
		return backend.ErrNotInitialized
	}
	if err := b.ensureAllocationsLocked(); err != nil {
		b.recordErrorLocked(err)
		return fmt.Errorf("allocate split policy routing primitives: %w", err)
	}
	if compiled != nil && compiled.UsesApplications() {
		if err := b.requireApplicationCapabilitiesLocked(); err != nil {
			b.recordErrorLocked(err)
			return err
		}
	}

	previous, err := b.previousIntentLocked()
	if err != nil {
		b.recordErrorLocked(err)
		return err
	}
	if previous.journal != nil && previous.journal.State.interrupted() {
		err := fmt.Errorf("%w: journal is %s", ErrRecoveryRequired, previous.journal.State)
		b.recordErrorLocked(err)
		return err
	}

	enableIPv6 := compiled != nil && compiled.IPv6 && b.ipv6AvailableLocked()
	plan, err := compilePolicyForWithResolver(
		compiled, options, b.allocations, enableIPv6, b.cgroupIDs)
	if err != nil {
		b.recordErrorLocked(err)
		return fmt.Errorf("compile policy: %w", err)
	}

	revision := b.generation + 1
	if previous.journal != nil && previous.journal.Revision >= revision {
		// A fresh backend starts with generation zero while the journal may
		// already hold a committed revision, so never move the revision back.
		revision = previous.journal.Revision + 1
	}
	entry := b.newJournalEntryLocked(compiled, plan, previous, revision)
	if err := b.saveJournalLocked(&entry); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	b.journalState = entry.State
	b.journalRevision = entry.Revision
	b.resetRecoveryDiagnosticsLocked()
	b.protectionPreserved = previous.hasProtection

	if !compiled.Enabled {
		return b.commitDisabledPolicyLocked(ctx, compiled, options, &entry, previous)
	}

	if err := b.runApplyHookLocked(applyPhaseValidated); err != nil {
		return b.handleApplyInterruptionLocked(ctx, &entry, previous, err)
	}

	// Install the new guard before routes or classification change. A prior
	// guard stays in place when the new intent disables the kill switch, so it
	// is only cleared after the new state is verified.
	if len(plan.nft.killswitch) > 0 {
		control := killSwitchControlSets(plan.nft.sets)
		if err := b.nft.ApplyKillSwitch(ctx, control, plan.nft.killswitch); err != nil {
			applyErr := fmt.Errorf("arm kill switch guard: %w", err)
			b.recordErrorLocked(applyErr)
			return b.rollbackFailedApplyLocked(ctx, &entry, previous, applyErr)
		}
		b.protectionPreserved = true
	}
	if err := b.advanceJournalLocked(&entry, JournalStatePreArmed); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	b.journalState = entry.State
	if err := b.runApplyHookLocked(applyPhasePreArmed); err != nil {
		return b.handleApplyInterruptionLocked(ctx, &entry, previous, err)
	}

	if err := b.router.Apply(ctx, plan.route); err != nil {
		applyErr := fmt.Errorf("apply policy routing: %w", err)
		b.recordErrorLocked(applyErr)
		return b.rollbackFailedApplyLocked(ctx, &entry, previous, applyErr)
	}
	if err := b.advanceJournalLocked(&entry, JournalStateStaged); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	b.journalState = entry.State
	if err := b.runApplyHookLocked(applyPhaseStaged); err != nil {
		return b.handleApplyInterruptionLocked(ctx, &entry, previous, err)
	}

	if err := b.nft.ApplyPolicy(ctx, plan.nft); err != nil {
		applyErr := fmt.Errorf("apply nftables policy: %w", err)
		b.recordErrorLocked(applyErr)
		return b.rollbackFailedApplyLocked(ctx, &entry, previous, applyErr)
	}
	if err := b.runApplyHookLocked(applyPhaseApplied); err != nil {
		return b.handleApplyInterruptionLocked(ctx, &entry, previous, err)
	}

	if err := b.verifyPlanLocked(ctx, plan); err != nil {
		applyErr := fmt.Errorf("verify applied policy: %w", err)
		b.recordErrorLocked(applyErr)
		return b.rollbackFailedApplyLocked(ctx, &entry, previous, applyErr)
	}
	if err := b.advanceJournalLocked(&entry, JournalStateVerified); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	b.journalState = entry.State
	if err := b.runApplyHookLocked(applyPhaseVerified); err != nil {
		return b.handleApplyInterruptionLocked(ctx, &entry, previous, err)
	}

	if err := b.router.RemoveUnused(ctx, b.allocations, usedClasses(plan)); err != nil {
		applyErr := fmt.Errorf("remove stale policy routing: %w", err)
		b.recordErrorLocked(applyErr)
		return b.rollbackFailedApplyLocked(ctx, &entry, previous, applyErr)
	}

	if err := b.advanceJournalLocked(&entry, JournalStateCommitted); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	b.journalState = entry.State
	if err := b.runApplyHookLocked(applyPhaseCommitted); err != nil {
		return b.handleApplyInterruptionLocked(ctx, &entry, previous, err)
	}

	b.policyApplied = true
	b.rememberPolicyLocked(compiled, options, plan)
	snapshot := entry.snapshot()
	b.committed = &snapshot
	b.generation = revision
	b.lastError = ""
	b.updatedAt = time.Now().UTC()
	b.protectionPreserved = entry.Guard != nil && len(entry.Guard.Rules) > 0
	return nil
}

// previousIntent captures the last committed state for rollback. The journal
// entry is loaded first so a restart can still identify a committed intent.
func (b *Backend) previousIntentLocked() (applyPrevious, error) {
	previous := applyPrevious{
		compiled:      b.lastPolicy,
		options:       clonePolicyOptions(b.lastOptions),
		plan:          b.lastPlan,
		hadPolicy:     b.hasPolicy,
		snapshot:      cloneSnapshot(b.committed),
		hasProtection: b.committed != nil && b.committed.Guard != nil && len(b.committed.Guard.Rules) > 0,
	}
	entry, err := b.loadJournalLocked()
	switch {
	case err == nil:
		previous.journal = &entry
		if entry.State.committed() {
			snapshot := entry.snapshot()
			previous.snapshot = &snapshot
		}
	case errors.Is(err, ErrJournalNotFound):
	default:
		return applyPrevious{}, err
	}
	return previous, nil
}

type applyPrevious struct {
	compiled      *policy.CompiledPolicy
	options       backend.PolicyOptions
	plan          *policyPlan
	hadPolicy     bool
	snapshot      *journalSnapshot
	journal       *journalEntry
	hasProtection bool
}

func cloneSnapshot(snapshot *journalSnapshot) *journalSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	cloned.Guard = cloneGuard(snapshot.Guard)
	cloned.Ownership = cloneOwnership(snapshot.Ownership)
	return &cloned
}

func (b *Backend) newJournalEntryLocked(
	compiled *policy.CompiledPolicy,
	plan *policyPlan,
	previous applyPrevious,
	revision uint64,
) journalEntry {
	entry := journalEntry{
		SchemaVersion: journalSchemaVersion,
		State:         JournalStateValidated,
		Revision:      revision,
		PolicyID:      fingerprintPlan(plan),
		Ownership:     ownershipFrom(b.allocations, b.nft.Owned()),
		UpdatedAt:     time.Now().UTC(),
	}
	if compiled != nil {
		entry.Mode = string(compiled.KillSwitch)
	}
	entry.Guard = guardFromPlan(plan)
	if previous.snapshot != nil {
		entry.Previous = cloneSnapshot(previous.snapshot)
	}
	return entry
}

func (b *Backend) commitDisabledPolicyLocked(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
	entry *journalEntry,
	previous applyPrevious,
) error {
	if err := b.advanceJournalLocked(entry, JournalStatePreArmed); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	if err := b.advanceJournalLocked(entry, JournalStateStaged); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	if err := b.rollbackPolicyLocked(ctx); err != nil {
		applyErr := fmt.Errorf("clear disabled policy: %w", err)
		b.recordErrorLocked(applyErr)
		return b.rollbackFailedApplyLocked(ctx, entry, previous, applyErr)
	}
	if err := b.verifyPlanLocked(ctx, &policyPlan{}); err != nil {
		applyErr := fmt.Errorf("verify cleared policy: %w", err)
		b.recordErrorLocked(applyErr)
		return b.rollbackFailedApplyLocked(ctx, entry, previous, applyErr)
	}
	if err := b.advanceJournalLocked(entry, JournalStateVerified); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	if err := b.advanceJournalLocked(entry, JournalStateCommitted); err != nil {
		b.recordErrorLocked(err)
		return err
	}
	b.journalState = entry.State
	b.policyApplied = false
	b.rememberPolicyLocked(compiled, options, &policyPlan{})
	snapshot := entry.snapshot()
	b.committed = &snapshot
	b.generation = entry.Revision
	b.lastError = ""
	b.updatedAt = time.Now().UTC()
	return nil
}

// handleApplyInterruptionLocked implements the fault-injection crash point. A
// simulated crash leaves the journal exactly at the phase it reached so a
// fresh backend can recover it.
func (b *Backend) handleApplyInterruptionLocked(
	ctx context.Context,
	entry *journalEntry,
	previous applyPrevious,
	cause error,
) error {
	if errors.Is(cause, errSimulatedCrash) {
		b.journalState = entry.State
		b.journalRevision = entry.Revision
		b.recordErrorLocked(cause)
		return cause
	}
	b.recordErrorLocked(cause)
	return b.rollbackFailedApplyLocked(ctx, entry, previous, cause)
}

var errSimulatedCrash = errors.New("simulated apply crash")

func (b *Backend) rollbackFailedApplyLocked(
	ctx context.Context,
	entry *journalEntry,
	previous applyPrevious,
	cause error,
) error {
	restoreErr := b.restorePreviousLocked(ctx, previous)
	if restoreErr == nil {
		return b.finishRollbackLocked(entry, previous, cause)
	}

	rollbackErr := fmt.Errorf("restore previous policy: %w", restoreErr)
	b.rollbackFailed = true
	b.recordRecoveryIssueLocked("%v", rollbackErr)
	entry.LastError = errors.Join(cause, rollbackErr).Error()
	entry.Issues = append([]string(nil), b.recoveryIssues...)
	if entry.State != JournalStateRolledBack {
		if err := entry.transition(JournalStateRolledBack); err != nil {
			entry.State = JournalStateRolledBack
		}
	}
	entry.UpdatedAt = time.Now().UTC()

	guardErr := b.installFailClosedGuardLocked(ctx)
	if guardErr != nil {
		guardErr = fmt.Errorf("install fail-closed guard: %w", guardErr)
		b.recordRecoveryIssueLocked("%v", guardErr)
		entry.Issues = append([]string(nil), b.recoveryIssues...)
	} else {
		b.protectionPreserved = true
	}
	if err := b.saveJournalLocked(entry); err != nil {
		return errors.Join(cause, rollbackErr, guardErr, err)
	}
	b.journalState = entry.State
	b.journalRevision = entry.Revision
	return errors.Join(cause, rollbackErr, guardErr)
}

func (b *Backend) restorePreviousLocked(ctx context.Context, previous applyPrevious) error {
	if previous.plan != nil {
		if err := b.restorePlanLocked(ctx, previous.plan); err != nil {
			return err
		}
		return nil
	}
	if previous.snapshot != nil {
		return errors.New("previous compiled policy is unavailable")
	}
	return b.removePolicyStateLocked(ctx)
}

func (b *Backend) restorePlanLocked(ctx context.Context, plan *policyPlan) error {
	if err := b.router.Apply(ctx, plan.route); err != nil {
		return fmt.Errorf("restore policy routing: %w", err)
	}
	if err := b.nft.ApplyPolicy(ctx, plan.nft); err != nil {
		return fmt.Errorf("restore nftables policy: %w", err)
	}
	return b.verifyPlanLocked(ctx, plan)
}

func (b *Backend) removePolicyStateLocked(ctx context.Context) error {
	if b.nft != nil {
		if err := b.nft.ClearPolicy(ctx); err != nil {
			return fmt.Errorf("clear nftables policy: %w", err)
		}
	}
	if b.allocated && b.router != nil {
		if err := b.router.Remove(ctx, b.allocations); err != nil {
			return fmt.Errorf("remove policy routing: %w", err)
		}
	}
	b.policyApplied = false
	return nil
}

func (b *Backend) finishRollbackLocked(
	entry *journalEntry,
	previous applyPrevious,
	cause error,
) error {
	if previous.snapshot != nil {
		if entry.State != JournalStateRolledBack {
			if err := entry.transition(JournalStateRolledBack); err != nil {
				entry.State = JournalStateRolledBack
			}
		}
		entry.applySnapshot(*previous.snapshot)
		entry.State = JournalStateCommitted
		entry.Previous = nil
		entry.LastError = cause.Error()
		entry.Issues = append([]string(nil), b.recoveryIssues...)
		entry.UpdatedAt = time.Now().UTC()
		if err := b.saveJournalLocked(entry); err != nil {
			b.recordErrorLocked(err)
			return errors.Join(cause, err)
		}
		b.journalState = entry.State
		b.journalRevision = entry.Revision
		snapshot := entry.snapshot()
		b.committed = &snapshot
		b.policyApplied = true
		b.lastError = cause.Error()
		b.updatedAt = time.Now().UTC()
		return cause
	}

	if err := b.clearJournalLocked(); err != nil {
		b.recordErrorLocked(err)
		return errors.Join(cause, err)
	}
	b.journalState = ""
	b.journalRevision = 0
	b.committed = nil
	b.policyApplied = false
	b.lastError = cause.Error()
	b.updatedAt = time.Now().UTC()
	return cause
}

func (b *Backend) verifyPlanLocked(ctx context.Context, plan *policyPlan) error {
	if err := b.nft.VerifyPolicy(ctx, plan.nft); err != nil {
		return fmt.Errorf("verify nftables policy: %w", err)
	}
	if err := b.router.Verify(ctx, plan.route); err != nil {
		return fmt.Errorf("verify policy routing: %w", err)
	}
	return nil
}

func (b *Backend) installFailClosedGuardLocked(ctx context.Context) error {
	if b.nft == nil {
		return backend.ErrNotInitialized
	}
	enableIPv6 := b.ipv6AvailableLocked()
	rules := failClosedGuard(enableIPv6)
	return b.nft.ApplyKillSwitch(ctx, nil, rules)
}

// rememberPolicyLocked stores the last successful policy so the netlink
// reconciler can restore it. The compiled policy is immutable after
// compilation and the options are deep-copied at this boundary.
func (b *Backend) rememberPolicyLocked(
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
	plan *policyPlan,
) {
	b.lastPolicy = compiled
	b.lastOptions = clonePolicyOptions(options)
	b.lastPlan = plan
	b.hasPolicy = true
}

func clonePolicyOptions(options backend.PolicyOptions) backend.PolicyOptions {
	cloned := options
	cloned.Applications = append([]backend.ApplicationScope(nil), options.Applications...)
	cloned.DNSResolvers = append([]netip.Prefix(nil), options.DNSResolvers...)
	if options.ExitNode == nil {
		return cloned
	}
	exit := *options.ExitNode
	if options.ExitNode.Target6 != nil {
		target6 := *options.ExitNode.Target6
		exit.Target6 = &target6
	}
	cloned.ExitNode = &exit
	return cloned
}

// UpdateDomainSets replaces the owned domain timeout sets with the resolved
// addresses. It validates the whole batch before touching kernel state so a
// malformed or ambiguous update leaves the previous sets intact.
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
	if err := backend.ValidateDomainSetUpdates(updates); err != nil {
		b.recordErrorLocked(err)
		return fmt.Errorf("validate domain sets: %w", err)
	}

	var journal *journalEntry
	loaded, err := b.loadJournalLocked()
	switch {
	case err == nil:
		if loaded.State.interrupted() {
			err := fmt.Errorf("%w: journal is %s", ErrRecoveryRequired, loaded.State)
			b.recordErrorLocked(err)
			return err
		}
		journal = &loaded
	case errors.Is(err, ErrJournalNotFound):
	default:
		b.recordErrorLocked(err)
		return fmt.Errorf("load recovery journal: %w", err)
	}

	// Domain sets are transient owned state, so they do not change the
	// committed intent. Touching the journal records that a lifecycle event
	// completed while keeping the revision and policy identity stable.
	if err := b.nft.ApplyDomainSets(ctx, updates); err != nil {
		b.recordErrorLocked(err)
		return fmt.Errorf("apply domain sets: %w", err)
	}
	b.updatedAt = time.Now().UTC()
	if journal != nil {
		journal.UpdatedAt = b.updatedAt
		if err := b.saveJournalLocked(journal); err != nil {
			b.recordErrorLocked(err)
			return err
		}
	}
	return nil
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
		Generation:    b.generation,
	}, nil
}

// Rollback removes applied policy rules, routes and classification rules
// without removing the baseline table, chains or sets.
func (b *Backend) Rollback(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return backend.ErrClosed
	}
	if b.initialized {
		if err := b.rollbackPolicyLocked(ctx); err != nil {
			b.recordErrorLocked(err)
			return err
		}
	}
	if err := b.clearJournalLocked(); err != nil {
		b.recordErrorLocked(err)
		return err
	}

	b.lastPolicy = nil
	b.lastOptions = backend.PolicyOptions{}
	b.lastPlan = nil
	b.hasPolicy = false
	b.committed = nil
	b.journalState = ""
	b.journalRevision = 0
	b.policyApplied = false
	b.lastError = ""
	b.updatedAt = time.Now().UTC()
	return nil
}

func (b *Backend) rollbackPolicyLocked(ctx context.Context) error {
	var merr *multierror.Error

	if b.nft != nil {
		if err := b.nft.ClearPolicy(ctx); err != nil {
			// Keep routes and policy rules in place if classification could
			// not be removed, so protected traffic cannot leak.
			return fmt.Errorf("clear nftables policy: %w", err)
		}
	}
	if b.allocated && b.router != nil {
		if err := b.router.Remove(ctx, b.allocations); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove policy routing: %w", err))
		}
	}

	b.policyApplied = false
	return nberrors.FormatErrorOrNil(merr)
}

// requireApplicationCapabilitiesLocked rejects an application policy when the
// kernel cannot classify sockets by cgroup. The backend never downgrades to
// unclassified routing for selected applications.
func (b *Backend) requireApplicationCapabilitiesLocked() error {
	for _, id := range []backend.CapabilityID{
		backend.CapabilityCgroupV2,
		backend.CapabilitySocketCgroupV2,
	} {
		state := b.capabilities.StateOf(id)
		if state == backend.CapabilityAvailable {
			continue
		}
		if id == backend.CapabilitySocketCgroupV2 && state == backend.CapabilityDegraded {
			continue
		}
		return &backend.CapabilityError{
			Capability: id,
			State:      state,
			Detail:     b.capabilityDetailLocked(id),
		}
	}
	return nil
}

func (b *Backend) capabilityDetailLocked(id backend.CapabilityID) string {
	item, ok := b.capabilities.Get(id)
	if !ok {
		return "capability was not probed"
	}
	return item.Detail
}

// ipv6AvailableLocked reports whether the probed host stack can carry IPv6.
// Missing IPv6 skips only the v6 path; it never fails an IPv4 policy.
func (b *Backend) ipv6AvailableLocked() bool {
	return b.capabilities.StateOf(backend.CapabilityIPv6) == backend.CapabilityAvailable
}

func (b *Backend) ensureAllocationsLocked() error {
	if b.allocated {
		return nil
	}
	allocations, err := newAllocations()
	if err != nil {
		return err
	}
	b.allocations = allocations
	b.allocated = true
	return nil
}

func (b *Backend) recordErrorLocked(err error) {
	b.lastError = err.Error()
	b.updatedAt = time.Now().UTC()
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

	if err := b.ensureAllocationsLocked(); err != nil {
		b.failLocked(err)
		return err
	}
	if err := b.rollbackPolicyLocked(ctx); err != nil {
		cleanupErr := fmt.Errorf("remove applied policy: %w", err)
		b.failLocked(cleanupErr)
		return cleanupErr
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

	if err := b.clearJournalLocked(); err != nil {
		cleanupErr := fmt.Errorf("clear recovery journal: %w", err)
		b.failLocked(cleanupErr)
		return cleanupErr
	}

	b.nft = nil
	b.initialized = false
	b.cleanupDone = true
	b.policyApplied = false
	b.lastPolicy = nil
	b.lastOptions = backend.PolicyOptions{}
	b.lastPlan = nil
	b.hasPolicy = false
	b.committed = nil
	b.journalState = ""
	b.journalRevision = 0
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
