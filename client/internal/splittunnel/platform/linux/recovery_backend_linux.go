//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
)

// Recover reconciles the last journal against the observable kernel state.
//
// A committed intent is verified, and reapplied from intent when the caller
// supplies it. An interrupted intent is undone: owned policy state is removed
// and the recorded guard is reinstalled, so a crash cannot leave protected
// traffic on the physical path. Without a journal, owned state left by a crash
// is removed. Foreign objects are never touched; recovery fails instead.
//
// The backend must be initialized. Recovery is idempotent.
func (b *Backend) Recover(ctx context.Context, intent *RecoveryIntent) (RecoveryReport, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryReport{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return RecoveryReport{}, backend.ErrClosed
	}
	if !b.initialized {
		return RecoveryReport{}, backend.ErrNotInitialized
	}
	if err := b.ensureAllocationsLocked(); err != nil {
		return RecoveryReport{}, fmt.Errorf("allocate split policy routing primitives: %w", err)
	}

	entry, err := b.loadJournalLocked()
	switch {
	case errors.Is(err, ErrJournalNotFound):
		return b.recoverWithoutJournalLocked(ctx)
	case err != nil:
		b.journalState = ""
		b.journalRevision = 0
		b.recordErrorLocked(err)
		return RecoveryReport{Issues: []string{err.Error()}}, fmt.Errorf("load recovery journal: %w", err)
	}

	b.journalState = entry.State
	b.journalRevision = entry.Revision
	b.recordRecoveryIssueLocked("journal state %s, revision %d", entry.State, entry.Revision)

	if entry.State.committed() {
		return b.recoverCommittedLocked(ctx, entry, intent)
	}
	return b.recoverInterruptedLocked(ctx, entry)
}

func (b *Backend) recoverWithoutJournalLocked(ctx context.Context) (RecoveryReport, error) {
	observed, err := b.inspectOwnedLocked(ctx)
	if err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{Issues: []string{err.Error()}}, fmt.Errorf("inspect owned state: %w", err)
	}
	if !observed.nft.TablePresent && observed.routes.Routes == 0 && observed.routes.PolicyRules == 0 {
		b.journalState = ""
		b.journalRevision = 0
		return RecoveryReport{Action: RecoveryActionNone}, nil
	}

	if err := b.removeOrphanedOwnedLocked(ctx); err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{Issues: []string{err.Error()}}, fmt.Errorf("remove orphaned owned state: %w", err)
	}
	b.recordRecoveryIssueLocked("removed owned state without a recovery journal")
	return RecoveryReport{Action: RecoveryActionCleaned, Issues: append([]string(nil), b.recoveryIssues...)}, nil
}

func (b *Backend) recoverInterruptedLocked(
	ctx context.Context,
	entry journalEntry,
) (RecoveryReport, error) {
	interruptedState := entry.State
	observed, err := b.inspectOwnedLocked(ctx)
	if err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
			Issues: []string{err.Error()}}, fmt.Errorf("inspect staged state: %w", err)
	}

	if entry.State == JournalStateRolledBack &&
		observed.nft.ClassifyRules == 0 && observed.routes.Routes == 0 &&
		observed.routes.PolicyRules == 0 {
		if err := b.installJournalGuardLocked(ctx, entry.Guard); err != nil {
			b.recordErrorLocked(err)
			return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
				Issues: append([]string(nil), b.recoveryIssues...)}, fmt.Errorf("verify recovery guard: %w", err)
		}
		b.protectionPreserved = entry.Guard != nil && len(entry.Guard.Rules) > 0
		return RecoveryReport{
			Action:       RecoveryActionRolledBack,
			JournalState: entry.State,
			Revision:     entry.Revision,
			Issues:       append([]string(nil), b.recoveryIssues...),
		}, nil
	}

	if err := b.cleanupOwnedPolicyLocked(ctx); err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
			Issues: append([]string(nil), b.recoveryIssues...)}, fmt.Errorf("roll back interrupted intent: %w", err)
	}

	guard := entry.Guard
	if guard == nil && entry.Previous != nil {
		guard = entry.Previous.Guard
	}
	if err := b.installJournalGuardLocked(ctx, guard); err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
			Issues: append([]string(nil), b.recoveryIssues...)}, fmt.Errorf("restore recovery guard: %w", err)
	}
	b.protectionPreserved = guard != nil && len(guard.Rules) > 0

	if entry.State != JournalStateRolledBack {
		if err := b.advanceJournalLocked(&entry, JournalStateRolledBack); err != nil {
			b.recordErrorLocked(err)
			return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
				Issues: append([]string(nil), b.recoveryIssues...)}, err
		}
	}
	entry.Guard = cloneGuard(guard)
	entry.LastError = ""
	entry.Issues = append([]string(nil), b.recoveryIssues...)
	entry.UpdatedAt = nowUTC()
	if err := b.saveJournalLocked(&entry); err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
			Issues: append([]string(nil), b.recoveryIssues...)}, err
	}

	b.journalState = entry.State
	b.journalRevision = entry.Revision
	b.policyApplied = false
	b.lastPolicy = nil
	b.lastOptions = backend.PolicyOptions{}
	b.lastPlan = nil
	b.hasPolicy = false
	b.committed = nil
	b.lastError = ""
	b.recordRecoveryIssueLocked("rolled back %s intent; staged owned state removed", interruptedState)
	return RecoveryReport{
		Action:       RecoveryActionRolledBack,
		JournalState: entry.State,
		Revision:     entry.Revision,
		Issues:       append([]string(nil), b.recoveryIssues...),
	}, nil
}

func (b *Backend) recoverCommittedLocked(
	ctx context.Context,
	entry journalEntry,
	intent *RecoveryIntent,
) (RecoveryReport, error) {
	if intent == nil {
		if err := b.verifyOrRestoreGuardLocked(ctx, entry); err != nil {
			b.recordErrorLocked(err)
			return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
				Issues: append([]string(nil), b.recoveryIssues...)}, err
		}
		b.recordRecoveryIssueLocked("committed intent verified; no caller intent supplied for a full reapply")
		return RecoveryReport{
				Action:       RecoveryActionVerified,
				JournalState: entry.State,
				Revision:     entry.Revision,
				Issues:       append([]string(nil), b.recoveryIssues...),
			},
			fmt.Errorf("%w: journal revision %d", ErrRecoveryIntentRequired, entry.Revision)
	}

	if intent.Revision != 0 && entry.Revision != 0 && intent.Revision != entry.Revision {
		err := fmt.Errorf("%w: journal revision %d, intent revision %d",
			ErrRevisionMismatch, entry.Revision, intent.Revision)
		b.recordErrorLocked(err)
		return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
			Issues: []string{err.Error()}}, err
	}

	cloned := intent.clone()
	enableIPv6 := cloned.Compiled != nil && cloned.Compiled.IPv6 && b.ipv6AvailableLocked()
	plan, err := compilePolicyForWithResolver(
		cloned.Compiled, cloned.Options, b.allocations, enableIPv6, b.cgroupIDs)
	if err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{JournalState: entry.State, Revision: entry.Revision,
			Issues: []string{err.Error()}}, fmt.Errorf("compile recovery intent: %w", err)
	}
	if fingerprintPlan(plan) == entry.PolicyID {
		if err := b.verifyPlanLocked(ctx, plan); err == nil {
			b.recordRecoveryIssueLocked("committed intent already matches the kernel")
			return RecoveryReport{
				Action:       RecoveryActionVerified,
				JournalState: entry.State,
				Revision:     entry.Revision,
				Issues:       append([]string(nil), b.recoveryIssues...),
			}, nil
		}
	}

	if err := b.applyPolicyLocked(ctx, cloned.Compiled, cloned.Options); err != nil {
		b.recordErrorLocked(err)
		return RecoveryReport{JournalState: b.journalState, Revision: b.journalRevision,
			Issues: append([]string(nil), b.recoveryIssues...)}, fmt.Errorf("reapply committed intent: %w", err)
	}
	return RecoveryReport{
		Action:       RecoveryActionReapplied,
		JournalState: b.journalState,
		Revision:     b.journalRevision,
		Issues:       append([]string(nil), b.recoveryIssues...),
	}, nil
}

func (b *Backend) verifyOrRestoreGuardLocked(ctx context.Context, entry journalEntry) error {
	if entry.Guard == nil || len(entry.Guard.Rules) == 0 {
		return nil
	}
	observed, err := b.inspectOwnedLocked(ctx)
	if err != nil {
		return err
	}
	if observed.nft.TablePresent && observed.nft.KillSwitchRules >= len(entry.Guard.Rules) {
		return nil
	}
	return b.installJournalGuardLocked(ctx, entry.Guard)
}

type ownedObservation struct {
	nft    nftObservation
	routes routeObservation
}

func (b *Backend) inspectOwnedLocked(ctx context.Context) (ownedObservation, error) {
	if err := b.ensureAllocationsLocked(); err != nil {
		return ownedObservation{}, err
	}
	nftObs, err := b.nft.Inspect(ctx)
	if err != nil {
		return ownedObservation{}, err
	}
	routeObs, err := b.router.Inspect(ctx, b.allocations)
	if err != nil {
		return ownedObservation{}, err
	}
	return ownedObservation{nft: nftObs, routes: routeObs}, nil
}

func (b *Backend) removeOrphanedOwnedLocked(ctx context.Context) error {
	return b.retryLocked(ctx, func() error {
		if b.nft != nil {
			if err := b.nft.Cleanup(ctx); err != nil {
				return fmt.Errorf("cleanup owned nftables objects: %w", err)
			}
		}
		if err := b.router.Remove(ctx, b.allocations); err != nil {
			return fmt.Errorf("remove owned policy routing: %w", err)
		}
		return nil
	})
}

func (b *Backend) cleanupOwnedPolicyLocked(ctx context.Context) error {
	return b.retryLocked(ctx, func() error {
		if b.nft != nil {
			if err := b.nft.ClearPolicy(ctx); err != nil {
				return fmt.Errorf("clear owned nftables policy: %w", err)
			}
		}
		if err := b.router.Remove(ctx, b.allocations); err != nil {
			return fmt.Errorf("remove owned policy routing: %w", err)
		}
		return nil
	})
}

func (b *Backend) installJournalGuardLocked(ctx context.Context, guard *journalGuard) error {
	if guard == nil || len(guard.Rules) == 0 {
		return nil
	}
	control, rules, err := guard.toKillSwitch()
	if err != nil {
		return err
	}
	if err := b.retryLocked(ctx, func() error {
		return b.nft.ApplyKillSwitch(ctx, control, rules)
	}); err != nil {
		return err
	}
	verify := nftPolicy{
		sets:       control,
		killswitch: rules,
	}
	if err := b.retryLocked(ctx, func() error {
		return b.nft.VerifyPolicy(ctx, verify)
	}); err != nil {
		return fmt.Errorf("verify recovery guard: %w", err)
	}
	return nil
}
