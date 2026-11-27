// Package controller wires the versioned split tunnel configuration, the
// compiled policy and the platform network backend into the daemon.
//
// The controller owns the configuration revision, applies a configuration only
// after it validates and compiles, and keeps recoverable failures in status
// instead of failing the daemon. It implements the api.Backend surface so the
// local gRPC service reads and mutates the same state.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/domain"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

const (
	// DefaultConfigFileName is the split tunnel configuration file name under
	// the daemon's state directory.
	DefaultConfigFileName = "split-tunnel.json"
	defaultHistoryLimit   = 20
	// DefaultMaintenanceInterval is how often the controller reattaches a DNS
	// observer after an engine restart, sweeps expired domains and refreshes
	// application cgroups.
	DefaultMaintenanceInterval = 30 * time.Second
)

var (
	// ErrApplyFailed reports that the backend rejected a policy. The previous
	// revision stays current.
	ErrApplyFailed = errors.New("split tunnel policy apply failed")
	// ErrRevisionNotFound reports that the requested rollback revision is not
	// in the bounded history.
	ErrRevisionNotFound = errors.New("split tunnel configuration revision not found")
)

// Wiring is the runtime data a compiled policy needs from the daemon.
type Wiring struct {
	Constraints policy.Constraints
	Options     backend.PolicyOptions
	// TransportConfigured reports whether control and transport prefixes and
	// the DNS resolvers are complete. An enabled policy is refused until it is
	// true, so an incomplete wiring cannot route the daemon's own transport or
	// a private route through the wrong path.
	TransportConfigured bool
	// Missing explains why TransportConfigured is false.
	Missing []string
}

// RuntimeProvider returns the current runtime wiring. The provider may return
// an error when the network engine is not ready; in that case the controller
// keeps the configuration but does not apply it.
type RuntimeProvider func(ctx context.Context) (Wiring, error)

// ApplicationProvider discovers applications and reconciles their cgroup
// scopes. Reconcile must return every scope the backend should match for the
// compiled policy.
type ApplicationProvider interface {
	Reconcile(ctx context.Context, compiled *policy.CompiledPolicy) ([]backend.ApplicationScope, error)
	List() []application.Application
	Close() error
}

// DNSRuntime is the live DNS surface the controller observes. The pointer may
// change when the engine restarts its DNS server, so the maintenance loop
// re-reads the provider and reattaches the tracker.
type DNSRuntime interface {
	SetResponseObserver(observer dns.ResponseObserver)
	ResolverPrefixes() []netip.Prefix
}

// DNSProvider returns the current DNS runtime, or nil when none is running.
type DNSProvider func(ctx context.Context) (DNSRuntime, error)

// LinkReconciler watches link, address, route and gateway changes.
type LinkReconciler interface {
	Start(ctx context.Context) error
	Stop()
}

// PolicyReapplier re-applies the last successfully applied policy.
type PolicyReapplier interface {
	Reapply(ctx context.Context) error
}

// RecoveryReport describes what startup reconciliation did.
type RecoveryReport struct {
	Action              string
	JournalState        string
	Revision            uint64
	Issues              []string
	ProtectionPreserved bool
	RollbackFailed      bool
	LastError           string
}

// Backend is the platform network backend the controller owns.
type Backend interface {
	Initialize(ctx context.Context) error
	Recover(ctx context.Context) (RecoveryReport, error)
	ApplyPolicy(ctx context.Context, compiled *policy.CompiledPolicy, options backend.PolicyOptions) error
	InstallProtection(ctx context.Context, compiled *policy.CompiledPolicy, options backend.PolicyOptions) error
	UpdateDomainSets(ctx context.Context, updates []backend.DomainSetUpdate) error
	Rollback(ctx context.Context) error
	GetStatus(ctx context.Context) (backend.Status, error)
	EmergencyReset(ctx context.Context) error
	Close(ctx context.Context) error
}

// Options configures a Controller.
type Options struct {
	// Backend applies compiled policy. A nil backend leaves mutations
	// unavailable while status and configuration reads keep working.
	Backend Backend
	// Runtime supplies route targets and constraints. Nil uses an empty
	// wiring, which is enough for disabled policies only.
	Runtime RuntimeProvider
	// Applications supplies the live cgroup scopes for application rules. Nil
	// makes a policy that uses applications fail closed.
	Applications ApplicationProvider
	// DNS supplies the live DNS server used for domain tracking.
	DNS DNSProvider
	// LinkReconciler watches kernel routing changes. Nil uses the platform
	// reconciler on Linux and disables reapply elsewhere.
	LinkReconciler LinkReconciler
	// HistoryLimit bounds retained configurations available for rollback.
	HistoryLimit int
	// MaintenanceInterval controls the DNS/app/domain maintenance loop.
	MaintenanceInterval time.Duration
}

var _ api.Backend = (*Controller)(nil)

// Controller owns the split tunnel runtime state.
type Controller struct {
	mu sync.Mutex

	store        *store
	backend      Backend
	runtime      RuntimeProvider
	applications ApplicationProvider
	dnsProvider  DNSProvider
	reconciler   LinkReconciler

	historyLimit        int
	maintenanceInterval time.Duration

	loaded             bool
	loadErr            error
	config             *config.Config
	revision           uint64
	backendInitialized bool
	recoveryErr        error
	applied            bool
	pendingApply       bool
	stopped            bool
	compiled           *policy.CompiledPolicy
	appliedOptions     backend.PolicyOptions
	appScopes          []backend.ApplicationScope
	protectionArmed    bool
	diagnostics        map[string]string

	tracker    *domain.Tracker
	dnsRuntime DNSRuntime

	runCtx    context.Context
	runCancel context.CancelFunc
	runDone   chan struct{}
}

// New returns a controller backed by path. The path is injected so tests can
// use a temporary store and the daemon can keep it under its state directory.
func New(path string, opts Options) *Controller {
	historyLimit := opts.HistoryLimit
	if historyLimit <= 0 {
		historyLimit = defaultHistoryLimit
	}
	interval := opts.MaintenanceInterval
	if interval <= 0 {
		interval = DefaultMaintenanceInterval
	}
	return &Controller{
		store:               newStore(path),
		backend:             opts.Backend,
		runtime:             opts.Runtime,
		applications:        opts.Applications,
		dnsProvider:         opts.DNS,
		reconciler:          opts.LinkReconciler,
		historyLimit:        historyLimit,
		maintenanceInterval: interval,
		diagnostics:         make(map[string]string),
	}
}

// Start loads the persisted configuration, initializes the backend and
// recovers a previous run before applying managed traffic. Recovery runs even
// when the configuration is missing or corrupt so stale owned kernel state is
// not left behind. Failures are recorded in status so the rest of the daemon
// can keep serving.
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return errors.New("split tunnel controller is stopped")
	}
	if c.loaded {
		return nil
	}

	loadErr := c.loadLocked()
	if c.config == nil {
		c.setDiagnosticLocked("config", "missing")
	} else {
		c.setDiagnosticLocked("config", "loaded")
	}

	var startErr error
	if c.backend == nil {
		if c.config != nil && c.config.SplitTunnel.Enabled {
			c.setDiagnosticLocked("backend", "unavailable")
			startErr = api.ErrBackendUnavailable
		}
	} else if err := c.ensureBackendLocked(ctx); err != nil {
		startErr = err
	} else {
		c.startReconcilerLocked(ctx)
	}

	if loadErr != nil {
		startErr = errors.Join(loadErr, startErr)
	}

	if c.backend != nil && c.backendInitialized && c.recoveryErr == nil && loadErr == nil && c.config != nil {
		if !c.config.SplitTunnel.Enabled {
			c.applyDisabledLocked(ctx)
		} else if err := c.applyCurrentConfigLocked(ctx); err != nil {
			c.pendingApply = true
			startErr = errors.Join(startErr, err)
		}
	}

	c.startMaintenanceLocked(ctx)
	return startErr
}

// Stop performs an emergency reset so an explicit daemon shutdown does not
// leave split tunnel policy or protection behind. It stops the reconciler,
// detaches the DNS observer and removes application scopes before resetting
// the backend.
func (c *Controller) Stop(ctx context.Context) error {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return nil
	}
	c.stopped = true
	c.applied = false
	cancel := c.runCancel
	done := c.runDone
	reconciler := c.reconciler
	c.reconciler = nil
	c.runCancel = nil
	c.runDone = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	if reconciler != nil {
		reconciler.Stop()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.detachTrackerLocked()
	if err := c.closeApplicationsLocked(); err != nil {
		c.setDiagnosticLocked("applications.error", err.Error())
	}
	if c.backend == nil || !c.backendInitialized {
		return nil
	}

	var merr error
	if err := c.backend.EmergencyReset(ctx); err != nil {
		merr = errors.Join(merr, fmt.Errorf("reset split tunnel policy: %w", err))
	}
	if err := c.backend.Close(ctx); err != nil {
		merr = errors.Join(merr, fmt.Errorf("close split tunnel backend: %w", err))
	}
	return merr
}

// Config returns the current configuration and revision.
func (c *Controller) Config(context.Context) (*config.Config, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.loaded {
		if err := c.loadLocked(); err != nil {
			return nil, 0, err
		}
	}
	if c.loadErr != nil {
		return nil, 0, c.loadErr
	}
	return c.config, c.revision, nil
}

// ApplyConfig validates and applies cfg when expectedRevision is current, then
// persists it as the next revision. A backend or persistence failure leaves the
// previous revision in place.
func (c *Controller) ApplyConfig(ctx context.Context, cfg *config.Config, expectedRevision uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.readyForMutationLocked(); err != nil {
		return 0, err
	}
	if err := cfg.Validate(); err != nil {
		return 0, err
	}
	if c.revision != expectedRevision {
		return 0, api.ErrRevisionConflict
	}
	c.pendingApply = false
	return c.applyAndPersistLocked(ctx, cfg, c.revision+1)
}

// RollbackConfig restores a previous configuration as a new revision.
func (c *Controller) RollbackConfig(ctx context.Context, revision, expectedRevision uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.readyForMutationLocked(); err != nil {
		return 0, err
	}
	if c.revision != expectedRevision {
		return 0, api.ErrRevisionConflict
	}
	c.pendingApply = false

	target, ok := c.historyConfigLocked(revision)
	if !ok {
		if revision == c.revision {
			target = c.config
		} else {
			return 0, fmt.Errorf("%w: %d", ErrRevisionNotFound, revision)
		}
	}
	if target == nil {
		return 0, ErrRevisionNotFound
	}
	return c.applyAndPersistLocked(ctx, target, c.revision+1)
}

// Reapply recompiles and reapplies the current committed policy after a
// network change. It refreshes route targets, constraints and application
// scopes but does not persist a new revision. A failure is reported to the
// caller and in status; the daemon keeps running.
func (c *Controller) Reapply(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return nil
	}
	if !c.applied || c.config == nil || !c.config.SplitTunnel.Enabled {
		return nil
	}
	if err := c.ensureBackendLocked(ctx); err != nil {
		return err
	}

	wiring, err := c.wiringLocked(ctx)
	if err != nil {
		c.setDiagnosticLocked("runtime", "unavailable")
		c.setDiagnosticLocked("runtime.error", err.Error())
		return err
	}
	compiled, err := c.compileLocked(c.config, wiring)
	if err != nil {
		c.recordApplyErrorLocked(err)
		return err
	}
	scopes, err := c.reconcileApplicationsLocked(ctx, compiled)
	if err != nil {
		c.recordApplyErrorLocked(err)
		return err
	}
	wiring.Options.Applications = scopes

	if err := c.preArmLocked(ctx, compiled, wiring.Options); err != nil {
		c.recordApplyErrorLocked(err)
		return err
	}
	if err := c.backend.ApplyPolicy(ctx, compiled, wiring.Options); err != nil {
		c.recordApplyErrorLocked(err)
		return err
	}

	c.compiled = compiled
	c.appliedOptions = wiring.Options
	c.appScopes = scopes
	c.protectionArmed = compiled.KillSwitch != config.KillSwitchDisabled && compiled.KillSwitch != ""
	c.clearDiagnosticLocked("apply.error")
	c.setDiagnosticLocked("apply", "reapplied")
	return nil
}

// Status returns the current engine status. Configuration and backend failures
// are reported as diagnostics rather than as an error.
func (c *Controller) Status(ctx context.Context) (api.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.loaded {
		_ = c.loadLocked()
	}

	status := api.Status{
		Revision:    c.revision,
		Mode:        config.ModeStandard,
		Backend:     c.backendNameLocked(),
		Diagnostics: cloneDiagnostics(c.diagnostics),
	}
	if c.config != nil {
		status.Enabled = c.config.SplitTunnel.Enabled
		status.Mode = c.config.SplitTunnel.Mode
		status.Running = c.config.SplitTunnel.Enabled && c.applied
	}
	if c.loadErr != nil {
		status.Diagnostics["config"] = "invalid"
		status.Diagnostics["config.error"] = c.loadErr.Error()
	}
	if c.applications != nil && c.applied {
		status.Diagnostics["applications.count"] = fmt.Sprintf("%d", len(c.applications.List()))
	}
	if c.tracker != nil {
		diagnostics := c.tracker.Diagnostics()
		status.Diagnostics["domain.references"] = fmt.Sprintf("%d", diagnostics.References)
		status.Diagnostics["domain.addresses"] = fmt.Sprintf("%d", diagnostics.Addresses)
		status.Diagnostics["domain.conflicts"] = fmt.Sprintf("%d", len(diagnostics.Conflicts))
	}
	if c.reconciler != nil {
		if lastErr := reconcilerLastError(c.reconciler); lastErr != "" {
			status.Diagnostics["reconcile.error"] = lastErr
		}
	}
	if c.backendInitialized {
		backendStatus, err := c.backend.GetStatus(ctx)
		if err != nil {
			status.Diagnostics["backend.error"] = err.Error()
		} else {
			status.Diagnostics["backend.state"] = string(backendStatus.State)
			if backendStatus.LastError != "" {
				status.Diagnostics["backend.last_error"] = backendStatus.LastError
			}
		}
	}
	return status, nil
}

// Applications reports the discovered application registry.
func (c *Controller) Applications(context.Context) ([]application.Application, error) {
	c.mu.Lock()
	provider := c.applications
	c.mu.Unlock()
	if provider == nil {
		return nil, api.ErrNotImplemented
	}
	return provider.List(), nil
}

// Rules reports the applied rule set and the structural conflicts the compiler
// found.
func (c *Controller) Rules(context.Context) (api.Rules, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.config == nil {
		return api.Rules{}, api.ErrNotImplemented
	}
	rules := api.Rules{
		Revision: c.revision,
		Rules:    append([]config.Rule(nil), c.config.SplitTunnel.Rules...),
	}
	if c.compiled != nil {
		for _, conflict := range c.compiled.Conflicts {
			rules.Conflicts = append(rules.Conflicts, conflict.Detail)
		}
	}
	return rules, nil
}

// Trace evaluates a packet against the applied policy.
func (c *Controller) Trace(_ context.Context, query api.TraceQuery) (api.TraceResult, error) {
	c.mu.Lock()
	compiled := c.compiled
	c.mu.Unlock()

	if compiled == nil {
		return api.TraceResult{}, api.ErrNotImplemented
	}
	decision := compiled.Evaluate(policy.Flow{
		Destination: query.DestinationIP,
		Protocol:    config.Protocol(strings.ToLower(query.Protocol)),
		Port:        query.DestinationPort,
		UID:         query.UID,
	})
	return api.TraceResult{
		FinalAction: decision.Action,
		Stages:      traceStages(decision),
	}, nil
}

func traceStages(decision policy.Decision) []api.TraceStage {
	stages := make([]api.TraceStage, 0, len(decision.Trace))
	for _, entry := range decision.Trace {
		stages = append(stages, api.TraceStage{
			Name:    string(entry.Layer),
			Message: entry.Detail,
			Allowed: entry.Action != config.ActionBlock,
		})
	}
	return stages
}

func reconcilerLastError(reconciler LinkReconciler) string {
	if reporter, ok := reconciler.(interface{ LastError() string }); ok {
		return reporter.LastError()
	}
	return ""
}

func (c *Controller) loadLocked() error {
	c.loaded = true
	doc, err := c.store.load()
	if err != nil {
		c.loadErr = err
		c.setDiagnosticLocked("config", "invalid")
		return fmt.Errorf("load split tunnel config: %w", err)
	}
	c.loadErr = nil
	c.config = doc.Config
	c.revision = doc.Revision
	return nil
}

func (c *Controller) ensureBackendLocked(ctx context.Context) error {
	if c.backend == nil {
		c.setDiagnosticLocked("backend", "unavailable")
		return api.ErrBackendUnavailable
	}
	if c.backendInitialized {
		if c.recoveryErr == nil {
			return nil
		}
	} else {
		if err := c.backend.Initialize(ctx); err != nil {
			c.setDiagnosticLocked("backend", "initialize_failed")
			c.setDiagnosticLocked("backend.error", err.Error())
			return fmt.Errorf("initialize split tunnel backend: %w", err)
		}
		c.backendInitialized = true
		c.setDiagnosticLocked("backend", "ready")
	}

	report, err := c.backend.Recover(ctx)
	if err != nil {
		c.recoveryErr = err
		c.setDiagnosticLocked("recovery", "failed")
		c.setDiagnosticLocked("recovery.error", err.Error())
		return fmt.Errorf("recover split tunnel state: %w", err)
	}
	c.recoveryErr = nil
	c.clearDiagnosticLocked("recovery.error")
	c.clearDiagnosticLocked("recovery.issues")
	c.clearDiagnosticLocked("recovery.protection_preserved")
	c.clearDiagnosticLocked("recovery.rollback_failed")
	c.clearDiagnosticLocked("recovery.last_error")
	action := report.Action
	if action == "" {
		action = "none"
	}
	c.setDiagnosticLocked("recovery", action)
	if report.JournalState != "" {
		c.setDiagnosticLocked("recovery.journal", report.JournalState)
	}
	if len(report.Issues) > 0 {
		c.setDiagnosticLocked("recovery.issues", strings.Join(report.Issues, "; "))
	}
	if report.ProtectionPreserved {
		c.setDiagnosticLocked("recovery.protection_preserved", "true")
	}
	if report.RollbackFailed {
		c.setDiagnosticLocked("recovery.rollback_failed", "true")
	}
	if report.LastError != "" {
		c.setDiagnosticLocked("recovery.last_error", report.LastError)
	}
	return nil
}

func (c *Controller) startReconcilerLocked(ctx context.Context) {
	if c.reconciler == nil {
		c.reconciler = newPlatformReconciler(c)
	}
	if c.reconciler == nil {
		return
	}
	if err := c.reconciler.Start(ctx); err != nil {
		c.setDiagnosticLocked("reconcile", "start_failed")
		c.setDiagnosticLocked("reconcile.error", err.Error())
		return
	}
	c.setDiagnosticLocked("reconcile", "running")
}

func (c *Controller) startMaintenanceLocked(ctx context.Context) {
	if c.runCancel != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.runCtx = runCtx
	c.runCancel = cancel
	c.runDone = done
	go c.maintenanceLoop(runCtx, done)
}

func (c *Controller) maintenanceLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(c.maintenanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.maintain(ctx)
		}
	}
}

func (c *Controller) maintain(ctx context.Context) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	if c.pendingApply && c.config != nil && c.config.SplitTunnel.Enabled && !c.applied {
		if err := c.applyCurrentConfigLocked(ctx); err != nil {
			log.Debugf("retry pending split tunnel policy: %v", err)
		}
	}
	if !c.applied || c.config == nil || !c.config.SplitTunnel.Enabled {
		c.mu.Unlock()
		return
	}
	tracker := c.tracker
	compiled := c.compiled
	provider := c.applications
	dnsProvider := c.dnsProvider
	c.mu.Unlock()

	if tracker != nil {
		if err := tracker.Sweep(); err != nil {
			c.setRuntimeDiagnostic("domain.error", err.Error())
		}
	}
	if dnsProvider != nil && tracker != nil {
		runtime, err := dnsProvider(ctx)
		if err != nil {
			c.setRuntimeDiagnostic("dns.error", err.Error())
		} else if runtime != nil {
			c.reattachDNS(tracker, runtime)
		}
	}
	if provider != nil && compiled != nil && compiled.UsesApplications() {
		scopes, err := provider.Reconcile(ctx, compiled)
		if err != nil {
			c.setRuntimeDiagnostic("applications.error", err.Error())
			return
		}
		if !scopesEqual(scopes, c.appScopeSnapshot()) {
			if err := c.Reapply(ctx); err != nil {
				log.Debugf("reapply split tunnel after application change: %v", err)
			}
		}
	}
}

func (c *Controller) reattachDNS(tracker *domain.Tracker, runtime DNSRuntime) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped || c.tracker != tracker || sameDNSRuntime(c.dnsRuntime, runtime) {
		return
	}
	if c.dnsRuntime != nil {
		c.dnsRuntime.SetResponseObserver(nil)
	}
	c.dnsRuntime = runtime
	runtime.SetResponseObserver(tracker)
	c.clearDiagnosticLocked("dns.error")
}

func (c *Controller) appScopeSnapshot() []backend.ApplicationScope {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]backend.ApplicationScope(nil), c.appScopes...)
}

func (c *Controller) setRuntimeDiagnostic(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setDiagnosticLocked(key, value)
}

func (c *Controller) applyCurrentConfigLocked(ctx context.Context) error {
	wiring, err := c.wiringLocked(ctx)
	if err != nil {
		c.setDiagnosticLocked("runtime", "unavailable")
		c.setDiagnosticLocked("runtime.error", err.Error())
		return err
	}
	compiled, err := c.compileLocked(c.config, wiring)
	if err != nil {
		c.setDiagnosticLocked("apply", "invalid")
		c.setDiagnosticLocked("apply.error", err.Error())
		return err
	}

	scopes, tracker, dnsRuntime, err := c.preparePolicyLocked(ctx, compiled, &wiring)
	if err != nil {
		c.recordApplyErrorLocked(err)
		return err
	}
	if err := c.preArmLocked(ctx, compiled, wiring.Options); err != nil {
		closeTracker(tracker)
		c.recordApplyErrorLocked(err)
		return err
	}
	if err := c.backend.ApplyPolicy(ctx, compiled, wiring.Options); err != nil {
		closeTracker(tracker)
		c.recordApplyErrorLocked(err)
		return fmt.Errorf("apply split tunnel policy: %w", err)
	}

	c.applied = true
	c.pendingApply = false
	c.compiled = compiled
	c.appliedOptions = wiring.Options
	c.appScopes = scopes
	c.protectionArmed = protectionEnabled(compiled)
	c.installTrackerLocked(tracker, dnsRuntime)
	c.clearDiagnosticLocked("apply.error")
	c.setDiagnosticLocked("apply", "applied")
	return nil
}

func (c *Controller) applyDisabledLocked(ctx context.Context) {
	compiled, err := policy.CompileWith(c.config, policy.Constraints{})
	if err != nil {
		c.setDiagnosticLocked("apply", "invalid")
		c.setDiagnosticLocked("apply.error", err.Error())
		return
	}
	if c.applications != nil {
		if _, err := c.applications.Reconcile(ctx, compiled); err != nil {
			c.setDiagnosticLocked("applications.error", err.Error())
		}
	}
	if err := c.backend.ApplyPolicy(ctx, compiled, backend.PolicyOptions{}); err != nil {
		c.recordApplyErrorLocked(err)
		return
	}
	c.applied = false
	c.pendingApply = false
	c.compiled = compiled
	c.appliedOptions = backend.PolicyOptions{}
	c.appScopes = nil
	c.protectionArmed = false
	c.detachTrackerLocked()
	c.clearDiagnosticLocked("apply.error")
	c.setDiagnosticLocked("apply", "disabled")
}

func (c *Controller) readyForMutationLocked() error {
	if c.stopped {
		return errors.New("split tunnel controller is stopped")
	}
	if !c.loaded {
		if err := c.loadLocked(); err != nil {
			return err
		}
	}
	if c.loadErr != nil {
		return c.loadErr
	}
	if c.backend == nil {
		return api.ErrBackendUnavailable
	}
	return nil
}

func (c *Controller) applyAndPersistLocked(ctx context.Context, cfg *config.Config, revision uint64) (uint64, error) {
	if err := c.ensureBackendLocked(ctx); err != nil {
		return 0, err
	}

	wiring, err := c.wiringForLocked(ctx, cfg)
	if err != nil {
		return 0, err
	}
	compiled, err := c.compileLocked(cfg, wiring)
	if err != nil {
		return 0, err
	}

	scopes, tracker, dnsRuntime, err := c.preparePolicyLocked(ctx, compiled, &wiring)
	if err != nil {
		c.recordApplyErrorLocked(err)
		return 0, fmt.Errorf("%w: %w", ErrApplyFailed, err)
	}

	previousConfig := c.config
	if err := c.preArmLocked(ctx, compiled, wiring.Options); err != nil {
		closeTracker(tracker)
		c.recordApplyErrorLocked(err)
		return 0, fmt.Errorf("%w: %w", ErrApplyFailed, err)
	}
	if err := c.backend.ApplyPolicy(ctx, compiled, wiring.Options); err != nil {
		closeTracker(tracker)
		c.recordApplyErrorLocked(err)
		return 0, fmt.Errorf("%w: %w", ErrApplyFailed, err)
	}

	doc := document{
		SchemaVersion: storeSchemaVersion,
		Revision:      revision,
		Config:        cfg,
		History:       c.historyLocked(previousConfig),
	}
	if err := c.store.save(doc); err != nil {
		c.restorePreviousLocked(ctx, previousConfig)
		closeTracker(tracker)
		c.recordApplyErrorLocked(err)
		return 0, fmt.Errorf("persist split tunnel config: %w", err)
	}

	c.config = cfg
	c.revision = revision
	c.applied = cfg.SplitTunnel.Enabled
	c.compiled = compiled
	c.appliedOptions = wiring.Options
	c.appScopes = scopes
	c.protectionArmed = protectionEnabled(compiled)
	if cfg.SplitTunnel.Enabled {
		c.installTrackerLocked(tracker, dnsRuntime)
	} else {
		closeTracker(tracker)
		c.detachTrackerLocked()
	}
	c.clearDiagnosticLocked("apply.error")
	c.setDiagnosticLocked("apply", "applied")
	return revision, nil
}

// preparePolicyLocked reconciles application scopes and builds the domain
// tracker for a policy. Neither has a kernel side effect beyond the classifier
// scopes; the tracker is attached only after the backend accepts the policy.
func (c *Controller) preparePolicyLocked(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	wiring *Wiring,
) ([]backend.ApplicationScope, *domain.Tracker, DNSRuntime, error) {
	scopes, err := c.reconcileApplicationsLocked(ctx, compiled)
	if err != nil {
		return nil, nil, nil, err
	}
	wiring.Options.Applications = scopes

	if !compiled.UsesDomains() {
		return scopes, nil, nil, nil
	}
	if c.dnsProvider == nil {
		return nil, nil, nil, errors.New("split tunnel domain rules require DNS observation")
	}
	runtime, err := c.dnsProvider(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read DNS runtime: %w", err)
	}
	if runtime == nil {
		return nil, nil, nil, errors.New("split tunnel domain rules require a running DNS server")
	}
	wiring.Options.DNSResolvers = runtime.ResolverPrefixes()

	tracker, err := domain.NewTrackerForPolicy(c.backend, compiled, domain.Options{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile domain tracking: %w", err)
	}
	return scopes, tracker, runtime, nil
}

func (c *Controller) reconcileApplicationsLocked(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
) ([]backend.ApplicationScope, error) {
	if compiled.UsesApplications() {
		if c.applications == nil {
			return nil, errors.New("split tunnel application rules require a classifier")
		}
		return c.applications.Reconcile(ctx, compiled)
	}
	if c.applications != nil {
		// Clear scopes left by a previous application policy. A cleanup failure
		// is not fatal: the backend no longer references those rules.
		if _, err := c.applications.Reconcile(ctx, compiled); err != nil {
			log.Debugf("clean up split tunnel application scopes: %v", err)
		}
	}
	return nil, nil
}

func (c *Controller) preArmLocked(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
) error {
	if !protectionEnabled(compiled) {
		c.protectionArmed = false
		return nil
	}
	if err := c.backend.InstallProtection(ctx, compiled, options); err != nil {
		c.protectionArmed = false
		c.setDiagnosticLocked("protection", "failed")
		c.setDiagnosticLocked("protection.error", err.Error())
		return fmt.Errorf("pre-arm split tunnel kill switch: %w", err)
	}
	c.protectionArmed = true
	c.clearDiagnosticLocked("protection.error")
	c.setDiagnosticLocked("protection", "armed")
	return nil
}

func protectionEnabled(compiled *policy.CompiledPolicy) bool {
	return compiled != nil && compiled.Enabled && compiled.KillSwitch != config.KillSwitchDisabled && compiled.KillSwitch != ""
}

func closeTracker(tracker *domain.Tracker) {
	if tracker != nil {
		tracker.Close()
	}
}

func (c *Controller) installTrackerLocked(tracker *domain.Tracker, runtime DNSRuntime) {
	if tracker == nil || runtime == nil {
		c.detachTrackerLocked()
		return
	}
	if c.dnsRuntime != nil && !sameDNSRuntime(c.dnsRuntime, runtime) {
		c.dnsRuntime.SetResponseObserver(nil)
	}
	oldTracker := c.tracker
	c.tracker = tracker
	c.dnsRuntime = runtime
	runtime.SetResponseObserver(tracker)
	if oldTracker != nil && oldTracker != tracker {
		oldTracker.Close()
	}
}

func (c *Controller) detachTrackerLocked() {
	if c.dnsRuntime != nil {
		c.dnsRuntime.SetResponseObserver(nil)
	}
	if c.tracker != nil {
		c.tracker.Close()
	}
	c.tracker = nil
	c.dnsRuntime = nil
}

func (c *Controller) closeApplicationsLocked() error {
	if c.applications == nil {
		return nil
	}
	err := c.applications.Close()
	c.applications = nil
	c.appScopes = nil
	return err
}

func (c *Controller) restorePreviousLocked(ctx context.Context, previous *config.Config) {
	if previous == nil {
		if err := c.backend.Rollback(ctx); err != nil {
			c.setDiagnosticLocked("rollback.error", err.Error())
		}
		return
	}
	wiring, err := c.wiringForLocked(ctx, previous)
	if err != nil {
		c.rollbackLocked(ctx)
		return
	}
	compiled, err := c.compileLocked(previous, wiring)
	if err != nil {
		c.rollbackLocked(ctx)
		return
	}
	scopes, tracker, dnsRuntime, err := c.preparePolicyLocked(ctx, compiled, &wiring)
	if err != nil {
		c.rollbackLocked(ctx)
		return
	}
	if err := c.backend.ApplyPolicy(ctx, compiled, wiring.Options); err != nil {
		closeTracker(tracker)
		c.setDiagnosticLocked("rollback.error", err.Error())
		return
	}
	c.compiled = compiled
	c.appliedOptions = wiring.Options
	c.appScopes = scopes
	if previous.SplitTunnel.Enabled {
		c.installTrackerLocked(tracker, dnsRuntime)
	} else {
		closeTracker(tracker)
		c.detachTrackerLocked()
	}
}

func (c *Controller) rollbackLocked(ctx context.Context) {
	if err := c.backend.Rollback(ctx); err != nil {
		c.setDiagnosticLocked("rollback.error", err.Error())
	}
}

func (c *Controller) wiringForLocked(ctx context.Context, cfg *config.Config) (Wiring, error) {
	// A disabled policy only clears kernel state, so it must not depend on a
	// network engine that may be down when the caller disables split tunneling.
	if cfg == nil || !cfg.SplitTunnel.Enabled {
		return Wiring{}, nil
	}
	return c.wiringLocked(ctx)
}

func (c *Controller) wiringLocked(ctx context.Context) (Wiring, error) {
	if c.runtime == nil {
		return Wiring{}, nil
	}
	wiring, err := c.runtime(ctx)
	if err != nil {
		return Wiring{}, err
	}
	c.clearDiagnosticLocked("runtime.error")
	c.clearDiagnosticLocked("runtime")
	if !wiring.TransportConfigured {
		c.setDiagnosticLocked("runtime.transport", "incomplete")
		if len(wiring.Missing) > 0 {
			c.setDiagnosticLocked("runtime.missing", strings.Join(wiring.Missing, "; "))
		}
	} else {
		c.clearDiagnosticLocked("runtime.transport")
		c.clearDiagnosticLocked("runtime.missing")
	}
	return wiring, nil
}

func (c *Controller) compileLocked(cfg *config.Config, wiring Wiring) (*policy.CompiledPolicy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	killSwitch := cfg.SplitTunnel.KillSwitch
	if killSwitch == "" {
		killSwitch = config.KillSwitchDisabled
	}
	if cfg.SplitTunnel.Enabled &&
		(killSwitch == config.KillSwitchGlobal || killSwitch == config.KillSwitchStrict) &&
		!wiring.TransportConfigured {
		return nil, &config.FieldError{
			Path: "splitTunnel.killSwitch",
			Err: fmt.Errorf("%s mode requires control and transport wiring that is not configured",
				killSwitch),
		}
	}
	if cfg.SplitTunnel.Enabled && !wiring.TransportConfigured {
		return nil, &config.FieldError{
			Path: "splitTunnel",
			Err:  errors.New("control, transport and private route wiring is incomplete"),
		}
	}
	compiled, err := policy.CompileWith(cfg, wiring.Constraints)
	if err != nil {
		return nil, err
	}
	return compiled, nil
}

func (c *Controller) historyConfigLocked(revision uint64) (*config.Config, bool) {
	if c.config == nil {
		return nil, false
	}
	doc, err := c.store.load()
	if err != nil {
		return nil, false
	}
	for _, item := range doc.History {
		if item.Revision == revision {
			return item.Config, true
		}
	}
	return nil, false
}

func (c *Controller) historyLocked(previous *config.Config) []historyEntry {
	if previous == nil {
		return nil
	}
	doc, err := c.store.load()
	if err != nil {
		return nil
	}
	history := doc.History
	if len(history) >= c.historyLimit {
		history = append([]historyEntry(nil), history[len(history)-c.historyLimit+1:]...)
	}
	return append(history, historyEntry{Revision: c.revision, Config: previous})
}

func (c *Controller) recordApplyErrorLocked(err error) {
	c.setDiagnosticLocked("apply", "failed")
	c.setDiagnosticLocked("apply.error", err.Error())
}

func (c *Controller) backendNameLocked() string {
	if c.backend == nil {
		return "unavailable"
	}
	return backendName()
}

func (c *Controller) setDiagnosticLocked(key, value string) {
	c.diagnostics[key] = value
}

func (c *Controller) clearDiagnosticLocked(key string) {
	delete(c.diagnostics, key)
}

func cloneDiagnostics(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(in))
	for _, key := range keys {
		out[key] = in[key]
	}
	return out
}

func scopesEqual(left, right []backend.ApplicationScope) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sameDNSRuntime(left, right DNSRuntime) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Kind() != reflect.Ptr || rightValue.Kind() != reflect.Ptr {
		return false
	}
	return leftValue.Pointer() == rightValue.Pointer()
}
