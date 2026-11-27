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
	"sort"
	"sync"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

const (
	// DefaultConfigFileName is the split tunnel configuration file name under
	// the daemon's state directory.
	DefaultConfigFileName = "split-tunnel.json"
	defaultHistoryLimit   = 20
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
	// the DNS resolvers are complete. Global and strict kill switches are
	// refused until it is true, so an incomplete wiring cannot silently block
	// the daemon's own transport.
	TransportConfigured bool
}

// RuntimeProvider returns the current runtime wiring. The provider may return
// an error when the network engine is not ready; in that case the controller
// keeps the configuration but does not apply it.
type RuntimeProvider func(ctx context.Context) (Wiring, error)

// RecoveryReport describes what startup reconciliation did.
type RecoveryReport struct {
	Action       string
	JournalState string
	Revision     uint64
	Issues       []string
}

// Backend is the platform network backend the controller owns.
type Backend interface {
	Initialize(ctx context.Context) error
	Recover(ctx context.Context) (RecoveryReport, error)
	ApplyPolicy(ctx context.Context, compiled *policy.CompiledPolicy, options backend.PolicyOptions) error
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
	// HistoryLimit bounds retained configurations available for rollback.
	HistoryLimit int
}

var _ api.Backend = (*Controller)(nil)

// Controller owns the split tunnel runtime state.
type Controller struct {
	mu sync.Mutex

	store        *store
	backend      Backend
	runtime      RuntimeProvider
	historyLimit int

	loaded             bool
	loadErr            error
	config             *config.Config
	revision           uint64
	backendInitialized bool
	applied            bool
	stopped            bool
	diagnostics        map[string]string
}

// New returns a controller backed by path. The path is injected so tests can
// use a temporary store and the daemon can keep it under its state directory.
func New(path string, opts Options) *Controller {
	historyLimit := opts.HistoryLimit
	if historyLimit <= 0 {
		historyLimit = defaultHistoryLimit
	}
	return &Controller{
		store:        newStore(path),
		backend:      opts.Backend,
		runtime:      opts.Runtime,
		historyLimit: historyLimit,
		diagnostics:  make(map[string]string),
	}
}

// Start loads the persisted configuration, initializes the backend and
// recovers a previous run before applying managed traffic. A missing
// configuration is not an error. Failures are recorded in status so the rest
// of the daemon can keep serving.
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return errors.New("split tunnel controller is stopped")
	}
	if c.loaded {
		return nil
	}

	if err := c.loadLocked(); err != nil {
		return err
	}
	if c.config == nil {
		c.setDiagnosticLocked("config", "missing")
		return nil
	}
	c.setDiagnosticLocked("config", "loaded")

	if !c.config.SplitTunnel.Enabled {
		if err := c.ensureBackendLocked(ctx); err != nil {
			return err
		}
		c.applyDisabledLocked(ctx)
		return nil
	}

	if err := c.ensureBackendLocked(ctx); err != nil {
		return err
	}

	wiring, err := c.wiringLocked(ctx)
	if err != nil {
		c.setDiagnosticLocked("runtime", "unavailable")
		c.setDiagnosticLocked("runtime.error", err.Error())
		return nil
	}
	compiled, err := c.compileLocked(c.config, wiring)
	if err != nil {
		c.setDiagnosticLocked("apply", "invalid")
		c.setDiagnosticLocked("apply.error", err.Error())
		return nil
	}
	if err := c.backend.ApplyPolicy(ctx, compiled, wiring.Options); err != nil {
		c.recordApplyErrorLocked(err)
		return fmt.Errorf("apply split tunnel policy: %w", err)
	}
	c.applied = true
	c.clearDiagnosticLocked("apply.error")
	c.setDiagnosticLocked("apply", "applied")
	return nil
}

// Stop performs an emergency reset so an explicit daemon shutdown does not
// leave split tunnel policy or protection behind.
func (c *Controller) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return nil
	}
	c.stopped = true
	c.applied = false
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

// Applications reports that application discovery is not part of this runtime
// slice.
func (c *Controller) Applications(context.Context) ([]application.Application, error) {
	return nil, api.ErrNotImplemented
}

// Rules reports that rule inspection is not part of this runtime slice.
func (c *Controller) Rules(context.Context) (api.Rules, error) {
	return api.Rules{}, api.ErrNotImplemented
}

// Trace reports that packet tracing is not part of this runtime slice.
func (c *Controller) Trace(context.Context, api.TraceQuery) (api.TraceResult, error) {
	return api.TraceResult{}, api.ErrNotImplemented
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
		return nil
	}
	if err := c.backend.Initialize(ctx); err != nil {
		c.setDiagnosticLocked("backend", "initialize_failed")
		c.setDiagnosticLocked("backend.error", err.Error())
		return fmt.Errorf("initialize split tunnel backend: %w", err)
	}
	c.backendInitialized = true
	c.setDiagnosticLocked("backend", "ready")

	report, err := c.backend.Recover(ctx)
	if err != nil {
		c.setDiagnosticLocked("recovery", "failed")
		c.setDiagnosticLocked("recovery.error", err.Error())
	} else {
		c.setDiagnosticLocked("recovery", report.Action)
	}
	return nil
}

func (c *Controller) applyDisabledLocked(ctx context.Context) {
	compiled, err := policy.CompileWith(c.config, policy.Constraints{})
	if err != nil {
		c.setDiagnosticLocked("apply", "invalid")
		c.setDiagnosticLocked("apply.error", err.Error())
		return
	}
	if err := c.backend.ApplyPolicy(ctx, compiled, backend.PolicyOptions{}); err != nil {
		c.recordApplyErrorLocked(err)
		return
	}
	c.applied = false
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

	previousConfig := c.config
	if err := c.backend.ApplyPolicy(ctx, compiled, wiring.Options); err != nil {
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
		c.recordApplyErrorLocked(err)
		return 0, fmt.Errorf("persist split tunnel config: %w", err)
	}

	c.config = cfg
	c.revision = revision
	c.applied = cfg.SplitTunnel.Enabled
	c.clearDiagnosticLocked("apply.error")
	c.setDiagnosticLocked("apply", "applied")
	return revision, nil
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
	if err := c.backend.ApplyPolicy(ctx, compiled, wiring.Options); err != nil {
		c.setDiagnosticLocked("rollback.error", err.Error())
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
