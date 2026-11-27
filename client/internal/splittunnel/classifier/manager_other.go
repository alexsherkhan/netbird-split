//go:build !linux || android

package classifier

import (
	"context"
	"os/exec"

	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

// Options configures a Manager. Root and Base are relative cgroup v2 paths.
type Options struct {
	Root      string
	Base      string
	MaxScopes int
}

// Scope is one live application cgroup owned by the classifier.
type Scope struct {
	Identity   Identity
	UID        config.UID
	Path       string
	Generation uint64
	PIDs       []int32
}

// BackendScope converts the live scope to the runtime backend input.
func (s Scope) BackendScope() backend.ApplicationScope {
	return backend.ApplicationScope{
		Identity:   s.Identity.backendIdentity(),
		UID:        s.UID,
		CgroupPath: s.Path,
	}
}

// Manager is unavailable outside Linux cgroup v2.
type Manager struct{}

// New reports that application classification is unsupported on this platform.
func New(*application.Registry, Options) (*Manager, error) {
	return nil, ErrUnsupported
}

// Reconcile reports that application classification is unsupported.
func (m *Manager) Reconcile(context.Context, *policy.CompiledPolicy) ([]backend.ApplicationScope, error) {
	return nil, ErrUnsupported
}

// ReconcileScopes reports that application classification is unsupported.
func (m *Manager) ReconcileScopes(context.Context, *policy.CompiledPolicy) ([]Scope, error) {
	return nil, ErrUnsupported
}

// ReconcileProcesses reports that application classification is unsupported.
func (m *Manager) ReconcileProcesses(context.Context, []application.Process, []Requirement) ([]Scope, error) {
	return nil, ErrUnsupported
}

// EnsureScope reports that application classification is unsupported.
func (m *Manager) EnsureScope(context.Context, Identity, config.UID) (Scope, error) {
	return Scope{}, ErrUnsupported
}

// LaunchSpec describes a process the caller starts through the managed launcher.
type LaunchSpec struct {
	Identity Identity
	UID      config.UID
	Path     string
	Args     []string
	Env      []string
	Dir      string
}

// Launch reports that application classification is unsupported.
func (m *Manager) Launch(context.Context, LaunchSpec) (*exec.Cmd, error) {
	return nil, ErrUnsupported
}

// Close is safe on an unsupported platform.
func (m *Manager) Close() error {
	return nil
}
