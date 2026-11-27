//go:build linux && !android

package classifier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

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

func (o Options) normalized() Options {
	if o.Root == "" {
		o.Root = DefaultRoot
	}
	if o.Base == "" {
		o.Base = DefaultBase
	}
	if o.MaxScopes <= 0 {
		o.MaxScopes = DefaultMaxScopes
	}
	return o
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

type scopeState struct {
	identity   Identity
	uid        config.UID
	path       string
	generation uint64
	processes  map[application.ProcessKey]struct{}
}

// Manager creates and owns application cgroup scopes and maps live processes
// to them. All methods are safe for concurrent use.
type Manager struct {
	mu sync.Mutex

	registry       *application.Registry
	opts           Options
	fs             cgroupFS
	requireCgroup2 bool

	scopes    map[string]*scopeState
	baseAbs   string
	baseReady bool
	closed    bool
}

// New returns a manager that uses the platform cgroup v2 filesystem.
func New(registry *application.Registry, opts Options) (*Manager, error) {
	return newManager(registry, opts, true)
}

func newManager(registry *application.Registry, opts Options, requireCgroup2 bool) (*Manager, error) {
	opts = opts.normalized()
	if err := validateScopePath(opts.Base); err != nil {
		return nil, fmt.Errorf("classifier base: %w", err)
	}
	if opts.Root == "" || !filepath.IsAbs(opts.Root) {
		return nil, fmt.Errorf("classifier root %q must be absolute", opts.Root)
	}
	return &Manager{
		registry:       registry,
		opts:           opts,
		fs:             osCgroupFS{},
		requireCgroup2: requireCgroup2,
		scopes:         make(map[string]*scopeState),
	}, nil
}

// Reconcile refreshes the M06 registry, classifies matching live processes and
// returns the cgroup scopes a backend should match. Processes that do not match
// a policy requirement are left unclassified and follow the policy default.
// Scopes that were classified before a per-process or cleanup error are still
// returned so the caller can install their rules instead of routing them as
// unclassified traffic.
func (m *Manager) Reconcile(ctx context.Context, compiled *policy.CompiledPolicy) ([]backend.ApplicationScope, error) {
	scopes, err := m.ReconcileScopes(ctx, compiled)
	out := make([]backend.ApplicationScope, len(scopes))
	for i := range scopes {
		out[i] = scopes[i].BackendScope()
	}
	return out, err
}

// ReconcileScopes is Reconcile with the live generation and PID detail kept for
// diagnostics and tests.
func (m *Manager) ReconcileScopes(ctx context.Context, compiled *policy.CompiledPolicy) ([]Scope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrClosed
	}
	if err := m.ensureBaseLocked(); err != nil {
		return nil, err
	}
	requirements := Requirements(compiled)
	if len(requirements) == 0 {
		return nil, m.removeAllScopesLocked()
	}
	if m.registry == nil {
		return nil, errors.New("application registry is required to reconcile a policy")
	}
	if _, err := m.registry.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("refresh application registry: %w", err)
	}
	return m.reconcileProcessesLocked(ctx, m.registry.Processes(), requirements)
}

// ReconcileProcesses classifies an explicit process snapshot. Callers can use
// it with a registry refresh of their own; tests use it to avoid reading the
// host process table.
func (m *Manager) ReconcileProcesses(
	ctx context.Context,
	processes []application.Process,
	requirements []Requirement,
) ([]Scope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrClosed
	}
	if err := m.ensureBaseLocked(); err != nil {
		return nil, err
	}
	if len(requirements) == 0 {
		return nil, m.removeAllScopesLocked()
	}
	return m.reconcileProcessesLocked(ctx, processes, requirements)
}

// EnsureScope returns an existing scope for the identity and user, or creates a
// new owned scope. It does not move any process.
func (m *Manager) EnsureScope(
	ctx context.Context,
	identity Identity,
	uid config.UID,
) (Scope, error) {
	if err := ctx.Err(); err != nil {
		return Scope{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return Scope{}, ErrClosed
	}
	if err := m.ensureBaseLocked(); err != nil {
		return Scope{}, err
	}
	state, err := m.ensureScopeLocked(identity, uid)
	if err != nil {
		return Scope{}, err
	}
	return scopeSnapshot(state), nil
}

// LaunchSpec describes a process the caller explicitly starts through the
// managed launcher fallback. The managed launcher is only used when the caller
// can start the application; the classifier never executes desktop entry
// commands.
type LaunchSpec struct {
	Identity Identity
	UID      config.UID
	Path     string
	Args     []string
	Env      []string
	Dir      string
}

// Launch starts a process atomically inside the application scope with
// CLONE_INTO_CGROUP, so the first socket it creates is already classified.
// Callers are responsible for the executable and arguments; nothing is read
// from a desktop entry.
func (m *Manager) Launch(ctx context.Context, spec LaunchSpec) (*exec.Cmd, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if spec.Path == "" {
		return nil, errors.New("launcher executable path is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrClosed
	}
	if err := m.ensureBaseLocked(); err != nil {
		return nil, err
	}
	state, err := m.ensureScopeLocked(spec.Identity, spec.UID)
	if err != nil {
		return nil, err
	}

	cgroupPath := m.absoluteLocked(state.path)
	fd, err := unix.Open(cgroupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open cgroup %q: %w", state.path, err)
	}

	cmd := exec.CommandContext(ctx, spec.Path, spec.Args...)
	cmd.Env = spec.Env
	cmd.Dir = spec.Dir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    fd,
	}
	if err := cmd.Start(); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("start %q in cgroup %q: %w", spec.Path, state.path, err)
	}
	if err := unix.Close(fd); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, fmt.Errorf("close cgroup descriptor for %q: %w", state.path, err)
	}
	return cmd, nil
}

// Close removes every owned application scope. It never removes the base path,
// which may be a delegated systemd slice, and it is idempotent.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true
	if !m.baseReady {
		return nil
	}
	return m.removeAllScopesLocked()
}

func (m *Manager) reconcileProcessesLocked(
	ctx context.Context,
	processes []application.Process,
	requirements []Requirement,
) ([]Scope, error) {
	var merr error
	live := make(map[string]bool)
	matched := make(map[string]map[application.ProcessKey]struct{})

	for i := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		process := processes[i]
		identity, ok := m.identityForProcessLocked(process)
		if !ok || !matchesAny(identity, requirements) {
			continue
		}

		state, err := m.ensureScopeLocked(identity, config.UID(process.UID))
		if err != nil {
			merr = errors.Join(merr, fmt.Errorf("ensure scope for process %d: %w", process.PID, err))
			continue
		}
		if !processInScope(process.Cgroup, state.path) {
			if err := m.fs.WriteProcs(m.absoluteLocked(state.path), process.PID); err != nil {
				merr = errors.Join(merr,
					fmt.Errorf("assign process %d to cgroup %q: %w", process.PID, state.path, err))
				continue
			}
		}
		if matched[state.path] == nil {
			matched[state.path] = make(map[application.ProcessKey]struct{})
		}
		matched[state.path][process.Key()] = struct{}{}
		live[state.path] = true
	}

	// A child process inherits the application cgroup even when its executable
	// does not match the registry. Keep the scope alive while any process is in
	// it, including children created after the application was moved.
	pids := make(map[string][]int32)
	for i := range processes {
		process := processes[i]
		state := m.stateByPath(process.Cgroup)
		if state == nil {
			continue
		}
		if matched[state.path] == nil {
			matched[state.path] = make(map[application.ProcessKey]struct{})
		}
		matched[state.path][process.Key()] = struct{}{}
		live[state.path] = true
		pids[state.path] = append(pids[state.path], process.PID)
	}
	for path, keys := range matched {
		for key := range keys {
			pids[path] = append(pids[path], key.PID)
		}
	}

	for key, state := range m.scopes {
		if live[state.path] {
			continue
		}
		if err := m.removeScopeLocked(state); err != nil {
			merr = errors.Join(merr, err)
			continue
		}
		delete(m.scopes, key)
	}

	for path, keys := range matched {
		state := m.stateByPath(path)
		if state == nil {
			continue
		}
		m.advanceGeneration(state, keys)
	}

	if err := m.removeStaleDirsLocked(live); err != nil {
		merr = errors.Join(merr, err)
	}

	scopes := make([]Scope, 0, len(m.scopes))
	for _, state := range m.scopes {
		if !live[state.path] {
			continue
		}
		snapshot := scopeSnapshot(state)
		snapshot.PIDs = uniquePIDs(pids[state.path])
		scopes = append(scopes, snapshot)
	}
	sortScopes(scopes)
	return scopes, merr
}

func (m *Manager) identityForProcessLocked(process application.Process) (Identity, bool) {
	if m.registry != nil {
		if app, ok := m.registry.Match(process); ok && !app.Unknown {
			identity := IdentityOf(app)
			enrichIdentityFromCgroup(&identity, process.Cgroup)
			if identity.canonical() != "" {
				return identity, true
			}
		}
	}

	identity := Identity{Executable: config.Executable(process.Executable)}
	enrichIdentityFromCgroup(&identity, process.Cgroup)
	if identity.canonical() == "" {
		return Identity{}, false
	}
	return identity, true
}

func enrichIdentityFromCgroup(identity *Identity, cgroupPath string) {
	fromCgroup := IdentityFromCgroup(cgroupPath)
	if identity.FlatpakID == "" {
		identity.FlatpakID = fromCgroup.FlatpakID
	}
	if identity.DesktopID == "" {
		identity.DesktopID = fromCgroup.DesktopID
	}
	if identity.SnapID == "" {
		identity.SnapID = fromCgroup.SnapID
	}
}

func (m *Manager) ensureBaseLocked() error {
	if m.baseReady {
		return nil
	}
	if m.requireCgroup2 {
		if err := m.fs.Cgroup2(m.opts.Root); err != nil {
			return fmt.Errorf("%w: %v", ErrCgroupV2Unavailable, err)
		}
	}

	base := m.absoluteLocked(m.opts.Base)
	exists, err := m.fs.Exists(base)
	if err != nil {
		return fmt.Errorf("inspect classifier base %q: %w", m.opts.Base, err)
	}
	if !exists {
		if err := m.fs.MkdirAll(base); err != nil {
			return fmt.Errorf("create classifier base %q: %w", m.opts.Base, err)
		}
	}
	m.baseAbs = base
	m.baseReady = true
	return nil
}

func (m *Manager) ensureScopeLocked(identity Identity, uid config.UID) (*scopeState, error) {
	key := scopeKey(uid, identity)
	if state, ok := m.scopes[key]; ok {
		return state, nil
	}
	if len(m.scopes) >= m.opts.MaxScopes {
		return nil, fmt.Errorf("%w: %d scopes", ErrScopeLimit, m.opts.MaxScopes)
	}

	path := m.opts.Base + "/" + scopeName(uid, identity)
	absolute := m.absoluteLocked(path)
	exists, err := m.fs.Exists(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect scope %q: %w", path, err)
	}
	if !exists {
		if err := m.fs.MkdirAll(absolute); err != nil {
			return nil, fmt.Errorf("create scope %q: %w", path, err)
		}
	}

	state := &scopeState{
		identity:  identity,
		uid:       uid,
		path:      path,
		processes: make(map[application.ProcessKey]struct{}),
	}
	m.scopes[key] = state
	return state, nil
}

func (m *Manager) advanceGeneration(
	state *scopeState,
	current map[application.ProcessKey]struct{},
) {
	previous := state.processes
	state.processes = current
	if len(current) == 0 {
		return
	}
	if len(previous) == 0 || !processSetsOverlap(previous, current) {
		state.generation++
	}
}

func processSetsOverlap(
	left, right map[application.ProcessKey]struct{},
) bool {
	for key := range left {
		if _, ok := right[key]; ok {
			return true
		}
	}
	return false
}

func (m *Manager) removeAllScopesLocked() error {
	var merr error
	for key, state := range m.scopes {
		if err := m.removeScopeLocked(state); err != nil {
			merr = errors.Join(merr, err)
			continue
		}
		delete(m.scopes, key)
	}
	if err := m.removeStaleDirsLocked(nil); err != nil {
		merr = errors.Join(merr, err)
	}
	return merr
}

func (m *Manager) removeScopeLocked(state *scopeState) error {
	absolute := m.absoluteLocked(state.path)
	if err := m.fs.Remove(absolute); err != nil {
		return fmt.Errorf("remove scope %q: %w", state.path, err)
	}
	return nil
}

func (m *Manager) removeStaleDirsLocked(live map[string]bool) error {
	if !m.baseReady {
		return nil
	}
	entries, err := m.fs.ReadDir(m.baseAbs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("list classifier base %q: %w", m.opts.Base, err)
	}

	var merr error
	for _, name := range entries {
		if !strings.HasPrefix(name, scopePrefix) {
			continue
		}
		path := m.opts.Base + "/" + name
		if live[path] {
			continue
		}
		if err := m.fs.Remove(m.absoluteLocked(path)); err != nil {
			merr = errors.Join(merr, fmt.Errorf("remove stale scope %q: %w", path, err))
		}
	}
	return merr
}

func (m *Manager) stateByPath(cgroupPath string) *scopeState {
	for _, state := range m.scopes {
		if processInScope(cgroupPath, state.path) {
			return state
		}
	}
	return nil
}

func (m *Manager) absoluteLocked(relativePath string) string {
	return filepath.Join(m.opts.Root, filepath.FromSlash(relativePath))
}

func processInScope(processCgroup, scopePath string) bool {
	clean := strings.Trim(processCgroup, "/")
	if clean == "" {
		return false
	}
	return clean == scopePath || strings.HasPrefix(clean, scopePath+"/")
}

func scopeSnapshot(state *scopeState) Scope {
	return Scope{
		Identity:   state.identity,
		UID:        state.uid,
		Path:       state.path,
		Generation: state.generation,
	}
}

func uniquePIDs(pids []int32) []int32 {
	if len(pids) == 0 {
		return nil
	}
	seen := make(map[int32]struct{}, len(pids))
	out := make([]int32, 0, len(pids))
	for _, pid := range pids {
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortScopes(scopes []Scope) {
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].Path != scopes[j].Path {
			return scopes[i].Path < scopes[j].Path
		}
		return scopes[i].UID < scopes[j].UID
	})
}

type cgroupFS interface {
	Cgroup2(root string) error
	MkdirAll(path string) error
	Exists(path string) (bool, error)
	Remove(path string) error
	WriteProcs(path string, pid int32) error
	ReadDir(path string) ([]string, error)
}

type osCgroupFS struct{}

func (osCgroupFS) Cgroup2(root string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(root, &stat); err != nil {
		return err
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("%s is not a cgroup v2 hierarchy", root)
	}
	return nil
}

func (osCgroupFS) MkdirAll(path string) error {
	return os.MkdirAll(path, 0o755)
}

func (osCgroupFS) Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (osCgroupFS) Remove(path string) error {
	// cgroupfs rejects removing its pseudo-files; a test root uses a real file
	// instead. Ignore the file removal and let the directory removal decide
	// whether the scope is empty.
	_ = os.Remove(filepath.Join(path, "cgroup.procs"))
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (osCgroupFS) WriteProcs(path string, pid int32) error {
	file, err := os.OpenFile(filepath.Join(path, "cgroup.procs"),
		os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(strconv.FormatInt(int64(pid), 10) + "\n"); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (osCgroupFS) ReadDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}
