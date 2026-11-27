package application

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ErrRegistryFull is returned when adding metadata would exceed a configured
// limit.
var ErrRegistryFull = errors.New("application registry is full")

type registryEntry struct {
	app  Application
	rank int
}

// RefreshResult reports the state after a successful refresh.
type RefreshResult struct {
	Applications int
	Processes    int
}

// Registry holds discoverable application metadata and live process identity in
// separate maps. Applications are keyed by desktop ID; processes are keyed by
// PID and start time so a reused PID cannot inherit stale state.
type Registry struct {
	mu sync.RWMutex

	opts       Options
	discovered map[string]registryEntry
	explicit   map[string]registryEntry
	processes  map[ProcessKey]Process
}

// New creates an empty registry. Options are copied and normalized.
func New(opts Options) *Registry {
	opts = opts.normalized()
	return &Registry{
		opts:       opts,
		discovered: make(map[string]registryEntry),
		explicit:   make(map[string]registryEntry),
		processes:  make(map[ProcessKey]Process),
	}
}

// Add registers an explicit application, which takes precedence over
// discovered metadata with the same desktop ID.
func (r *Registry) Add(app Application) error {
	if strings.TrimSpace(app.DesktopID) == "" {
		return ErrDesktopIDRequired
	}
	app = cloneApplication(app)
	app.InstallType = InstallExplicit
	app.Unknown = false

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.explicit[app.DesktopID]; !exists && len(r.explicit) >= r.opts.MaxApplications {
		return ErrRegistryFull
	}
	if discovered, ok := r.discovered[app.DesktopID]; ok {
		app.Shadowed = cleanShadowed(append(app.Shadowed, SourceRef{
			Path:        discovered.app.SourcePath,
			InstallType: discovered.app.InstallType,
		}))
	}
	r.explicit[app.DesktopID] = registryEntry{app: app, rank: -1}
	return nil
}

// Remove deletes application metadata with the given desktop ID. It reports
// whether an entry existed.
func (r *Registry) Remove(desktopID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, explicit := r.explicit[desktopID]
	_, discovered := r.discovered[desktopID]
	delete(r.explicit, desktopID)
	delete(r.discovered, desktopID)
	return explicit || discovered
}

// List returns application metadata sorted by desktop ID.
func (r *Registry) List() []Application {
	r.mu.RLock()
	defer r.mu.RUnlock()

	apps := make([]Application, 0, len(r.discovered)+len(r.explicit))
	for desktopID, entry := range r.discovered {
		if _, shadowed := r.explicit[desktopID]; shadowed {
			continue
		}
		apps = append(apps, cloneApplication(entry.app))
	}
	for _, entry := range r.explicit {
		apps = append(apps, cloneApplication(entry.app))
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].DesktopID < apps[j].DesktopID })
	return apps
}

// Lookup returns application metadata for one desktop ID. Explicit entries
// take precedence over discovered entries.
func (r *Registry) Lookup(desktopID string) (Application, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if entry, ok := r.explicit[desktopID]; ok {
		return cloneApplication(entry.app), true
	}
	if entry, ok := r.discovered[desktopID]; ok {
		return cloneApplication(entry.app), true
	}
	return Application{}, false
}

// AddProcess records a live process. A new start time for an existing PID
// replaces the stale entry, which protects against PID reuse.
func (r *Registry) AddProcess(process Process) error {
	if process.PID <= 0 {
		return ErrProcessPID
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for key := range r.processes {
		if key.PID == process.PID && key.StartTime != process.StartTime {
			delete(r.processes, key)
		}
	}
	key := process.Key()
	if _, exists := r.processes[key]; !exists && len(r.processes) >= r.opts.ScanLimit {
		return ErrRegistryFull
	}
	r.processes[key] = process
	return nil
}

// RemoveProcess deletes one process generation. It reports whether the exact
// PID and start time were present.
func (r *Registry) RemoveProcess(pid int32, startTime uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ProcessKey{PID: pid, StartTime: startTime}
	if _, ok := r.processes[key]; !ok {
		return false
	}
	delete(r.processes, key)
	return true
}

// Processes returns live processes sorted by PID and start time.
func (r *Registry) Processes() []Process {
	r.mu.RLock()
	defer r.mu.RUnlock()

	processes := make([]Process, 0, len(r.processes))
	for _, process := range r.processes {
		processes = append(processes, process)
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].PID != processes[j].PID {
			return processes[i].PID < processes[j].PID
		}
		return processes[i].StartTime < processes[j].StartTime
	})
	return processes
}

// Match returns application metadata for a process executable. With
// UnknownTrack an unmatched executable produces a synthetic unknown
// application; otherwise the second result is false.
func (r *Registry) Match(process Process) (Application, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	best, found := r.matchExecutable(process.Executable)
	if found {
		return best, true
	}
	if r.opts.Unknown == UnknownTrack && process.Executable != "" {
		return unknownApplication(process.Executable), true
	}
	return Application{}, false
}

func (r *Registry) matchExecutable(executable string) (Application, bool) {
	var (
		best      registryEntry
		bestScore int
		found     bool
	)
	consider := func(entry registryEntry) {
		score := executableMatchScore(entry.app.Executable, executable)
		if score == 0 {
			return
		}
		switch {
		case !found:
		case score > bestScore:
		case score < bestScore:
			return
		case entry.rank < best.rank:
		case entry.rank > best.rank:
			return
		case entry.app.DesktopID >= best.app.DesktopID:
			return
		}
		best = entry
		bestScore = score
		found = true
	}
	for _, entry := range r.explicit {
		consider(entry)
	}
	for _, entry := range r.discovered {
		consider(entry)
	}
	if !found {
		return Application{}, false
	}
	return cloneApplication(best.app), true
}

// Refresh rediscovers applications and rescans processes. Explicit entries are
// preserved; discovered metadata and processes are replaced on success.
func (r *Registry) Refresh(ctx context.Context) (RefreshResult, error) {
	r.mu.RLock()
	opts := r.opts
	explicit := make(map[string]registryEntry, len(r.explicit))
	for id, entry := range r.explicit {
		explicit[id] = registryEntry{app: cloneApplication(entry.app), rank: entry.rank}
	}
	r.mu.RUnlock()

	apps, err := Discover(ctx, opts)
	if err != nil {
		return RefreshResult{}, err
	}
	processes, err := ScanProcesses(ctx, opts.ProcRoot, opts.ScanLimit)
	if err != nil && !errors.Is(err, ErrUnsupported) {
		return RefreshResult{}, err
	}

	sources := dedupeSources(opts.Sources)
	discovered := make(map[string]registryEntry, len(apps))
	for _, app := range apps {
		if entry, ok := explicit[app.DesktopID]; ok {
			entry.app.Shadowed = cleanShadowed(append(entry.app.Shadowed, SourceRef{
				Path:        app.SourcePath,
				InstallType: app.InstallType,
			}))
			explicit[app.DesktopID] = entry
			continue
		}
		discovered[app.DesktopID] = registryEntry{
			app:  app,
			rank: sourceRank(app.SourcePath, sources),
		}
	}

	processMap := make(map[ProcessKey]Process, len(processes))
	for _, process := range processes {
		processMap[process.Key()] = process
	}

	r.mu.Lock()
	r.discovered = discovered
	r.explicit = explicit
	r.processes = processMap
	r.mu.Unlock()

	return RefreshResult{
		Applications: len(discovered) + len(explicit),
		Processes:    len(processMap),
	}, nil
}

func sourceRank(sourcePath string, sources []Source) int {
	for index, source := range sources {
		rel, err := filepath.Rel(source.Path, sourcePath)
		if err != nil {
			continue
		}
		if rel == "." {
			return index
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return index
		}
	}
	return len(sources)
}
