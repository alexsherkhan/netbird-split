package application

import (
	"errors"
	"path/filepath"
	"strings"
)

// InstallType describes where an application entry was discovered.
type InstallType string

const (
	// InstallSystem is a desktop entry from a system data directory.
	InstallSystem InstallType = "system"
	// InstallUser is a desktop entry from the user's data directory.
	InstallUser InstallType = "user"
	// InstallFlatpak is a desktop entry exported by Flatpak.
	InstallFlatpak InstallType = "flatpak"
	// InstallSnap is a desktop entry exported by Snap.
	InstallSnap InstallType = "snap"
	// InstallExplicit is an entry supplied directly by the caller.
	InstallExplicit InstallType = "explicit"
	// InstallUnknown describes a running executable with no desktop entry.
	InstallUnknown InstallType = "unknown"
)

// Default limits keep discovery and process scans bounded. A zero or negative
// option is replaced by the matching default.
const (
	DefaultMaxApplications = 5000
	DefaultScanLimit       = 20000
)

// Errors reported by the registry and process scanner.
var (
	// ErrDesktopIDRequired is returned when an application has no desktop ID.
	ErrDesktopIDRequired = errors.New("desktop ID is required")
	// ErrProcessPID is returned when a process has no positive PID.
	ErrProcessPID = errors.New("process PID must be positive")
)

// Source is a directory searched for desktop entries. Sources are ordered by
// precedence: a source earlier in the list shadows the same desktop ID found
// later.
type Source struct {
	Path        string
	InstallType InstallType
}

// SourceRef records a lower precedence source that a desktop ID shadowed.
type SourceRef struct {
	Path        string
	InstallType InstallType
}

// Icon is a reference to an icon theme name or an absolute icon path. It is
// never loaded or decoded.
type Icon struct {
	Name string
	Path string
}

// Application is discoverable metadata for an installed application. Live
// process state is kept separate in Process.
type Application struct {
	DesktopID   string
	Name        string
	Icon        Icon
	Executable  string
	InstallType InstallType
	SourcePath  string
	NoDisplay   bool
	Unknown     bool
	Shadowed    []SourceRef
}

// UnknownBehavior selects how a process without a matching desktop entry is
// treated by Registry.Match.
type UnknownBehavior string

const (
	// UnknownSkip ignores processes without a matching desktop entry.
	UnknownSkip UnknownBehavior = "skip"
	// UnknownTrack returns a synthetic application for an unmatched executable.
	UnknownTrack UnknownBehavior = "track"
)

// Options configures discovery, process scanning and the registry.
type Options struct {
	// Sources are desktop entry directories in descending precedence. When
	// nil, DefaultSources is used; an empty non-nil slice disables discovery.
	Sources []Source
	// ProcRoot is the proc filesystem root. When empty, /proc is used.
	ProcRoot string
	// ScanLimit caps the number of processes returned by one scan. When zero
	// or negative, DefaultScanLimit is used.
	ScanLimit int
	// MaxApplications caps the number of desktop files examined by one
	// discovery run. When zero or negative, DefaultMaxApplications is used.
	MaxApplications int
	// Unknown selects behavior for executables without a desktop entry.
	Unknown UnknownBehavior
}

func (o Options) normalized() Options {
	if o.Sources == nil {
		o.Sources = DefaultSources()
	}
	if o.ProcRoot == "" {
		o.ProcRoot = defaultProcRoot
	}
	if o.ScanLimit <= 0 {
		o.ScanLimit = DefaultScanLimit
	}
	if o.MaxApplications <= 0 {
		o.MaxApplications = DefaultMaxApplications
	}
	if o.Unknown == "" {
		o.Unknown = UnknownSkip
	}
	return o
}

func unknownApplication(executable string) Application {
	return Application{
		DesktopID:   "unknown:" + executable,
		Name:        filepath.Base(executable),
		Executable:  executable,
		InstallType: InstallUnknown,
		Unknown:     true,
	}
}

func cleanShadowed(refs []SourceRef) []SourceRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]SourceRef, 0, len(refs))
	seen := make(map[SourceRef]struct{}, len(refs))
	for _, ref := range refs {
		if ref.Path == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func cloneApplication(app Application) Application {
	app.Shadowed = append([]SourceRef(nil), app.Shadowed...)
	return app
}

func executableMatchScore(entry, executable string) int {
	if entry == "" || executable == "" {
		return 0
	}
	if filepath.Clean(entry) == filepath.Clean(executable) {
		return 2
	}
	if strings.ContainsRune(entry, filepath.Separator) {
		return 0
	}
	if filepath.Base(entry) == filepath.Base(executable) {
		return 1
	}
	return 0
}
