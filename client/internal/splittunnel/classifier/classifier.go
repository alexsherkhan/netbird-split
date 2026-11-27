package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

var (
	// ErrUnsupported reports a classifier operation outside Linux cgroup v2.
	ErrUnsupported = errors.New("application classification is not supported on this platform")
	// ErrClosed reports an operation on a closed manager.
	ErrClosed = errors.New("application classifier is closed")
	// ErrCgroupV2Unavailable reports a host without the cgroup v2 hierarchy.
	ErrCgroupV2Unavailable = errors.New("cgroup v2 unified hierarchy is unavailable")
	// ErrScopeLimit reports that the configured scope limit was reached.
	ErrScopeLimit = errors.New("application scope limit reached")
)

const (
	// DefaultRoot is the cgroup v2 mount point.
	DefaultRoot = "/sys/fs/cgroup"
	// DefaultBase is the relative cgroup path owned by the classifier. A
	// systemd host needs this path delegated to the daemon; the current
	// milestone does not install that delegation.
	DefaultBase = "netbird-split"
	// DefaultMaxScopes bounds the number of live application scopes.
	DefaultMaxScopes = 1024

	scopePrefix = "nb-"
)

// Identity is the install-independent identity of a classified application.
// Empty fields never match a requirement.
type Identity struct {
	DesktopID  config.DesktopID
	Executable config.Executable
	FlatpakID  config.FlatpakID
	SnapID     config.SnapID
}

// IdentityOf maps discovered application metadata to a classification identity.
// Flatpak and Snap IDs follow the platform desktop entry and cgroup naming
// conventions; this never imports or executes a desktop entry command.
func IdentityOf(app application.Application) Identity {
	identity := Identity{
		DesktopID:  config.DesktopID(app.DesktopID),
		Executable: config.Executable(app.Executable),
	}
	if app.Unknown {
		return Identity{Executable: identity.Executable}
	}

	switch app.InstallType {
	case application.InstallFlatpak:
		id := flatpakIDFromDesktopID(app.DesktopID)
		identity.FlatpakID = config.FlatpakID(id)
		if id != "" {
			identity.DesktopID = config.DesktopID(id + ".desktop")
		}
	case application.InstallSnap:
		identity.SnapID = config.SnapID(snapIDFromDesktopID(app.DesktopID))
	}
	return identity
}

func flatpakIDFromDesktopID(desktopID string) string {
	id := strings.TrimSuffix(desktopID, ".desktop")
	if id == desktopID || !strings.Contains(id, ".") {
		return ""
	}
	return id
}

func snapIDFromDesktopID(desktopID string) string {
	base := strings.TrimSuffix(desktopID, ".desktop")
	if snap, _, ok := strings.Cut(base, "_"); ok {
		return snap
	}
	return base
}

// IdentityFromCgroup extracts Flatpak and Snap identity from a process cgroup
// path. It is a fallback for applications whose desktop entry executable is a
// launcher such as flatpak or snap, so the process executable does not match
// the entry.
func IdentityFromCgroup(cgroupPath string) Identity {
	var identity Identity
	for _, component := range strings.Split(strings.Trim(cgroupPath, "/"), "/") {
		if strings.HasPrefix(component, "app-flatpak-") {
			name := strings.TrimPrefix(component, "app-flatpak-")
			name = strings.TrimSuffix(name, ".scope")
			name = trimScopeSuffix(name)
			if name != "" {
				identity.FlatpakID = config.FlatpakID(name)
				identity.DesktopID = config.DesktopID(name + ".desktop")
			}
			continue
		}
		if strings.HasPrefix(component, "snap.") {
			fields := strings.Split(strings.TrimSuffix(component, ".scope"), ".")
			if len(fields) >= 3 && fields[1] != "" {
				identity.SnapID = config.SnapID(fields[1])
				appName, _, _ := strings.Cut(fields[2], "-")
				if appName != "" {
					identity.DesktopID = config.DesktopID(fields[1] + "_" + appName + ".desktop")
				}
			}
		}
	}
	return identity
}

func trimScopeSuffix(name string) string {
	index := strings.LastIndexByte(name, '-')
	if index <= 0 {
		return name
	}
	if _, err := strconv.ParseUint(name[index+1:], 10, 64); err == nil {
		return name[:index]
	}
	return name
}

func (i Identity) canonical() string {
	if i.DesktopID == "" && i.Executable == "" && i.FlatpakID == "" && i.SnapID == "" {
		return ""
	}
	return strings.Join([]string{
		string(i.DesktopID),
		string(i.Executable),
		string(i.FlatpakID),
		string(i.SnapID),
	}, "\x00")
}

func (i Identity) backendIdentity() backend.ApplicationIdentity {
	return backend.ApplicationIdentity{
		DesktopID:  i.DesktopID,
		Executable: i.Executable,
		FlatpakID:  i.FlatpakID,
		SnapID:     i.SnapID,
	}
}

// Requirement is one application selector extracted from a compiled policy.
// A process is classified when its identity matches at least one requirement.
type Requirement struct {
	DesktopID  config.DesktopID
	Executable config.Executable
	FlatpakID  config.FlatpakID
	SnapID     config.SnapID
}

// Matches reports whether the identity satisfies the requirement.
func (r Requirement) Matches(identity Identity) bool {
	switch {
	case r.DesktopID != "":
		return r.DesktopID == identity.DesktopID
	case r.Executable != "":
		return r.Executable == identity.Executable
	case r.FlatpakID != "":
		return r.FlatpakID == identity.FlatpakID
	case r.SnapID != "":
		return r.SnapID == identity.SnapID
	default:
		return false
	}
}

// Requirements extracts every application selector from a compiled policy.
// UID conditions alone do not need a cgroup scope because the backend matches
// them directly against the packet's socket user ID.
func Requirements(compiled *policy.CompiledPolicy) []Requirement {
	if compiled == nil || !compiled.Enabled {
		return nil
	}
	var out []Requirement
	for i := range compiled.BlockRules {
		collectRequirements(compiled.BlockRules[i].Conditions, &out)
	}
	for i := range compiled.Rules {
		collectRequirements(compiled.Rules[i].Conditions, &out)
	}
	return dedupeRequirements(out)
}

func collectRequirements(conditions []config.Condition, out *[]Requirement) {
	for i := range conditions {
		condition := &conditions[i]
		switch condition.Type {
		case config.ConditionDesktopID:
			*out = append(*out, Requirement{DesktopID: condition.DesktopID})
		case config.ConditionExecutable:
			*out = append(*out, Requirement{Executable: condition.Executable})
		case config.ConditionFlatpakID:
			*out = append(*out, Requirement{FlatpakID: condition.FlatpakID})
		case config.ConditionSnapID:
			*out = append(*out, Requirement{SnapID: condition.SnapID})
		case config.ConditionAll, config.ConditionAny:
			collectRequirements(condition.Children, out)
		}
	}
}

func dedupeRequirements(requirements []Requirement) []Requirement {
	if len(requirements) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(requirements))
	out := make([]Requirement, 0, len(requirements))
	for _, requirement := range requirements {
		key := requirement.canonical()
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, requirement)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].canonical() < out[j].canonical() })
	return out
}

func (r Requirement) canonical() string {
	switch {
	case r.DesktopID != "":
		return "desktop:" + string(r.DesktopID)
	case r.Executable != "":
		return "executable:" + string(r.Executable)
	case r.FlatpakID != "":
		return "flatpak:" + string(r.FlatpakID)
	case r.SnapID != "":
		return "snap:" + string(r.SnapID)
	default:
		return ""
	}
}

func matchesAny(identity Identity, requirements []Requirement) bool {
	for _, requirement := range requirements {
		if requirement.Matches(identity) {
			return true
		}
	}
	return false
}

func validateScopePath(relativePath string) error {
	if relativePath == "" {
		return errors.New("path is empty")
	}
	if strings.HasPrefix(relativePath, "/") {
		return fmt.Errorf("path %q must be relative to the cgroup root", relativePath)
	}
	if strings.Contains(relativePath, `\`) {
		return fmt.Errorf("path %q must use forward slashes", relativePath)
	}
	for _, component := range strings.Split(relativePath, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("path %q contains an invalid component %q", relativePath, component)
		}
	}
	return nil
}

func scopeName(uid config.UID, identity Identity) string {
	sum := sha256.Sum256([]byte(identity.canonical()))
	return fmt.Sprintf("nb-%d-%s", uid, hex.EncodeToString(sum[:8]))
}

func scopeKey(uid config.UID, identity Identity) string {
	return fmt.Sprintf("%d\x00%s", uid, identity.canonical())
}
