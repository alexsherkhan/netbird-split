//go:build linux && !android

package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

const (
	journalSchemaVersion = 1
	defaultJournalPath   = "/var/lib/netbird/split-tunnel-journal.json"

	defaultRecoveryRetryAttempts = 3
	defaultRecoveryRetryDelay    = 50 * time.Millisecond
	maxRecoveryRetryDelay        = time.Second
)

var (
	// ErrJournalNotFound reports that no recovery journal exists.
	ErrJournalNotFound = errors.New("split tunnel recovery journal not found")
	// ErrJournalCorrupt reports a journal that cannot be trusted. Recovery
	// refuses to mutate kernel state so the caller can decide deliberately.
	ErrJournalCorrupt = errors.New("split tunnel recovery journal is corrupt")
	// ErrInvalidJournalTransition reports a requested state machine edge that is
	// not defined. The journal is left unchanged.
	ErrInvalidJournalTransition = errors.New("invalid split tunnel recovery journal transition")
	// ErrRevisionMismatch reports a recovery intent whose revision differs from
	// the committed journal. The backend refuses to replace a newer intent.
	ErrRevisionMismatch = errors.New("split tunnel recovery intent revision mismatch")
	// ErrRecoveryRequired reports an apply while an interrupted apply is still
	// recorded. The caller must recover it first instead of overwriting it.
	ErrRecoveryRequired = errors.New("split tunnel recovery is required before a new apply")
	// ErrRecoveryIntentRequired reports a committed journal recovered without
	// the caller's current intent. The guard is verified, but a full reapply
	// needs the caller to recompile application scopes against live processes.
	ErrRecoveryIntentRequired = errors.New("split tunnel recovery needs the caller intent")
)

// JournalState is one step of the recovery state machine. Every state except
// JournalStateCommitted is uncommitted: a crash there must roll back or fail
// closed rather than be treated as the intended state.
type JournalState string

const (
	// JournalStateValidated is a validated intent that has not touched the kernel.
	JournalStateValidated JournalState = "validated_intent"
	// JournalStatePreArmed means a protection guard is installed before routes
	// and classification are replaced.
	JournalStatePreArmed JournalState = "pre_armed_guard"
	// JournalStateStaged means routes are installed and classification is being
	// replaced.
	JournalStateStaged JournalState = "staged_apply"
	// JournalStateVerified means the observable kernel state matches the intent.
	JournalStateVerified JournalState = "verified"
	// JournalStateCommitted means the intent is fully applied and may be
	// reapplied after a restart.
	JournalStateCommitted JournalState = "committed"
	// JournalStateRolledBack means the attempt was undone and the previous state
	// or a fail-closed guard is in place.
	JournalStateRolledBack JournalState = "rolled_back"
)

// Valid reports whether the state is one of the defined values.
func (s JournalState) Valid() bool {
	switch s {
	case JournalStateValidated, JournalStatePreArmed, JournalStateStaged,
		JournalStateVerified, JournalStateCommitted, JournalStateRolledBack:
		return true
	default:
		return false
	}
}

// CanTransitionTo reports whether next is a legal successor state.
func (s JournalState) CanTransitionTo(next JournalState) bool {
	switch s {
	case JournalStateValidated:
		return next == JournalStatePreArmed || next == JournalStateRolledBack
	case JournalStatePreArmed:
		return next == JournalStateStaged || next == JournalStateRolledBack
	case JournalStateStaged:
		return next == JournalStateVerified || next == JournalStateRolledBack
	case JournalStateVerified:
		return next == JournalStateCommitted || next == JournalStateRolledBack
	case JournalStateCommitted:
		return next == JournalStateValidated || next == JournalStateRolledBack
	case JournalStateRolledBack:
		return next == JournalStateValidated || next == JournalStateCommitted
	default:
		return false
	}
}

func (s JournalState) committed() bool {
	return s == JournalStateCommitted
}

func (s JournalState) interrupted() bool {
	switch s {
	case JournalStateValidated, JournalStatePreArmed, JournalStateStaged, JournalStateVerified:
		return true
	default:
		return false
	}
}

// journalMatch is the persisted form of one nft match. It contains prefixes,
// protocols and ports, never a user path or a secret.
type journalMatch struct {
	Set      string `json:"set,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Port     uint16 `json:"port,omitempty"`
}

// journalKillRule is the persisted form of one kill switch rule.
type journalKillRule struct {
	Family  uint8          `json:"family"`
	Mark    *uint32        `json:"mark,omitempty"`
	Matches []journalMatch `json:"matches,omitempty"`
	Verdict uint8          `json:"verdict"`
}

// journalGuard is the protection snapshot that recovery can reinstall without
// the original compiled policy. It is intentionally limited to prefixes and
// verdicts, so it carries no raw configuration.
type journalGuard struct {
	Control4 []string          `json:"control4,omitempty"`
	Control6 []string          `json:"control6,omitempty"`
	Rules    []journalKillRule `json:"rules,omitempty"`
	IPv6     bool              `json:"ipv6,omitempty"`
}

// journalAllocation records one owned policy routing primitive.
type journalAllocation struct {
	Class     string `json:"class"`
	Table     uint32 `json:"table"`
	Priority  int    `json:"priority"`
	MarkValue uint32 `json:"mark_value"`
	MarkMask  uint32 `json:"mark_mask"`
}

// journalOwnership is the inventory of kernel objects the backend may inspect
// or remove. Recovery never touches an object outside this inventory and the
// fixed owned names.
type journalOwnership struct {
	Table       string              `json:"table"`
	Chains      []string            `json:"chains,omitempty"`
	Sets        []string            `json:"sets,omitempty"`
	Allocations []journalAllocation `json:"allocations,omitempty"`
}

// journalSnapshot identifies one committed intent. It is used to restore a
// previous commit after an interrupted apply.
type journalSnapshot struct {
	Revision  uint64           `json:"revision"`
	PolicyID  string           `json:"policy_id"`
	Mode      string           `json:"mode"`
	Guard     *journalGuard    `json:"guard,omitempty"`
	Ownership journalOwnership `json:"ownership"`
}

// journalEntry is the persistent recovery record.
type journalEntry struct {
	SchemaVersion int              `json:"schema_version"`
	State         JournalState     `json:"state"`
	Revision      uint64           `json:"revision"`
	PolicyID      string           `json:"policy_id"`
	Mode          string           `json:"mode"`
	Guard         *journalGuard    `json:"guard,omitempty"`
	Ownership     journalOwnership `json:"ownership"`
	Previous      *journalSnapshot `json:"previous,omitempty"`
	UpdatedAt     time.Time        `json:"updated_at"`
	LastError     string           `json:"last_error,omitempty"`
	Issues        []string         `json:"issues,omitempty"`
}

func (e journalEntry) validate() error {
	if e.SchemaVersion != journalSchemaVersion {
		return fmt.Errorf("%w: schema version %d", ErrJournalCorrupt, e.SchemaVersion)
	}
	if !e.State.Valid() {
		return fmt.Errorf("%w: unknown state %q", ErrJournalCorrupt, e.State)
	}
	if e.Ownership.Table == "" {
		return fmt.Errorf("%w: ownership table is empty", ErrJournalCorrupt)
	}
	if e.Guard != nil {
		if _, _, err := e.Guard.toKillSwitch(); err != nil {
			return fmt.Errorf("%w: guard: %w", ErrJournalCorrupt, err)
		}
	}
	if e.Previous != nil && e.Previous.Guard != nil {
		if _, _, err := e.Previous.Guard.toKillSwitch(); err != nil {
			return fmt.Errorf("%w: previous guard: %w", ErrJournalCorrupt, err)
		}
	}
	return nil
}

func (e *journalEntry) transition(next JournalState) error {
	if !e.State.CanTransitionTo(next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidJournalTransition, e.State, next)
	}
	e.State = next
	e.UpdatedAt = time.Now().UTC()
	return nil
}

func (e journalEntry) snapshot() journalSnapshot {
	return journalSnapshot{
		Revision:  e.Revision,
		PolicyID:  e.PolicyID,
		Mode:      e.Mode,
		Guard:     cloneGuard(e.Guard),
		Ownership: cloneOwnership(e.Ownership),
	}
}

func (e *journalEntry) applySnapshot(snapshot journalSnapshot) {
	e.Revision = snapshot.Revision
	e.PolicyID = snapshot.PolicyID
	e.Mode = snapshot.Mode
	e.Guard = cloneGuard(snapshot.Guard)
	e.Ownership = cloneOwnership(snapshot.Ownership)
}

func cloneGuard(guard *journalGuard) *journalGuard {
	if guard == nil {
		return nil
	}
	cloned := *guard
	cloned.Control4 = append([]string(nil), guard.Control4...)
	cloned.Control6 = append([]string(nil), guard.Control6...)
	cloned.Rules = make([]journalKillRule, len(guard.Rules))
	for i, rule := range guard.Rules {
		cloned.Rules[i] = rule
		cloned.Rules[i].Matches = append([]journalMatch(nil), rule.Matches...)
		if rule.Mark != nil {
			mark := *rule.Mark
			cloned.Rules[i].Mark = &mark
		}
	}
	return &cloned
}

func cloneOwnership(ownership journalOwnership) journalOwnership {
	cloned := ownership
	cloned.Chains = append([]string(nil), ownership.Chains...)
	cloned.Sets = append([]string(nil), ownership.Sets...)
	cloned.Allocations = append([]journalAllocation(nil), ownership.Allocations...)
	return cloned
}

// journalStore persists the recovery entry. A store may be in memory in tests
// and on platforms without durable storage; New uses a file store.
type journalStore interface {
	Load() (journalEntry, error)
	Save(journalEntry) error
	Clear() error
	Location() string
}

type memoryJournal struct {
	entry journalEntry
	found bool
}

func newMemoryJournal() *memoryJournal {
	return &memoryJournal{}
}

func (m *memoryJournal) Load() (journalEntry, error) {
	if !m.found {
		return journalEntry{}, ErrJournalNotFound
	}
	return m.entry, nil
}

func (m *memoryJournal) Save(entry journalEntry) error {
	m.entry = entry
	m.found = true
	return nil
}

func (m *memoryJournal) Clear() error {
	m.entry = journalEntry{}
	m.found = false
	return nil
}

func (m *memoryJournal) Location() string {
	return "memory"
}

type fileJournal struct {
	path    string
	rename  func(string, string) error
	remove  func(string) error
	syncDir func(string) error
}

func newFileJournal(path string) *fileJournal {
	return &fileJournal{
		path:    path,
		rename:  os.Rename,
		remove:  os.Remove,
		syncDir: syncDirectory,
	}
}

func (f *fileJournal) Load() (journalEntry, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return journalEntry{}, ErrJournalNotFound
		}
		return journalEntry{}, fmt.Errorf("read recovery journal: %w", err)
	}
	if len(data) == 0 {
		return journalEntry{}, fmt.Errorf("%w: empty file", ErrJournalCorrupt)
	}

	var entry journalEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return journalEntry{}, fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	if err := entry.validate(); err != nil {
		return journalEntry{}, err
	}
	return entry, nil
}

func (f *fileJournal) Save(entry journalEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("encode recovery journal: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create recovery journal directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".split-journal-*")
	if err != nil {
		return fmt.Errorf("create recovery journal temporary file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = f.remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("set recovery journal permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write recovery journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync recovery journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = f.remove(tmpName)
		return fmt.Errorf("close recovery journal: %w", err)
	}
	if err := f.rename(tmpName, f.path); err != nil {
		_ = f.remove(tmpName)
		return fmt.Errorf("replace recovery journal: %w", err)
	}
	if err := f.syncDir(dir); err != nil {
		return fmt.Errorf("sync recovery journal directory: %w", err)
	}
	return nil
}

func (f *fileJournal) Clear() error {
	err := f.remove(f.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove recovery journal: %w", err)
	}
	if err == nil {
		if syncErr := f.syncDir(filepath.Dir(f.path)); syncErr != nil {
			return fmt.Errorf("sync recovery journal directory: %w", syncErr)
		}
	}
	return nil
}

func (f *fileJournal) Location() string {
	return f.path
}

func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

// RecoveryAction names what startup reconciliation did.
type RecoveryAction string

const (
	// RecoveryActionNone means there was no journal and no owned state.
	RecoveryActionNone RecoveryAction = "none"
	// RecoveryActionVerified means the committed state was already correct.
	RecoveryActionVerified RecoveryAction = "verified"
	// RecoveryActionReapplied means the committed intent was applied again.
	RecoveryActionReapplied RecoveryAction = "reapplied"
	// RecoveryActionRolledBack means an interrupted intent was undone.
	RecoveryActionRolledBack RecoveryAction = "rolled_back"
	// RecoveryActionCleaned means orphaned owned state without a journal was
	// removed.
	RecoveryActionCleaned RecoveryAction = "cleaned"
)

// RecoveryReport describes one startup reconciliation.
type RecoveryReport struct {
	Action       RecoveryAction `json:"action"`
	JournalState JournalState   `json:"journal_state"`
	Revision     uint64         `json:"revision"`
	Issues       []string       `json:"issues,omitempty"`
}

// RecoveryDiagnostics is the structured recovery state exposed to callers.
type RecoveryDiagnostics struct {
	JournalState        JournalState `json:"journal_state"`
	Revision            uint64       `json:"revision"`
	Issues              []string     `json:"issues,omitempty"`
	RollbackFailed      bool         `json:"rollback_failed"`
	ProtectionPreserved bool         `json:"protection_preserved"`
	LastError           string       `json:"last_error,omitempty"`
}

// RecoveryIntent is the authoritative intent a caller asks recovery to
// reapply. Revision 0 means the caller has no revision precondition and the
// journal's fingerprint decides whether an apply is needed.
type RecoveryIntent struct {
	Revision uint64
	Compiled *policy.CompiledPolicy
	Options  backend.PolicyOptions
}

func (i *RecoveryIntent) clone() *RecoveryIntent {
	if i == nil {
		return nil
	}
	cloned := &RecoveryIntent{
		Revision: i.Revision,
		Compiled: i.Compiled,
		Options:  clonePolicyOptions(i.Options),
	}
	return cloned
}

func guardFromPlan(plan *policyPlan) *journalGuard {
	if plan == nil {
		return nil
	}
	guard := &journalGuard{
		Control4: prefixesToStrings(plan.nft.sets[setKillSwitchControl4]),
		Control6: prefixesToStrings(plan.nft.sets[setKillSwitchControl6]),
	}
	for _, rule := range plan.nft.killswitch {
		persisted := journalKillRule{
			Family:  uint8(rule.family),
			Verdict: uint8(rule.verdict),
		}
		if rule.mark != nil {
			mark := *rule.mark
			persisted.Mark = &mark
		}
		for _, match := range rule.matches {
			item := journalMatch{
				Set:      string(match.set),
				Protocol: string(match.protocol),
				Port:     match.port,
			}
			if match.prefix.IsValid() {
				item.Prefix = match.prefix.String()
			}
			persisted.Matches = append(persisted.Matches, item)
		}
		guard.Rules = append(guard.Rules, persisted)
	}
	if len(guard.Control6) > 0 || hasFamily6Rule(guard.Rules) {
		guard.IPv6 = true
	}
	return guard
}

func hasFamily6Rule(rules []journalKillRule) bool {
	for _, rule := range rules {
		if nftFamily(rule.Family) == family6 {
			return true
		}
	}
	return false
}

func prefixesToStrings(prefixes []netip.Prefix) []string {
	out := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = prefix.String()
	}
	return out
}

func (g *journalGuard) toKillSwitch() (map[setName][]netip.Prefix, []nftKillRule, error) {
	if g == nil {
		return nil, nil, nil
	}
	sets := make(map[setName][]netip.Prefix, 2)
	control4, err := parseJournalPrefixes(g.Control4)
	if err != nil {
		return nil, nil, fmt.Errorf("control4: %w", err)
	}
	control6, err := parseJournalPrefixes(g.Control6)
	if err != nil {
		return nil, nil, fmt.Errorf("control6: %w", err)
	}
	if len(control4) > 0 {
		sets[setKillSwitchControl4] = control4
	}
	if len(control6) > 0 {
		sets[setKillSwitchControl6] = control6
	}

	rules := make([]nftKillRule, 0, len(g.Rules))
	for i := range g.Rules {
		persisted := &g.Rules[i]
		if persisted.Family != uint8(family4) && persisted.Family != uint8(family6) {
			return nil, nil, fmt.Errorf("rule %d: invalid family %d", i, persisted.Family)
		}
		if persisted.Verdict > uint8(verdictDrop) {
			return nil, nil, fmt.Errorf("rule %d: invalid verdict %d", i, persisted.Verdict)
		}
		rule := nftKillRule{
			family:  nftFamily(persisted.Family),
			verdict: nftVerdict(persisted.Verdict),
		}
		if persisted.Mark != nil {
			mark := *persisted.Mark
			rule.mark = &mark
		}
		for j, match := range persisted.Matches {
			item := nftMatch{
				set:      setName(match.Set),
				protocol: config.Protocol(match.Protocol),
				port:     match.Port,
			}
			if match.Prefix != "" {
				prefix, err := netip.ParsePrefix(match.Prefix)
				if err != nil {
					return nil, nil, fmt.Errorf("rule %d match %d: %w", i, j, err)
				}
				item.prefix = prefix
			}
			rule.matches = append(rule.matches, item)
		}
		rules = append(rules, rule)
	}
	return sets, rules, nil
}

func parseJournalPrefixes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("prefix %d: %w", i, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func ownershipFrom(allocations allocations, owned backend.OwnedObjects) journalOwnership {
	ownership := journalOwnership{
		Table:  owned.Table,
		Chains: append([]string(nil), owned.Chains...),
		Sets:   append([]string(nil), owned.Sets...),
	}
	for _, class := range splitClasses {
		allocation, ok := allocations.get(class)
		if !ok {
			continue
		}
		ownership.Allocations = append(ownership.Allocations, journalAllocation{
			Class:     string(class),
			Table:     uint32(allocation.table),
			Priority:  int(allocation.priority),
			MarkValue: allocation.mark.Value,
			MarkMask:  allocation.mark.Mask,
		})
	}
	return ownership
}

type planIdentity struct {
	Sets       map[string][]string `json:"sets,omitempty"`
	Rules      []identityRule      `json:"rules,omitempty"`
	KillSwitch []journalKillRule   `json:"killswitch,omitempty"`
	Routes     []identityRoute     `json:"routes,omitempty"`
}

type identityRule struct {
	Family  uint8           `json:"family"`
	Matches []journalMatch  `json:"matches,omitempty"`
	Cgroup  *identityCgroup `json:"cgroup,omitempty"`
	UID     *uint32         `json:"uid,omitempty"`
	Mark    uint32          `json:"mark,omitempty"`
	Bypass  bool            `json:"bypass,omitempty"`
}

type identityCgroup struct {
	Level uint32 `json:"level"`
	ID    uint64 `json:"id"`
}

type identityRoute struct {
	Class     string `json:"class"`
	Table     uint32 `json:"table"`
	Priority  int    `json:"priority"`
	MarkValue uint32 `json:"mark_value"`
	MarkMask  uint32 `json:"mark_mask"`
	Family    uint8  `json:"family"`
	Interface string `json:"interface,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	Source    string `json:"source,omitempty"`
	Protected bool   `json:"protected,omitempty"`
	Blackhole bool   `json:"blackhole,omitempty"`
}

func fingerprintPlan(plan *policyPlan) string {
	if plan == nil {
		return ""
	}
	identity := planIdentity{}
	if len(plan.nft.sets) > 0 {
		identity.Sets = make(map[string][]string, len(plan.nft.sets))
		for name, prefixes := range plan.nft.sets {
			values := make([]string, len(prefixes))
			for i, prefix := range prefixes {
				values[i] = prefix.String()
			}
			sort.Strings(values)
			identity.Sets[string(name)] = values
		}
	}
	for _, rule := range plan.nft.rules {
		item := identityRule{
			Family: uint8(rule.family),
			Mark:   rule.mark,
			Bypass: rule.bypass,
		}
		if rule.cgroup != nil {
			item.Cgroup = &identityCgroup{Level: rule.cgroup.Level, ID: rule.cgroup.ID}
		}
		if rule.uid != nil {
			uid := *rule.uid
			item.UID = &uid
		}
		for _, match := range rule.matches {
			entry := journalMatch{
				Set:      string(match.set),
				Protocol: string(match.protocol),
				Port:     match.port,
			}
			if match.prefix.IsValid() {
				entry.Prefix = match.prefix.String()
			}
			item.Matches = append(item.Matches, entry)
		}
		identity.Rules = append(identity.Rules, item)
	}
	for _, rule := range plan.nft.killswitch {
		persisted := journalKillRule{
			Family:  uint8(rule.family),
			Verdict: uint8(rule.verdict),
		}
		if rule.mark != nil {
			mark := *rule.mark
			persisted.Mark = &mark
		}
		for _, match := range rule.matches {
			entry := journalMatch{
				Set:      string(match.set),
				Protocol: string(match.protocol),
				Port:     match.port,
			}
			if match.prefix.IsValid() {
				entry.Prefix = match.prefix.String()
			}
			persisted.Matches = append(persisted.Matches, entry)
		}
		identity.KillSwitch = append(identity.KillSwitch, persisted)
	}
	appendRoutes := func(routes []classRoute) {
		for _, route := range routes {
			identity.Routes = append(identity.Routes, identityRoute{
				Class:     string(route.class),
				Table:     uint32(route.allocation.table),
				Priority:  int(route.allocation.priority),
				MarkValue: route.allocation.mark.Value,
				MarkMask:  route.allocation.mark.Mask,
				Family:    uint8(route.family),
				Interface: route.target.Interface,
				Gateway:   addrString(route.target.Gateway),
				Source:    addrString(route.target.Source),
				Protected: route.protected,
				Blackhole: route.blackhole,
			})
		}
	}
	appendRoutes(plan.route.classes)
	appendRoutes(plan.route.classes6)

	encoded, err := json.Marshal(identity)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func usedClasses(plan *policyPlan) map[routeClass]bool {
	used := make(map[routeClass]bool, len(splitClasses))
	if plan == nil {
		return used
	}
	for _, route := range plan.route.classes {
		used[route.class] = true
	}
	for _, route := range plan.route.classes6 {
		used[route.class] = true
	}
	return used
}

func killSwitchControlSets(sets map[setName][]netip.Prefix) map[setName][]netip.Prefix {
	control := make(map[setName][]netip.Prefix, 2)
	for _, name := range []setName{setKillSwitchControl4, setKillSwitchControl6} {
		if len(sets[name]) == 0 {
			continue
		}
		control[name] = append([]netip.Prefix(nil), sets[name]...)
	}
	return control
}

// failClosedGuard returns a guard that drops every non-local egress. It does
// not accept protected marks because a failed rollback may have left their
// routing tables incomplete, so accepting them could reach the physical path.
func failClosedGuard(enableIPv6 bool) []nftKillRule {
	rules := compileKillSwitchFamily(config.KillSwitchGlobal, family4,
		nil, nil, allocations{})
	if enableIPv6 {
		rules = append(rules, compileKillSwitchFamily(config.KillSwitchGlobal, family6,
			nil, nil, allocations{})...)
	}
	return rules
}

func (b *Backend) saveJournalLocked(entry *journalEntry) error {
	if b.journal == nil {
		return nil
	}
	if err := b.journal.Save(*entry); err != nil {
		return fmt.Errorf("persist recovery journal: %w", err)
	}
	return nil
}

func (b *Backend) advanceJournalLocked(entry *journalEntry, next JournalState) error {
	if err := entry.transition(next); err != nil {
		return err
	}
	return b.saveJournalLocked(entry)
}

func (b *Backend) clearJournalLocked() error {
	if b.journal == nil {
		return nil
	}
	return b.journal.Clear()
}

func (b *Backend) loadJournalLocked() (journalEntry, error) {
	if b.journal == nil {
		return journalEntry{}, ErrJournalNotFound
	}
	return b.journal.Load()
}

func (b *Backend) retryLocked(ctx context.Context, fn func() error) error {
	attempts := b.retryAttempts
	if attempts < 1 {
		attempts = 1
	}
	delay := b.retryDelay
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if attempt == attempts-1 || !recoveryRetryable(err) {
			return err
		}
		if waitErr := b.waitLocked(ctx, delay); waitErr != nil {
			return waitErr
		}
		delay *= 2
		if delay > maxRecoveryRetryDelay {
			delay = maxRecoveryRetryDelay
		}
	}
	return err
}

func (b *Backend) waitLocked(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	if b.sleep != nil {
		return b.sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func recoveryRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, backend.ErrForeignObject) || errors.Is(err, backend.ErrObjectMismatch) ||
		errors.Is(err, ErrJournalCorrupt) || errors.Is(err, ErrInvalidJournalTransition) {
		return false
	}
	return true
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

func (b *Backend) recordRecoveryIssueLocked(format string, args ...any) {
	b.recoveryIssues = append(b.recoveryIssues, fmt.Sprintf(format, args...))
}

func (b *Backend) resetRecoveryDiagnosticsLocked() {
	b.recoveryIssues = nil
	b.rollbackFailed = false
	b.protectionPreserved = false
}

// RecoveryStatus returns the last structured recovery diagnostics.
func (b *Backend) RecoveryStatus() RecoveryDiagnostics {
	b.mu.Lock()
	defer b.mu.Unlock()

	return RecoveryDiagnostics{
		JournalState:        b.journalState,
		Revision:            b.journalRevision,
		Issues:              append([]string(nil), b.recoveryIssues...),
		RollbackFailed:      b.rollbackFailed,
		ProtectionPreserved: b.protectionPreserved,
		LastError:           b.lastError,
	}
}
