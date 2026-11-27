package domain

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

const (
	// DefaultMaxEntries bounds the number of tracked name/address/action
	// references. Reaching the bound fails the observation closed instead of
	// evicting a live reference.
	DefaultMaxEntries = 65_536
	// DefaultMinUpdateInterval coalesces expiry-refresh updates with the same
	// membership. Membership changes are always pushed.
	DefaultMinUpdateInterval = 250 * time.Millisecond
	// DefaultUpdateTimeout bounds a synchronous kernel set update.
	DefaultUpdateTimeout = 2 * time.Second
)

var (
	// ErrClosed reports an observation on a closed tracker.
	ErrClosed = errors.New("domain tracker is closed")
	// ErrCapacity reports that the bounded reference cache is full.
	ErrCapacity = errors.New("domain tracker reference capacity exceeded")
)

// Updater applies the resolved domain addresses to a backend.
type Updater interface {
	UpdateDomainSets(ctx context.Context, updates []backend.DomainSetUpdate) error
}

// Options configures a Tracker. Zero values are replaced by defaults, except
// ConflictPolicy which defaults to VPN.
type Options struct {
	ConflictPolicy    config.ConflictPolicy
	MaxEntries        int
	MinUpdateInterval time.Duration
	UpdateTimeout     time.Duration
	// Now is injectable for tests. Nil uses time.Now.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.ConflictPolicy == "" {
		o.ConflictPolicy = config.ConflictVPN
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	// A zero interval means the default; a negative value disables coalescing.
	if o.MinUpdateInterval == 0 {
		o.MinUpdateInterval = DefaultMinUpdateInterval
	}
	if o.MinUpdateInterval < 0 {
		o.MinUpdateInterval = 0
	}
	if o.UpdateTimeout <= 0 {
		o.UpdateTimeout = DefaultUpdateTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// AddressConflict describes one address selected by domains with different
// actions and the action chosen by the conflict policy.
type AddressConflict struct {
	Address netip.Addr
	Actions []config.Action
	Domains []string
	Chosen  config.Action
	Policy  config.ConflictPolicy
}

// Diagnostics is a point-in-time copy of the tracker state.
type Diagnostics struct {
	Rules         int
	References    int
	Addresses     int
	Conflicts     []AddressConflict
	RuleConflicts []RuleConflict
	Updates       uint64
	Skipped       uint64
	Dropped       uint64
	Errors        uint64
	MaxEntries    int
}

type refKey struct {
	owner  Name
	addr   netip.Addr
	action config.Action
}

type snapshot struct {
	updates    []backend.DomainSetUpdate
	signature  string
	membership map[config.Action]map[netip.Addr]time.Time
	conflicts  []AddressConflict
	addresses  int
}

// Tracker records observed DNS answers and pushes the resulting address sets.
// All exported methods are safe for concurrent use.
type Tracker struct {
	pushMu sync.Mutex
	mu     sync.Mutex

	updater       Updater
	rules         *Rules
	options       Options
	refs          map[refKey]time.Time
	ruleConflicts []RuleConflict
	last          snapshot
	hasLast       bool
	lastUpdate    time.Time
	updates       uint64
	skipped       uint64
	dropped       uint64
	errors        atomic.Uint64
	closed        bool
}

// NewTracker returns a tracker for the given rules. A nil updater keeps the
// tracker in tracking-only mode, which is useful for diagnostics and tests.
func NewTracker(updater Updater, rules *Rules, options Options) *Tracker {
	if rules == nil {
		rules = NewRules()
	}
	return &Tracker{
		updater: updater,
		rules:   rules,
		options: options.withDefaults(),
		refs:    make(map[refKey]time.Time),
	}
}

// NewTrackerForPolicy compiles the domain rules of a policy and returns a
// tracker whose conflict policy follows the compiled DNS settings.
func NewTrackerForPolicy(updater Updater, compiled *policy.CompiledPolicy, options Options) (*Tracker, error) {
	rules, conflicts, err := RulesFromPolicy(compiled)
	if err != nil {
		return nil, err
	}
	if options.ConflictPolicy == "" && compiled != nil {
		options.ConflictPolicy = compiled.DNS.ConflictPolicy
	}
	tracker := NewTracker(updater, rules, options)
	tracker.ruleConflicts = conflicts
	return tracker, nil
}

// SetRules replaces the matcher and drops references that no longer match the
// current rule action. The resulting set state is pushed before returning.
func (t *Tracker) SetRules(rules *Rules, conflicts []RuleConflict) error {
	if rules == nil {
		rules = NewRules()
	}

	t.pushMu.Lock()
	defer t.pushMu.Unlock()

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.rules = rules
	t.ruleConflicts = conflicts
	t.dropStaleRefsLocked()
	snap := t.buildSnapshotLocked(t.options.Now())
	t.mu.Unlock()

	return t.pushLocked(snap)
}

// ObserveResponse records the A, AAAA and CNAME answers of one DNS response and
// pushes the affected address sets. It returns an error when the kernel sets
// could not be updated before the caller releases the response.
func (t *Tracker) ObserveResponse(req, resp *dns.Msg) error {
	if req == nil || resp == nil {
		return nil
	}

	t.pushMu.Lock()
	defer t.pushMu.Unlock()

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	if t.rules == nil || t.rules.Count() == 0 || len(req.Question) == 0 {
		t.mu.Unlock()
		return nil
	}

	now := t.options.Now()
	t.pruneExpiredLocked(now)

	newKeys := make(map[refKey]struct{})
	overflow := false
	for i := range req.Question {
		question := &req.Question[i]
		name, err := Normalize(question.Name)
		if err != nil {
			continue
		}
		rule, ok := t.rules.Match(name)
		if !ok {
			continue
		}
		addresses := addressesForAnswer(string(name), resp.Answer)
		for _, answer := range addresses {
			if answer.ttl <= 0 {
				continue
			}
			key := refKey{owner: name, addr: answer.addr, action: rule.Action}
			if _, exists := t.refs[key]; !exists {
				if _, pending := newKeys[key]; !pending {
					if len(t.refs)+len(newKeys) >= t.options.MaxEntries {
						overflow = true
						break
					}
					newKeys[key] = struct{}{}
				}
			}
			t.refs[key] = now.Add(answer.ttl)
		}
		if overflow {
			break
		}
	}
	if overflow {
		for key := range newKeys {
			delete(t.refs, key)
		}
		t.dropped++
		t.errors.Add(1)
	}

	snap := t.buildSnapshotLocked(now)
	t.mu.Unlock()

	pushErr := t.pushLocked(snap)
	if overflow {
		return errors.Join(ErrCapacity, pushErr)
	}
	return pushErr
}

// Sweep removes expired references and pushes the resulting sets. Callers run
// it periodically so the tracker state does not retain expired answers.
func (t *Tracker) Sweep() error {
	t.pushMu.Lock()
	defer t.pushMu.Unlock()

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	now := t.options.Now()
	t.pruneExpiredLocked(now)
	snap := t.buildSnapshotLocked(now)
	t.mu.Unlock()

	return t.pushLocked(snap)
}

// Snapshot returns the current desired sets without pushing them.
func (t *Tracker) Snapshot() []backend.DomainSetUpdate {
	t.mu.Lock()
	defer t.mu.Unlock()
	return cloneUpdates(t.buildSnapshotLocked(t.options.Now()).updates)
}

// Diagnostics returns a bounded, deterministic copy of tracker state.
func (t *Tracker) Diagnostics() Diagnostics {
	t.mu.Lock()
	defer t.mu.Unlock()

	snap := t.buildSnapshotLocked(t.options.Now())
	return Diagnostics{
		Rules:         t.rules.Count(),
		References:    len(t.refs),
		Addresses:     snap.addresses,
		Conflicts:     cloneConflicts(snap.conflicts),
		RuleConflicts: SortedRuleConflicts(t.ruleConflicts),
		Updates:       t.updates,
		Skipped:       t.skipped,
		Dropped:       t.dropped,
		Errors:        t.errors.Load(),
		MaxEntries:    t.options.MaxEntries,
	}
}

// Close makes the tracker terminal. It is idempotent.
func (t *Tracker) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	t.refs = nil
	t.rules = nil
}

func (t *Tracker) pruneExpiredLocked(now time.Time) {
	for key, expires := range t.refs {
		if !expires.After(now) {
			delete(t.refs, key)
		}
	}
}

func (t *Tracker) dropStaleRefsLocked() {
	for key := range t.refs {
		rule, ok := t.rules.Match(key.owner)
		if !ok || rule.Action != key.action {
			delete(t.refs, key)
		}
	}
}

func (t *Tracker) pushLocked(snap snapshot) error {
	if t.updater == nil || (!t.hasLast && snap.entryCount() == 0) {
		t.mu.Lock()
		t.last = snap
		t.hasLast = true
		t.lastUpdate = t.options.Now()
		t.mu.Unlock()
		return nil
	}
	if t.hasLast && !t.needsUpdateLocked(snap) {
		t.skipped++
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), t.options.UpdateTimeout)
	defer cancel()
	if err := t.updater.UpdateDomainSets(ctx, cloneUpdates(snap.updates)); err != nil {
		t.errors.Add(1)
		return fmt.Errorf("update domain sets: %w", err)
	}

	t.mu.Lock()
	t.last = snap
	t.hasLast = true
	t.lastUpdate = t.options.Now()
	t.updates++
	t.mu.Unlock()
	return nil
}

// needsUpdateLocked reports whether a snapshot must reach the kernel. A
// membership change or an earlier expiry is always pushed. A later expiry is
// only pushed after MinUpdateInterval, which bounds refresh traffic.
func (t *Tracker) needsUpdateLocked(snap snapshot) bool {
	if snap.signature == t.last.signature {
		return false
	}
	for action, entries := range snap.membership {
		previous, ok := t.last.membership[action]
		if !ok {
			if len(entries) > 0 {
				return true
			}
			continue
		}
		if len(entries) != len(previous) {
			return true
		}
		for addr, expires := range entries {
			old, exists := previous[addr]
			if !exists || expires.Before(old) {
				return true
			}
		}
	}
	for action, previous := range t.last.membership {
		if len(previous) == 0 {
			continue
		}
		if _, ok := snap.membership[action]; !ok {
			return true
		}
	}
	return t.options.Now().Sub(t.lastUpdate) >= t.options.MinUpdateInterval
}

func (t *Tracker) buildSnapshotLocked(now time.Time) snapshot {
	type actionGroup struct {
		expires time.Time
		domains map[Name]struct{}
	}
	groups := make(map[netip.Addr]map[config.Action]*actionGroup)
	for key, expires := range t.refs {
		if !expires.After(now) {
			continue
		}
		byAction, ok := groups[key.addr]
		if !ok {
			byAction = make(map[config.Action]*actionGroup)
			groups[key.addr] = byAction
		}
		group, ok := byAction[key.action]
		if !ok {
			group = &actionGroup{domains: make(map[Name]struct{})}
			byAction[key.action] = group
		}
		if expires.After(group.expires) {
			group.expires = expires
		}
		group.domains[key.owner] = struct{}{}
	}

	entries := map[config.Action][]backend.DomainEntry{
		config.ActionVPN:    nil,
		config.ActionDirect: nil,
		config.ActionBlock:  nil,
	}
	membership := make(map[config.Action]map[netip.Addr]time.Time, len(entries))
	for action := range entries {
		membership[action] = make(map[netip.Addr]time.Time)
	}

	addresses := make([]netip.Addr, 0, len(groups))
	for addr := range groups {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })

	var conflicts []AddressConflict
	for _, addr := range addresses {
		byAction := groups[addr]
		actions := make([]config.Action, 0, len(byAction))
		domains := make(map[Name]struct{})
		var maxExpiry time.Time
		for action, group := range byAction {
			actions = append(actions, action)
			for name := range group.domains {
				domains[name] = struct{}{}
			}
			if group.expires.After(maxExpiry) {
				maxExpiry = group.expires
			}
		}
		sortActions(actions)
		chosen := actions[0]
		if len(actions) > 1 {
			chosen = resolveConflict(actions, t.options.ConflictPolicy)
			conflicts = append(conflicts, AddressConflict{
				Address: addr,
				Actions: actions,
				Domains: sortedNames(domains),
				Chosen:  chosen,
				Policy:  t.options.ConflictPolicy,
			})
		}
		entries[chosen] = append(entries[chosen], backend.DomainEntry{
			Prefix:    netip.PrefixFrom(addr, addr.BitLen()),
			ExpiresAt: maxExpiry,
		})
		membership[chosen][addr] = maxExpiry
	}

	updates := make([]backend.DomainSetUpdate, 0, len(entries))
	for _, action := range []config.Action{config.ActionVPN, config.ActionDirect, config.ActionBlock} {
		list := entries[action]
		sort.Slice(list, func(i, j int) bool {
			return list[i].Prefix.Addr().Less(list[j].Prefix.Addr())
		})
		updates = append(updates, backend.DomainSetUpdate{Action: action, Entries: list})
	}
	return snapshot{
		updates:    updates,
		signature:  signature(updates),
		membership: membership,
		conflicts:  conflicts,
		addresses:  len(groups),
	}
}

func resolveConflict(actions []config.Action, conflictPolicy config.ConflictPolicy) config.Action {
	if containsAction(actions, config.ActionBlock) {
		return config.ActionBlock
	}
	switch conflictPolicy {
	case config.ConflictDirect:
		if containsAction(actions, config.ActionDirect) {
			return config.ActionDirect
		}
	case config.ConflictBlock:
		return config.ActionBlock
	}
	if containsAction(actions, config.ActionVPN) {
		return config.ActionVPN
	}
	if containsAction(actions, config.ActionDirect) {
		return config.ActionDirect
	}
	return actions[0]
}

func containsAction(actions []config.Action, want config.Action) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}

func sortActions(actions []config.Action) {
	order := map[config.Action]int{
		config.ActionVPN:    0,
		config.ActionDirect: 1,
		config.ActionBlock:  2,
	}
	sort.Slice(actions, func(i, j int) bool {
		left, lok := order[actions[i]]
		right, rok := order[actions[j]]
		if !lok || !rok {
			return string(actions[i]) < string(actions[j])
		}
		return left < right
	})
}

func sortedNames(names map[Name]struct{}) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, string(name))
	}
	sort.Strings(out)
	return out
}

func signature(updates []backend.DomainSetUpdate) string {
	var builder strings.Builder
	for _, update := range updates {
		for _, entry := range update.Entries {
			builder.WriteString(string(update.Action))
			builder.WriteByte('|')
			builder.WriteString(entry.Prefix.String())
			builder.WriteByte('|')
			builder.WriteString(entry.ExpiresAt.UTC().Format(time.RFC3339Nano))
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func (s snapshot) entryCount() int {
	count := 0
	for i := range s.updates {
		count += len(s.updates[i].Entries)
	}
	return count
}

func cloneUpdates(updates []backend.DomainSetUpdate) []backend.DomainSetUpdate {
	out := make([]backend.DomainSetUpdate, len(updates))
	for i := range updates {
		out[i].Action = updates[i].Action
		out[i].Entries = append([]backend.DomainEntry(nil), updates[i].Entries...)
	}
	return out
}

func cloneConflicts(conflicts []AddressConflict) []AddressConflict {
	out := make([]AddressConflict, len(conflicts))
	for i := range conflicts {
		out[i] = conflicts[i]
		out[i].Actions = append([]config.Action(nil), conflicts[i].Actions...)
		out[i].Domains = append([]string(nil), conflicts[i].Domains...)
	}
	return out
}

type addressTTL struct {
	addr netip.Addr
	ttl  time.Duration
}

func addressesForAnswer(qname string, answer []dns.RR) []addressTTL {
	type cnameLink struct {
		target Name
		ttl    uint32
	}
	type addressRecord struct {
		addr netip.Addr
		ttl  uint32
	}

	cnames := make(map[Name]cnameLink)
	records := make(map[Name][]addressRecord)
	for _, rr := range answer {
		switch record := rr.(type) {
		case *dns.CNAME:
			owner, err := Normalize(record.Hdr.Name)
			if err != nil {
				continue
			}
			target, err := Normalize(record.Target)
			if err != nil {
				continue
			}
			if _, exists := cnames[owner]; !exists {
				cnames[owner] = cnameLink{target: target, ttl: record.Hdr.Ttl}
			}
		case *dns.A:
			owner, err := Normalize(record.Hdr.Name)
			if err != nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(record.A)
			if !ok {
				continue
			}
			records[owner] = append(records[owner], addressRecord{addr: addr.Unmap(), ttl: record.Hdr.Ttl})
		case *dns.AAAA:
			owner, err := Normalize(record.Hdr.Name)
			if err != nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(record.AAAA)
			if !ok {
				continue
			}
			records[owner] = append(records[owner], addressRecord{addr: addr.Unmap(), ttl: record.Hdr.Ttl})
		}
	}

	start, err := Normalize(qname)
	if err != nil {
		return nil
	}

	seen := make(map[Name]struct{})
	var result []addressTTL
	node := start
	chainTTL := ^uint32(0)
	for {
		if _, ok := seen[node]; ok {
			break
		}
		seen[node] = struct{}{}

		for _, record := range records[node] {
			ttl := record.ttl
			if chainTTL < ttl {
				ttl = chainTTL
			}
			if ttl == 0 {
				continue
			}
			result = append(result, addressTTL{
				addr: record.addr,
				ttl:  time.Duration(ttl) * time.Second,
			})
		}

		link, ok := cnames[node]
		if !ok {
			break
		}
		if link.ttl < chainTTL {
			chainTTL = link.ttl
		}
		node = link.target
	}
	return result
}
