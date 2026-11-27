package domain

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

type fakeClock struct {
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

type recordingUpdater struct {
	mu    sync.Mutex
	err   error
	calls [][]backend.DomainSetUpdate
}

func (u *recordingUpdater) UpdateDomainSets(_ context.Context, updates []backend.DomainSetUpdate) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != nil {
		return u.err
	}
	u.calls = append(u.calls, cloneUpdates(updates))
	return nil
}

func (u *recordingUpdater) setError(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.err = err
}

func (u *recordingUpdater) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func (u *recordingUpdater) last() []backend.DomainSetUpdate {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.calls) == 0 {
		return nil
	}
	return cloneUpdates(u.calls[len(u.calls)-1])
}

func testRules(t *testing.T, entries ...Rule) *Rules {
	t.Helper()
	rules := NewRules()
	for i, entry := range entries {
		require.True(t, rules.add(entry, i), "duplicate rule %s", entry.Pattern.String())
	}
	return rules
}

func rule(action config.Action, pattern string) Rule {
	if len(pattern) > 2 && pattern[:2] == "*." {
		base, err := NormalizeWildcard(pattern)
		if err != nil {
			panic(err)
		}
		return Rule{Pattern: Pattern{Name: Name(base), Wildcard: true}, Action: action}
	}
	name, err := Normalize(pattern)
	if err != nil {
		panic(err)
	}
	return Rule{Pattern: Pattern{Name: name}, Action: action}
}

func response(t *testing.T, qname string, qtype uint16, answers ...dns.RR) (*dns.Msg, *dns.Msg) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = answers
	return req, resp
}

func aRecord(t *testing.T, name, ip string, ttl uint32) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", dns.Fqdn(name), ttl, ip))
	require.NoError(t, err)
	return rr
}

func aaaaRecord(t *testing.T, name, ip string, ttl uint32) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", dns.Fqdn(name), ttl, ip))
	require.NoError(t, err)
	return rr
}

func cnameRecord(t *testing.T, name, target string, ttl uint32) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", dns.Fqdn(name), ttl, dns.Fqdn(target)))
	require.NoError(t, err)
	return rr
}

func entriesFor(t *testing.T, updates []backend.DomainSetUpdate, action config.Action) []backend.DomainEntry {
	t.Helper()
	for _, update := range updates {
		if update.Action == action {
			return update.Entries
		}
	}
	t.Fatalf("no update for action %q", action)
	return nil
}

func entryAddresses(entries []backend.DomainEntry) []netip.Addr {
	out := make([]netip.Addr, len(entries))
	for i := range entries {
		out[i] = entries[i].Prefix.Addr()
	}
	return out
}

func TestTrackerTracksAAndAAAA(t *testing.T) {
	clock := newFakeClock()
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t, rule(config.ActionVPN, "example.com")), Options{
		Now: clock.Now,
	})

	req, resp := response(t, "example.com", dns.TypeA,
		aRecord(t, "example.com", "192.0.2.10", 60),
		aaaaRecord(t, "example.com", "2001:db8::10", 60))
	require.NoError(t, tracker.ObserveResponse(req, resp))

	updates := updater.last()
	vpn := entriesFor(t, updates, config.ActionVPN)
	require.Len(t, vpn, 2)
	assert.ElementsMatch(t, []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
	}, entryAddresses(vpn))
	for _, entry := range vpn {
		assert.Equal(t, clock.Now().Add(60*time.Second), entry.ExpiresAt)
	}
}

func TestTrackerExpiresOnlyAfterLastReference(t *testing.T) {
	clock := newFakeClock()
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t,
		rule(config.ActionVPN, "a.example"),
		rule(config.ActionVPN, "b.example"),
	), Options{Now: clock.Now})

	reqA, respA := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.20", 10))
	require.NoError(t, tracker.ObserveResponse(reqA, respA))

	clock.Advance(5 * time.Second)
	reqB, respB := response(t, "b.example", dns.TypeA,
		aRecord(t, "b.example", "192.0.2.20", 10))
	require.NoError(t, tracker.ObserveResponse(reqB, respB))

	clock.Advance(6 * time.Second) // a expired, b still live
	require.NoError(t, tracker.Sweep())
	vpn := entriesFor(t, updater.last(), config.ActionVPN)
	require.Len(t, vpn, 1, "the shared address must remain while one reference lives")
	assert.Equal(t, clock.Now().Add(4*time.Second), vpn[0].ExpiresAt)

	clock.Advance(5 * time.Second) // both expired
	require.NoError(t, tracker.Sweep())
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionVPN),
		"the address must be removed when the last reference expires")
}

func TestTrackerFollowsCNAMEChainAndMinimumTTL(t *testing.T) {
	clock := newFakeClock()
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t, rule(config.ActionVPN, "www.example.com")), Options{
		Now: clock.Now,
	})

	req, resp := response(t, "www.example.com", dns.TypeA,
		cnameRecord(t, "www.example.com", "edge.example.com", 5),
		cnameRecord(t, "edge.example.com", "origin.example.com", 4),
		aRecord(t, "origin.example.com", "192.0.2.30", 60))
	require.NoError(t, tracker.ObserveResponse(req, resp))

	vpn := entriesFor(t, updater.last(), config.ActionVPN)
	require.Len(t, vpn, 1)
	assert.Equal(t, netip.MustParseAddr("192.0.2.30"), vpn[0].Prefix.Addr())
	assert.Equal(t, clock.Now().Add(4*time.Second), vpn[0].ExpiresAt,
		"the effective expiry is the minimum TTL along the chain")

	clock.Advance(5 * time.Second)
	require.NoError(t, tracker.Sweep())
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionVPN))
}

func TestTrackerIncompleteCNAMEIsNotTracked(t *testing.T) {
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t, rule(config.ActionVPN, "www.example.com")), Options{})

	req, resp := response(t, "www.example.com", dns.TypeA,
		cnameRecord(t, "www.example.com", "edge.example.com", 5))
	require.NoError(t, tracker.ObserveResponse(req, resp))
	assert.Zero(t, updater.count(), "an incomplete chain must not install a set entry")
}

func TestTrackerSkipsZeroTTL(t *testing.T) {
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t, rule(config.ActionVPN, "example.com")), Options{})

	req, resp := response(t, "example.com", dns.TypeA,
		aRecord(t, "example.com", "192.0.2.40", 0))
	require.NoError(t, tracker.ObserveResponse(req, resp))
	assert.Zero(t, updater.count())
}

func TestTrackerBoundsReferenceCache(t *testing.T) {
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t,
		rule(config.ActionVPN, "a.example"),
		rule(config.ActionVPN, "b.example"),
	), Options{MaxEntries: 1})

	reqA, respA := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.41", 60))
	require.NoError(t, tracker.ObserveResponse(reqA, respA))

	reqB, respB := response(t, "b.example", dns.TypeA,
		aRecord(t, "b.example", "192.0.2.42", 60))
	err := tracker.ObserveResponse(reqB, respB)
	require.ErrorIs(t, err, ErrCapacity)

	diagnostics := tracker.Diagnostics()
	assert.Equal(t, 1, diagnostics.References, "an overflow must not grow the cache")
	assert.Equal(t, uint64(1), diagnostics.Dropped)
}

func TestTrackerUpdateRateCoalescesRefresh(t *testing.T) {
	clock := newFakeClock()
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t,
		rule(config.ActionVPN, "a.example"),
		rule(config.ActionVPN, "b.example"),
	), Options{Now: clock.Now, MinUpdateInterval: time.Second})

	req, resp := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.50", 30))
	require.NoError(t, tracker.ObserveResponse(req, resp))
	require.Equal(t, 1, updater.count())

	clock.Advance(100 * time.Millisecond)
	reqRefresh, respRefresh := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.50", 30))
	require.NoError(t, tracker.ObserveResponse(reqRefresh, respRefresh))
	assert.Equal(t, 1, updater.count(), "a later expiry inside the interval is coalesced")
	assert.Equal(t, uint64(1), tracker.Diagnostics().Skipped)

	reqB, respB := response(t, "b.example", dns.TypeA,
		aRecord(t, "b.example", "192.0.2.51", 30))
	require.NoError(t, tracker.ObserveResponse(reqB, respB))
	assert.Equal(t, 2, updater.count(), "a membership change is always pushed")

	clock.Advance(time.Second)
	reqLater, respLater := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.50", 30))
	require.NoError(t, tracker.ObserveResponse(reqLater, respLater))
	assert.Equal(t, 3, updater.count(), "an expiry refresh is pushed after the interval")
}

func TestTrackerStaleEntriesRemovedFromSets(t *testing.T) {
	clock := newFakeClock()
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t,
		rule(config.ActionVPN, "a.example"),
	), Options{Now: clock.Now})

	req, resp := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.60", 1))
	require.NoError(t, tracker.ObserveResponse(req, resp))
	require.Len(t, entriesFor(t, updater.last(), config.ActionVPN), 1)

	clock.Advance(2 * time.Second)
	require.NoError(t, tracker.Sweep())
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionVPN))
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionDirect))
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionBlock))
}

func TestTrackerSharedIPConflictPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy config.ConflictPolicy
		want   config.Action
	}{
		{name: "vpn", policy: config.ConflictVPN, want: config.ActionVPN},
		{name: "direct", policy: config.ConflictDirect, want: config.ActionDirect},
		{name: "block", policy: config.ConflictBlock, want: config.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updater := &recordingUpdater{}
			tracker := NewTracker(updater, testRules(t,
				rule(config.ActionVPN, "a.example"),
				rule(config.ActionDirect, "b.example"),
			), Options{ConflictPolicy: tt.policy})

			req, resp := response(t, "a.example", dns.TypeA,
				aRecord(t, "a.example", "192.0.2.70", 60))
			require.NoError(t, tracker.ObserveResponse(req, resp))
			req, resp = response(t, "b.example", dns.TypeA,
				aRecord(t, "b.example", "192.0.2.70", 60))
			require.NoError(t, tracker.ObserveResponse(req, resp))

			updates := updater.last()
			for _, action := range []config.Action{config.ActionVPN, config.ActionDirect, config.ActionBlock} {
				entries := entriesFor(t, updates, action)
				if action == tt.want {
					assert.Len(t, entries, 1, "the conflict must choose %s", tt.want)
					continue
				}
				assert.Empty(t, entries, "the conflicting address must not be installed for %s", action)
			}

			diagnostics := tracker.Diagnostics()
			require.Len(t, diagnostics.Conflicts, 1)
			conflict := diagnostics.Conflicts[0]
			assert.Equal(t, netip.MustParseAddr("192.0.2.70"), conflict.Address)
			assert.Equal(t, []config.Action{config.ActionVPN, config.ActionDirect}, conflict.Actions)
			assert.Equal(t, []string{"a.example", "b.example"}, conflict.Domains)
			assert.Equal(t, tt.want, conflict.Chosen)
			assert.Equal(t, tt.policy, conflict.Policy)
		})
	}
}

func TestTrackerBlockWinsSharedIPConflict(t *testing.T) {
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t,
		rule(config.ActionDirect, "a.example"),
		rule(config.ActionBlock, "b.example"),
	), Options{ConflictPolicy: config.ConflictDirect})

	req, resp := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.71", 60))
	require.NoError(t, tracker.ObserveResponse(req, resp))
	req, resp = response(t, "b.example", dns.TypeA,
		aRecord(t, "b.example", "192.0.2.71", 60))
	require.NoError(t, tracker.ObserveResponse(req, resp))

	assert.Len(t, entriesFor(t, updater.last(), config.ActionBlock), 1,
		"a blocked name must not be routed through a less restrictive conflict policy")
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionDirect))
}

func TestTrackerUpdateFailureIsRetried(t *testing.T) {
	updater := &recordingUpdater{}
	updateErr := errors.New("kernel update failed")
	updater.setError(updateErr)
	tracker := NewTracker(updater, testRules(t, rule(config.ActionVPN, "a.example")), Options{})

	req, resp := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.80", 60))
	err := tracker.ObserveResponse(req, resp)
	require.ErrorIs(t, err, updateErr)

	updater.setError(nil)
	require.NoError(t, tracker.ObserveResponse(req, resp))
	assert.Equal(t, 1, updater.count())
}

func TestTrackerConcurrentQueries(t *testing.T) {
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t, rule(config.ActionVPN, "*.example")), Options{})

	const queries = 50
	var wg sync.WaitGroup
	for i := 0; i < queries; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("q%d.example", i)
			req, resp := response(t, name, dns.TypeA,
				aRecord(t, name, fmt.Sprintf("192.0.2.%d", i+1), 60))
			assert.NoError(t, tracker.ObserveResponse(req, resp))
		}(i)
	}
	wg.Wait()

	diagnostics := tracker.Diagnostics()
	assert.Equal(t, queries, diagnostics.References)
	assert.Equal(t, queries, diagnostics.Addresses)
	assert.Equal(t, queries, len(entryAddresses(entriesFor(t, updater.last(), config.ActionVPN))))
}

func TestTrackerSetRulesDropsStaleReferences(t *testing.T) {
	updater := &recordingUpdater{}
	tracker := NewTracker(updater, testRules(t, rule(config.ActionVPN, "a.example")), Options{})

	req, resp := response(t, "a.example", dns.TypeA,
		aRecord(t, "a.example", "192.0.2.90", 60))
	require.NoError(t, tracker.ObserveResponse(req, resp))
	require.Len(t, entriesFor(t, updater.last(), config.ActionVPN), 1)

	require.NoError(t, tracker.SetRules(testRules(t, rule(config.ActionDirect, "a.example")), nil))
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionVPN),
		"a rule action change must not leave the old set entry behind")
	assert.Empty(t, entriesFor(t, updater.last(), config.ActionDirect),
		"the new action only applies after a fresh observation")
}

func TestTrackerCloseIsIdempotent(t *testing.T) {
	tracker := NewTracker(&recordingUpdater{}, NewRules(), Options{})
	tracker.Close()
	tracker.Close()

	req, resp := response(t, "a.example", dns.TypeA)
	require.ErrorIs(t, tracker.ObserveResponse(req, resp), ErrClosed)
}
