package controller

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

type fakeDNS struct {
	mu sync.Mutex

	observer   clientdns.ResponseObserver
	resolvers  []netip.Prefix
	setCalls   int
	clearCalls int
}

func (d *fakeDNS) SetResponseObserver(observer clientdns.ResponseObserver) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.observer = observer
	d.setCalls++
	if observer == nil {
		d.clearCalls++
	}
}

func (d *fakeDNS) ResolverPrefixes() []netip.Prefix {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netip.Prefix(nil), d.resolvers...)
}

func (d *fakeDNS) current() clientdns.ResponseObserver {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.observer
}

type fakeApplications struct {
	mu sync.Mutex

	scopes         []backend.ApplicationScope
	reconcileCalls int
	closeCalls     int
	err            error
	last           *policy.CompiledPolicy
}

func (a *fakeApplications) Reconcile(
	_ context.Context,
	compiled *policy.CompiledPolicy,
) ([]backend.ApplicationScope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reconcileCalls++
	a.last = compiled
	return append([]backend.ApplicationScope(nil), a.scopes...), a.err
}

func (a *fakeApplications) List() []application.Application {
	return []application.Application{{DesktopID: "test.desktop"}}
}

func (a *fakeApplications) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closeCalls++
	return nil
}

func (a *fakeApplications) calls() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcileCalls, a.closeCalls
}

type fakeLinkReconciler struct {
	mu sync.Mutex

	startCalls int
	stopCalls  int
	startErr   error
}

func (r *fakeLinkReconciler) Start(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startCalls++
	if r.startErr != nil {
		return r.startErr
	}
	return nil
}

func (r *fakeLinkReconciler) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopCalls++
}

func (r *fakeLinkReconciler) calls() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.startCalls, r.stopCalls
}

func fakeResolver(hosts map[string][]string) HostResolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		values, ok := hosts[host]
		if !ok {
			return nil, errors.New("unknown host")
		}
		addrs := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, addr)
		}
		return addrs, nil
	}
}

func completeRuntimeInputs() RuntimeInputs {
	return RuntimeInputs{
		Options: backend.PolicyOptions{
			VPN:    backend.RouteTarget{Interface: "wt0"},
			Direct: backend.RouteTarget{Interface: "eth0"},
		},
		ManagementURL:      "https://mgmt.example.com:443",
		SignalURL:          "https://signal.example.com",
		RelayURLs:          []string{"rel://relay.example.com:3478"},
		STUNHosts:          []string{"stun.example.com"},
		TURNHosts:          []string{"turn.example.com"},
		PeerEndpoints:      []string{"198.51.100.20:51820"},
		PrivatePrefixes:    []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("10.20.0.0/16")},
		PrivateRoutesReady: true,
		DNSResolvers:       []netip.Prefix{netip.MustParsePrefix("100.64.0.53/32")},
		DNSReady:           true,
	}
}

func completeResolver() HostResolver {
	return fakeResolver(map[string][]string{
		"mgmt.example.com":   {"203.0.113.10"},
		"signal.example.com": {"203.0.113.11"},
		"relay.example.com":  {"203.0.113.12"},
		"stun.example.com":   {"203.0.113.13"},
		"turn.example.com":   {"203.0.113.14"},
	})
}

func TestBuildWiringPopulatesConstraintsAndTransport(t *testing.T) {
	wiring, problems := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	require.Empty(t, problems)
	assert.True(t, wiring.TransportConfigured)

	controls := prefixSet(wiring.Constraints.ControlPrefixes)
	for _, want := range []string{
		"203.0.113.10/32",
		"203.0.113.11/32",
		"203.0.113.12/32",
		"203.0.113.13/32",
		"203.0.113.14/32",
		"198.51.100.20/32",
	} {
		assert.Contains(t, controls, netip.MustParsePrefix(want))
	}
	privates := prefixSet(wiring.Constraints.PrivatePrefixes)
	assert.Contains(t, privates, netip.MustParsePrefix("100.64.0.0/10"))
	assert.Contains(t, privates, netip.MustParsePrefix("10.20.0.0/16"))
	assert.Contains(t, prefixSet(wiring.Options.DNSResolvers), netip.MustParsePrefix("100.64.0.53/32"))
}

func TestBuildWiringReportsIncompleteTransport(t *testing.T) {
	inputs := completeRuntimeInputs()
	inputs.PrivateRoutesReady = false
	inputs.DNSReady = false
	inputs.ManagementURL = ""

	wiring, problems := BuildWiring(context.Background(), inputs, completeResolver())
	assert.False(t, wiring.TransportConfigured)
	assert.NotEmpty(t, problems)
}

func TestKillSwitchPreArmHappensBeforeApply(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	ctrl := New(path, Options{
		Backend: backend,
		Runtime: func(context.Context) (Wiring, error) { return wiring, nil },
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	cfg := testConfig()
	cfg.SplitTunnel.KillSwitch = config.KillSwitchGlobal
	_, err := ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.NoError(t, err)

	protectCalls, protected := backend.protection()
	assert.Equal(t, 1, protectCalls)
	require.NotNil(t, protected)
	assert.Equal(t, config.KillSwitchGlobal, protected.KillSwitch)
	order := backend.order()
	require.Contains(t, order, "protect")
	require.Contains(t, order, "apply")
	assert.Less(t, indexOf(order, "protect"), indexOf(order, "apply"))
}

func TestGlobalKillSwitchBecomesAvailableWithCompleteWiring(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	ctrl := New(path, Options{
		Backend: backend,
		Runtime: func(context.Context) (Wiring, error) { return wiring, nil },
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	cfg := testConfig()
	cfg.SplitTunnel.KillSwitch = config.KillSwitchStrict
	_, err := ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.NoError(t, err)
}

func TestClassifierScopesReachBackendAndCloseOnStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	fake := &fakeBackend{}
	applications := &fakeApplications{scopes: []backend.ApplicationScope{{
		Identity:   backend.ApplicationIdentity{DesktopID: "org.example.Editor.desktop"},
		UID:        config.UID(1000),
		CgroupPath: "netbird-split/nb-1000-deadbeef",
	}}}
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	ctrl := New(path, Options{
		Backend:      fake,
		Runtime:      func(context.Context) (Wiring, error) { return wiring, nil },
		Applications: applications,
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	cfg := testConfig()
	cfg.SplitTunnel.Rules = []config.Rule{{
		ID:        "app",
		Name:      "app",
		Enabled:   true,
		Priority:  10,
		MatchMode: config.MatchAll,
		Conditions: []config.Condition{{
			Type:      config.ConditionDesktopID,
			DesktopID: "org.example.Editor.desktop",
		}},
		Action: config.ActionVPN,
	}}
	_, err := ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.NoError(t, err)

	_, options := fake.applied()
	require.Len(t, options.Applications, 1)
	assert.Equal(t, "netbird-split/nb-1000-deadbeef", options.Applications[0].CgroupPath)

	reconciles, _ := applications.calls()
	assert.GreaterOrEqual(t, reconciles, 1)
	require.NoError(t, ctrl.Stop(testContext(t)))
	_, closes := applications.calls()
	assert.Equal(t, 1, closes)
}

func TestDNSObserverLifecycleUpdatesDomainSets(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	dnsRuntime := &fakeDNS{}
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	ctrl := New(path, Options{
		Backend: backend,
		Runtime: func(context.Context) (Wiring, error) { return wiring, nil },
		DNS: func(context.Context) (DNSRuntime, error) {
			return dnsRuntime, nil
		},
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	cfg := testConfig()
	cfg.SplitTunnel.Rules = []config.Rule{{
		ID:        "domain",
		Name:      "domain",
		Enabled:   true,
		Priority:  10,
		MatchMode: config.MatchAll,
		Conditions: []config.Condition{{
			Type:   config.ConditionDomain,
			Domain: "vpn.example.com",
		}},
		Action: config.ActionVPN,
	}}
	_, err := ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.NoError(t, err)
	observer := dnsRuntime.current()
	require.NotNil(t, observer, "a domain policy must attach the tracker")

	request := new(dns.Msg)
	request.SetQuestion("vpn.example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "vpn.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{198, 51, 100, 77},
	}}
	require.NoError(t, observer.ObserveResponse(request, response))

	updates := backend.domains()
	require.NotEmpty(t, updates)
	found := false
	for _, update := range updates {
		if update.Action != config.ActionVPN {
			continue
		}
		for _, entry := range update.Entries {
			if entry.Prefix == netip.MustParsePrefix("198.51.100.77/32") {
				found = true
			}
		}
	}
	assert.True(t, found, "the DNS answer must reach the owned VPN domain set")

	require.NoError(t, ctrl.Stop(testContext(t)))
	assert.Nil(t, dnsRuntime.current(), "stopping the controller must unset the observer")
}

func TestMaintenanceReattachesDNSAfterEngineRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	first := &fakeDNS{}
	second := &fakeDNS{}
	current := first
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	ctrl := New(path, Options{
		Backend: backend,
		Runtime: func(context.Context) (Wiring, error) { return wiring, nil },
		DNS: func(context.Context) (DNSRuntime, error) {
			return current, nil
		},
		MaintenanceInterval: time.Hour,
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	cfg := testConfig()
	cfg.SplitTunnel.Rules = []config.Rule{{
		ID:        "domain",
		Name:      "domain",
		Enabled:   true,
		Priority:  10,
		MatchMode: config.MatchAll,
		Conditions: []config.Condition{{
			Type:   config.ConditionDomain,
			Domain: "vpn.example.com",
		}},
		Action: config.ActionVPN,
	}}
	_, err := ctrl.ApplyConfig(testContext(t), cfg, 0)
	require.NoError(t, err)
	require.NotNil(t, first.current())

	current = second
	ctrl.maintain(testContext(t))

	assert.Nil(t, first.current(), "the stopped DNS server must not keep the observer")
	require.NotNil(t, second.current(), "the restarted DNS server must receive the tracker")
	require.NoError(t, ctrl.Stop(testContext(t)))
	assert.Nil(t, second.current())
}

func TestMaintenanceAppliesPendingStartupPolicyWhenRuntimeAppears(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	stored := newStore(path)
	require.NoError(t, stored.save(document{
		SchemaVersion: storeSchemaVersion,
		Revision:      1,
		Config:        testConfig(),
	}))

	fake := &fakeBackend{}
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	ready := false
	ctrl := New(path, Options{
		Backend: fake,
		Runtime: func(context.Context) (Wiring, error) {
			if !ready {
				return Wiring{}, errors.New("engine is not connected")
			}
			return wiring, nil
		},
		MaintenanceInterval: time.Hour,
	})
	require.Error(t, ctrl.Start(testContext(t)), "the first apply must wait for the live engine")
	_, _, appliedBefore := fake.calls()
	assert.Zero(t, appliedBefore)

	ready = true
	ctrl.maintain(testContext(t))

	_, _, appliedAfter := fake.calls()
	assert.Equal(t, 1, appliedAfter, "the maintenance loop must apply the pending policy")
	status, err := ctrl.Status(testContext(t))
	require.NoError(t, err)
	assert.True(t, status.Running)
}

func TestReconcilerStartsStopsAndReapplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	link := &fakeLinkReconciler{}
	ctrl := New(path, Options{
		Backend:        backend,
		Runtime:        func(context.Context) (Wiring, error) { return wiring, nil },
		LinkReconciler: link,
	})
	require.NoError(t, ctrl.Start(testContext(t)))
	starts, _ := link.calls()
	assert.Equal(t, 1, starts, "the reconciler must start with the controller")

	_, err := ctrl.ApplyConfig(testContext(t), testConfig(), 0)
	require.NoError(t, err)
	_, _, before := backend.calls()

	require.NoError(t, ctrl.Reapply(testContext(t)))
	_, _, after := backend.calls()
	assert.Greater(t, after, before, "a netlink change must reapply the committed policy")

	require.NoError(t, ctrl.Stop(testContext(t)))
	_, stops := link.calls()
	assert.Equal(t, 1, stops)
}

func TestReconcilerStartFailureDoesNotFailDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	wiring, _ := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	link := &fakeLinkReconciler{startErr: errors.New("netlink unavailable")}
	ctrl := New(path, Options{
		Backend:        backend,
		Runtime:        func(context.Context) (Wiring, error) { return wiring, nil },
		LinkReconciler: link,
	})
	require.NoError(t, ctrl.Start(testContext(t)))

	status, err := ctrl.Status(testContext(t))
	require.NoError(t, err)
	assert.Equal(t, "start_failed", status.Diagnostics["reconcile"])
}

func TestDaemonRuntimeKeepsControlAndPrivateRoutesOutOfTunnel(t *testing.T) {
	wiring, problems := BuildWiring(context.Background(), completeRuntimeInputs(), completeResolver())
	require.Empty(t, problems)

	tests := []struct {
		name   string
		config *config.Config
	}{
		{
			name: "default vpn",
			config: &config.Config{
				SchemaVersion: config.CurrentSchemaVersion,
				SplitTunnel: config.SplitTunnel{
					Enabled:       true,
					Mode:          config.ModeCustom,
					DefaultAction: config.ActionVPN,
					KillSwitch:    config.KillSwitchSelective,
					Rules: []config.Rule{{
						ID:        "excluded",
						Name:      "excluded",
						Enabled:   true,
						Priority:  10,
						MatchMode: config.MatchAll,
						Conditions: []config.Condition{{
							Type:   config.ConditionCIDR,
							Prefix: netip.MustParsePrefix("192.168.50.0/24"),
						}},
						Action: config.ActionDirect,
					}},
				},
			},
		},
		{
			name: "exclude mode",
			config: &config.Config{
				SchemaVersion: config.CurrentSchemaVersion,
				SplitTunnel: config.SplitTunnel{
					Enabled:       true,
					Mode:          config.ModeExclude,
					DefaultAction: config.ActionVPN,
					KillSwitch:    config.KillSwitchSelective,
					Rules: []config.Rule{{
						ID:        "excluded",
						Name:      "excluded",
						Enabled:   true,
						Priority:  10,
						MatchMode: config.MatchAll,
						Conditions: []config.Condition{{
							Type:   config.ConditionCIDR,
							Prefix: netip.MustParsePrefix("192.168.50.0/24"),
						}},
						Action: config.ActionDirect,
					}, {
						ID:        "private-direct",
						Name:      "private-direct",
						Enabled:   true,
						Priority:  20,
						MatchMode: config.MatchAll,
						Conditions: []config.Condition{{
							Type:   config.ConditionCIDR,
							Prefix: netip.MustParsePrefix("10.20.0.0/16"),
						}},
						Action: config.ActionDirect,
					}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultConfigFileName)
			backend := &fakeBackend{}
			dnsRuntime := &fakeDNS{}
			ctrl := New(path, Options{
				Backend: backend,
				Runtime: func(context.Context) (Wiring, error) { return wiring, nil },
				DNS: func(context.Context) (DNSRuntime, error) {
					return dnsRuntime, nil
				},
				MaintenanceInterval: time.Hour,
			})
			require.NoError(t, ctrl.Start(testContext(t)))
			_, err := ctrl.ApplyConfig(testContext(t), tt.config, 0)
			require.NoError(t, err)

			compiled, _ := backend.applied()
			require.NotNil(t, compiled)

			assertDecision(t, compiled, "203.0.113.10", config.ActionDirect, policy.LayerControl)
			assertDecision(t, compiled, "203.0.113.12", config.ActionDirect, policy.LayerControl)
			assertDecision(t, compiled, "10.20.1.5", config.ActionVPN, policy.LayerMandatory)
			assertDecision(t, compiled, "100.64.0.8", config.ActionVPN, policy.LayerMandatory)
			assertDecision(t, compiled, "192.168.50.5", config.ActionDirect, policy.LayerRule)
			assertDecision(t, compiled, "8.8.8.8", config.ActionVPN, policy.LayerDefault)
		})
	}
}

func assertDecision(
	t *testing.T,
	compiled *policy.CompiledPolicy,
	destination string,
	action config.Action,
	layer policy.Layer,
) {
	t.Helper()
	decision := compiled.Evaluate(policy.Flow{Destination: netip.MustParseAddr(destination)})
	assert.Equal(t, action, decision.Action, "destination %s", destination)
	assert.Equal(t, layer, decision.Layer, "destination %s", destination)
}

func prefixSet(prefixes []netip.Prefix) map[netip.Prefix]struct{} {
	out := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		out[prefix] = struct{}{}
	}
	return out
}

func indexOf(values []string, want string) int {
	for i, value := range values {
		if value == want {
			return i
		}
	}
	return -1
}
