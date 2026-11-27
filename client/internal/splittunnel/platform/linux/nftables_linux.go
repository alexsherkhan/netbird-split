//go:build linux && !android

package linux

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/google/nftables"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
)

type chainName string
type setName string

const (
	chainClassifyOutput     chainName = "classify_output"
	chainClassifyConnection chainName = "classify_connection"
	chainEnforceOutput      chainName = "enforce_output"
	chainKillswitch         chainName = "killswitch"
)

const (
	setVPN4     setName = "vpn4"
	setVPN6     setName = "vpn6"
	setDirect4  setName = "direct4"
	setDirect6  setName = "direct6"
	setBlocked4 setName = "blocked4"
	setBlocked6 setName = "blocked6"
	setDomains4 setName = "domains4"
	setDomains6 setName = "domains6"
)

const domainSetTimeout = 5 * time.Minute

var ownedRuleUserData = []byte("netbird-split:owned:v1")

type chainSpec struct {
	name     chainName
	chainTyp nftables.ChainType
	hook     nftables.ChainHook
	priority nftables.ChainPriority
}

type setSpec struct {
	name     setName
	keyType  nftables.SetDatatype
	interval bool
	timeout  time.Duration
	comment  string
}

func chainSpecs() []chainSpec {
	return []chainSpec{
		{
			name:     chainClassifyOutput,
			chainTyp: nftables.ChainTypeRoute,
			hook:     *nftables.ChainHookOutput,
			priority: *nftables.ChainPriorityMangle,
		},
		{
			name:     chainClassifyConnection,
			chainTyp: nftables.ChainTypeFilter,
			hook:     *nftables.ChainHookOutput,
			priority: *nftables.ChainPriorityMangle,
		},
		{
			name:     chainEnforceOutput,
			chainTyp: nftables.ChainTypeFilter,
			hook:     *nftables.ChainHookOutput,
			priority: *nftables.ChainPriorityFilter,
		},
		{
			name:     chainKillswitch,
			chainTyp: nftables.ChainTypeFilter,
			hook:     *nftables.ChainHookOutput,
			priority: *nftables.ChainPrioritySecurity,
		},
	}
}

func setSpecs() []setSpec {
	return []setSpec{
		{name: setVPN4, keyType: nftables.TypeIPAddr, interval: true, comment: "split tunnel VPN prefixes, IPv4"},
		{name: setVPN6, keyType: nftables.TypeIP6Addr, interval: true, comment: "split tunnel VPN prefixes, IPv6"},
		{name: setDirect4, keyType: nftables.TypeIPAddr, interval: true, comment: "split tunnel direct prefixes, IPv4"},
		{name: setDirect6, keyType: nftables.TypeIP6Addr, interval: true, comment: "split tunnel direct prefixes, IPv6"},
		{name: setBlocked4, keyType: nftables.TypeIPAddr, interval: true, comment: "split tunnel blocked prefixes, IPv4"},
		{name: setBlocked6, keyType: nftables.TypeIP6Addr, interval: true, comment: "split tunnel blocked prefixes, IPv6"},
		{name: setDomains4, keyType: nftables.TypeIPAddr, timeout: domainSetTimeout, comment: "split tunnel resolved domains, IPv4"},
		{name: setDomains6, keyType: nftables.TypeIP6Addr, timeout: domainSetTimeout, comment: "split tunnel resolved domains, IPv6"},
	}
}

type nftablesManager struct {
	conn         *nftables.Conn
	tableName    string
	table        *nftables.Table
	createdTable bool
}

func newNFTablesManager(tableName string) (*nftablesManager, error) {
	if tableName == "" {
		return nil, fmt.Errorf("nftables table name is empty")
	}
	return &nftablesManager{
		conn:      &nftables.Conn{},
		tableName: tableName,
	}, nil
}

// Ensure creates the dedicated table or reconciles missing owned objects in an
// existing one. It never flushes or replaces objects it did not create.
func (m *nftablesManager) Ensure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	table, found, err := m.findTable()
	if err != nil {
		return err
	}
	if !found {
		return m.createOwnedObjects(ctx)
	}
	m.table = table

	chains, err := m.chainsInTable()
	if err != nil {
		return err
	}
	if err := verifyExistingChains(chains); err != nil {
		return err
	}
	if err := m.verifyRules(chains); err != nil {
		return err
	}

	sets, err := m.conn.GetSets(table)
	if err != nil {
		return fmt.Errorf("list nftables sets: %w", err)
	}
	if err := verifyExistingSets(sets, table); err != nil {
		return err
	}

	return m.addMissing(chains, sets)
}

// Cleanup removes only objects defined by this backend. If the dedicated table
// contains an object the backend does not own, it returns ErrForeignObject and
// leaves everything in place.
func (m *nftablesManager) Cleanup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	table, found, err := m.findTable()
	if err != nil {
		return err
	}
	if !found {
		m.table = nil
		m.createdTable = false
		return nil
	}
	m.table = table

	chains, err := m.chainsInTable()
	if err != nil {
		return err
	}
	if err := verifyExistingChains(chains); err != nil {
		return err
	}
	rules, err := m.rulesByChain(chains)
	if err != nil {
		return err
	}

	sets, err := m.conn.GetSets(table)
	if err != nil {
		return fmt.Errorf("list nftables sets: %w", err)
	}
	if err := verifyExistingSets(sets, table); err != nil {
		return err
	}

	for _, chainRules := range rules {
		for _, rule := range chainRules {
			if err := m.conn.DelRule(rule); err != nil {
				return fmt.Errorf("delete owned rule %d: %w", rule.Handle, err)
			}
		}
	}
	for _, chain := range chains {
		m.conn.DelChain(chain)
	}
	for _, set := range sets {
		m.conn.DelSet(set)
	}
	m.conn.DelTable(table)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("delete owned nftables objects: %w", err)
	}

	m.table = nil
	m.createdTable = false
	return nil
}

// CreatedTable reports whether the last successful Ensure created the table.
func (m *nftablesManager) CreatedTable() bool {
	return m.createdTable
}

// Owned lists the object names this backend is allowed to remove.
func (m *nftablesManager) Owned() backend.OwnedObjects {
	chains := chainSpecs()
	chainNames := make([]string, len(chains))
	for i, spec := range chains {
		chainNames[i] = string(spec.name)
	}

	sets := setSpecs()
	setNames := make([]string, len(sets))
	for i, spec := range sets {
		setNames[i] = string(spec.name)
	}

	return backend.OwnedObjects{
		Table:  m.tableName,
		Chains: chainNames,
		Sets:   setNames,
	}
}

func (m *nftablesManager) findTable() (*nftables.Table, bool, error) {
	tables, err := m.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, false, fmt.Errorf("list inet nftables tables: %w", err)
	}
	for _, table := range tables {
		if table.Name == m.tableName {
			return table, true, nil
		}
	}
	return nil, false, nil
}

func (m *nftablesManager) chainsInTable() ([]*nftables.Chain, error) {
	all, err := m.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, fmt.Errorf("list inet nftables chains: %w", err)
	}

	var chains []*nftables.Chain
	for _, chain := range all {
		if chain.Table != nil && chain.Table.Name == m.tableName {
			chains = append(chains, chain)
		}
	}
	return chains, nil
}

func (m *nftablesManager) rulesByChain(chains []*nftables.Chain) (map[string][]*nftables.Rule, error) {
	rules := make(map[string][]*nftables.Rule, len(chains))
	for _, chain := range chains {
		chainRules, err := m.conn.GetRules(m.table, chain)
		if err != nil {
			return nil, fmt.Errorf("list rules in chain %q: %w", chain.Name, err)
		}
		for _, rule := range chainRules {
			if !isOwnedRule(rule) {
				return nil, fmt.Errorf("rule handle %d in chain %q: %w",
					rule.Handle, chain.Name, backend.ErrForeignObject)
			}
		}
		rules[chain.Name] = chainRules
	}
	return rules, nil
}

func (m *nftablesManager) verifyRules(chains []*nftables.Chain) error {
	_, err := m.rulesByChain(chains)
	return err
}

func (m *nftablesManager) createOwnedObjects(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	table := m.conn.AddTable(&nftables.Table{
		Name:   m.tableName,
		Family: nftables.TableFamilyINet,
	})
	for _, spec := range chainSpecs() {
		m.addChain(table, spec)
	}
	for _, spec := range setSpecs() {
		if err := m.addSet(table, spec); err != nil {
			return err
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("create owned nftables objects: %w", err)
	}

	m.table = table
	m.createdTable = true
	return nil
}

func (m *nftablesManager) addMissing(chains []*nftables.Chain, sets []*nftables.Set) error {
	existingChains := make(map[string]struct{}, len(chains))
	for _, chain := range chains {
		existingChains[chain.Name] = struct{}{}
	}
	existingSets := make(map[string]struct{}, len(sets))
	for _, set := range sets {
		existingSets[set.Name] = struct{}{}
	}

	pending := false
	for _, spec := range chainSpecs() {
		if _, ok := existingChains[string(spec.name)]; ok {
			continue
		}
		m.addChain(m.table, spec)
		pending = true
	}
	for _, spec := range setSpecs() {
		if _, ok := existingSets[string(spec.name)]; ok {
			continue
		}
		if err := m.addSet(m.table, spec); err != nil {
			return err
		}
		pending = true
	}

	if !pending {
		return nil
	}
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("add missing owned nftables objects: %w", err)
	}
	return nil
}

func (m *nftablesManager) addChain(table *nftables.Table, spec chainSpec) {
	priority := spec.priority
	hook := spec.hook
	m.conn.AddChain(&nftables.Chain{
		Name:     string(spec.name),
		Table:    table,
		Type:     spec.chainTyp,
		Hooknum:  &hook,
		Priority: &priority,
	})
}

func (m *nftablesManager) addSet(table *nftables.Table, spec setSpec) error {
	set := &nftables.Set{
		Name:       string(spec.name),
		Table:      table,
		KeyType:    spec.keyType,
		Interval:   spec.interval,
		AutoMerge:  spec.interval,
		HasTimeout: spec.timeout > 0,
		Timeout:    spec.timeout,
		Comment:    spec.comment,
	}
	if err := m.conn.AddSet(set, nil); err != nil {
		return fmt.Errorf("add owned set %q: %w", spec.name, err)
	}
	return nil
}

func verifyExistingChains(chains []*nftables.Chain) error {
	specs := make(map[string]chainSpec, len(chainSpecs()))
	for _, spec := range chainSpecs() {
		specs[string(spec.name)] = spec
	}

	for _, chain := range chains {
		spec, ok := specs[chain.Name]
		if !ok {
			return fmt.Errorf("chain %q: %w", chain.Name, backend.ErrForeignObject)
		}
		if chain.Type != spec.chainTyp ||
			chain.Hooknum == nil || *chain.Hooknum != spec.hook ||
			chain.Priority == nil || *chain.Priority != spec.priority {
			return fmt.Errorf("chain %q has type %q hook %v priority %v, want type %q hook %v priority %v: %w",
				chain.Name, chain.Type, chainHook(chain), chainPriority(chain),
				spec.chainTyp, spec.hook, spec.priority, backend.ErrObjectMismatch)
		}
	}
	return nil
}

func verifyExistingSets(sets []*nftables.Set, table *nftables.Table) error {
	specs := make(map[string]setSpec, len(setSpecs()))
	for _, spec := range setSpecs() {
		specs[string(spec.name)] = spec
	}

	for _, set := range sets {
		if set.Table == nil || set.Table.Name != table.Name {
			continue
		}
		spec, ok := specs[set.Name]
		if !ok {
			return fmt.Errorf("set %q: %w", set.Name, backend.ErrForeignObject)
		}
		timeoutMismatch := spec.timeout > 0 && set.Timeout != spec.timeout
		if set.Interval != spec.interval ||
			set.KeyType.Name != spec.keyType.Name ||
			set.HasTimeout != (spec.timeout > 0) ||
			timeoutMismatch {
			return fmt.Errorf("set %q has interval=%t key=%q timeout=%t/%v, want interval=%t key=%q timeout=%t/%v: %w",
				set.Name, set.Interval, set.KeyType.Name, set.HasTimeout, set.Timeout,
				spec.interval, spec.keyType.Name, spec.timeout > 0, spec.timeout,
				backend.ErrObjectMismatch)
		}
	}
	return nil
}

func chainHook(chain *nftables.Chain) any {
	if chain.Hooknum == nil {
		return "none"
	}
	return *chain.Hooknum
}

func chainPriority(chain *nftables.Chain) any {
	if chain.Priority == nil {
		return "none"
	}
	return *chain.Priority
}

func isOwnedRule(rule *nftables.Rule) bool {
	return bytes.Equal(rule.UserData, ownedRuleUserData)
}
