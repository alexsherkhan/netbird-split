//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

// nftFamily is the address family a classification rule matches. The inet
// table sees both families, so every rule carries an explicit family guard.
type nftFamily uint8

const (
	family4 nftFamily = iota
	family6
)

func (f nftFamily) nfproto() uint32 {
	if f == family6 {
		return unix.NFPROTO_IPV6
	}
	return unix.NFPROTO_IPV4
}

func (f nftFamily) String() string {
	if f == family6 {
		return "IPv6"
	}
	return "IPv4"
}

// nftPolicy is the nftables half of a compiled policy. It is deliberately
// logical rather than a list of raw netlink expressions so policy compilation
// stays testable without a kernel.
type nftPolicy struct {
	sets       map[setName][]netip.Prefix
	rules      []nftRule
	killswitch []nftKillRule
}

// nftRule is one ordered classification rule. All matches must hold, then the
// mark is applied and the chain returns. Bypass rules return without changing
// the mark.
type nftRule struct {
	family  nftFamily
	matches []nftMatch
	cgroup  *nftCgroupMatch
	uid     *uint32
	mark    uint32
	bypass  bool
}

// nftMatch is one conjunctive match inside an nftRule.
type nftMatch struct {
	set      setName
	prefix   netip.Prefix
	protocol config.Protocol
	port     uint16
}

func policySetNames() []setName {
	return []setName{
		setVPN4, setDirect4, setBlocked4, setExit4,
		setVPN6, setDirect6, setBlocked6, setExit6,
		setKillSwitchControl4, setKillSwitchControl6,
	}
}

func (m *nftablesManager) ApplyPolicy(ctx context.Context, policy nftPolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.table == nil {
		return errors.New("nftables table is not initialized")
	}

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
	if err := m.verifySets(); err != nil {
		return err
	}

	var classify, killswitch *nftables.Chain
	for _, chain := range chains {
		switch chain.Name {
		case string(chainClassifyOutput):
			classify = chain
		case string(chainKillswitch):
			killswitch = chain
		}
	}
	if classify == nil {
		return fmt.Errorf("owned chain %q is missing", chainClassifyOutput)
	}
	if len(policy.killswitch) > 0 && killswitch == nil {
		return fmt.Errorf("owned chain %q is missing", chainKillswitch)
	}

	sets, err := m.ownedSets()
	if err != nil {
		return err
	}

	for _, chainRules := range rules {
		for _, rule := range chainRules {
			if err := m.conn.DelRule(rule); err != nil {
				return fmt.Errorf("delete owned rule %d: %w", rule.Handle, err)
			}
		}
	}
	for _, name := range policySetNames() {
		m.conn.FlushSet(sets[name])
	}
	for _, name := range domainSetNames() {
		m.conn.FlushSet(sets[name])
	}
	for _, name := range policySetNames() {
		prefixes := policy.sets[name]
		if len(prefixes) == 0 {
			continue
		}
		if err := m.conn.SetAddElements(sets[name], prefixSetElements(prefixes)); err != nil {
			return fmt.Errorf("add prefixes to set %q: %w", name, err)
		}
	}
	for i := range policy.rules {
		exprs, err := nftRuleExprs(policy.rules[i], sets)
		if err != nil {
			return err
		}
		exprs = withClassificationCounter(policy.rules[i], exprs)
		m.conn.AddRule(&nftables.Rule{
			Table:    m.table,
			Chain:    classify,
			Exprs:    exprs,
			UserData: ownedRuleUserData,
		})
	}
	for i := range policy.killswitch {
		exprs, err := nftKillRuleExprs(policy.killswitch[i], sets)
		if err != nil {
			return err
		}
		m.conn.AddRule(&nftables.Rule{
			Table:    m.table,
			Chain:    killswitch,
			Exprs:    exprs,
			UserData: ownedRuleUserData,
		})
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("apply owned nftables policy: %w", err)
	}
	return nil
}

// ApplyKillSwitch replaces the kill switch rules without touching the
// classification rules or the protected routing tables. It is the pre-arm path
// a caller uses before managed traffic is applied, and repeated calls are
// idempotent. An empty rule set clears the chain.
func (m *nftablesManager) ApplyKillSwitch(
	ctx context.Context,
	controlSets map[setName][]netip.Prefix,
	rules []nftKillRule,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.table == nil {
		return errors.New("nftables table is not initialized")
	}
	if err := m.verifySets(); err != nil {
		return err
	}
	chains, err := m.chainsInTable()
	if err != nil {
		return err
	}
	if err := verifyExistingChains(chains); err != nil {
		return err
	}
	chainRules, err := m.rulesByChain(chains)
	if err != nil {
		return err
	}

	var killswitch *nftables.Chain
	for _, chain := range chains {
		if chain.Name == string(chainKillswitch) {
			killswitch = chain
			break
		}
	}
	if killswitch == nil {
		return fmt.Errorf("owned chain %q is missing", chainKillswitch)
	}
	sets, err := m.ownedSets()
	if err != nil {
		return err
	}

	for _, rule := range chainRules[string(chainKillswitch)] {
		if err := m.conn.DelRule(rule); err != nil {
			return fmt.Errorf("delete owned kill switch rule %d: %w", rule.Handle, err)
		}
	}
	for _, name := range []setName{setKillSwitchControl4, setKillSwitchControl6} {
		m.conn.FlushSet(sets[name])
		if len(controlSets[name]) == 0 {
			continue
		}
		if err := m.conn.SetAddElements(sets[name], prefixSetElements(controlSets[name])); err != nil {
			return fmt.Errorf("add kill switch control prefixes to set %q: %w", name, err)
		}
	}
	for i := range rules {
		exprs, err := nftKillRuleExprs(rules[i], sets)
		if err != nil {
			return err
		}
		m.conn.AddRule(&nftables.Rule{
			Table:    m.table,
			Chain:    killswitch,
			Exprs:    exprs,
			UserData: ownedRuleUserData,
		})
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("apply owned kill switch rules: %w", err)
	}
	return nil
}

// VerifyPolicy confirms the observable kernel state matches the intended
// policy: owned chains and sets are present, every rule is owned, and the
// classification and kill switch rule counts match. A foreign object makes the
// verification fail instead of being removed.
func (m *nftablesManager) VerifyPolicy(ctx context.Context, policy nftPolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	table, found, err := m.findTable()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("owned table %q is missing", m.tableName)
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
	if err := m.verifySets(); err != nil {
		return err
	}
	if _, err := m.ownedSets(); err != nil {
		return err
	}

	if got, want := len(rules[string(chainClassifyOutput)]), len(policy.rules); got != want {
		return fmt.Errorf("owned classification rules %d, want %d", got, want)
	}
	if got, want := len(rules[string(chainKillswitch)]), len(policy.killswitch); got != want {
		return fmt.Errorf("owned kill switch rules %d, want %d", got, want)
	}
	return nil
}

// Inspect reports only the owned nftables state. It refuses to continue when
// the owned table contains a foreign chain, set or rule.
func (m *nftablesManager) Inspect(ctx context.Context) (nftObservation, error) {
	if err := ctx.Err(); err != nil {
		return nftObservation{}, err
	}
	table, found, err := m.findTable()
	if err != nil {
		return nftObservation{}, err
	}
	if !found {
		return nftObservation{}, nil
	}
	m.table = table

	chains, err := m.chainsInTable()
	if err != nil {
		return nftObservation{}, err
	}
	if err := verifyExistingChains(chains); err != nil {
		return nftObservation{}, err
	}
	rules, err := m.rulesByChain(chains)
	if err != nil {
		return nftObservation{}, err
	}
	sets, err := m.conn.GetSets(table)
	if err != nil {
		return nftObservation{}, fmt.Errorf("list nftables sets: %w", err)
	}
	if err := verifyExistingSets(sets, table); err != nil {
		return nftObservation{}, err
	}

	observation := nftObservation{TablePresent: true}
	for _, chain := range chains {
		observation.Chains = append(observation.Chains, chain.Name)
	}
	for _, set := range sets {
		observation.Sets = append(observation.Sets, set.Name)
	}
	observation.ClassifyRules = len(rules[string(chainClassifyOutput)])
	observation.KillSwitchRules = len(rules[string(chainKillswitch)])
	return observation, nil
}

func (m *nftablesManager) ClearPolicy(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if m.table == nil {
		table, found, err := m.findTable()
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		m.table = table
	}

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
	if err := m.verifySets(); err != nil {
		return err
	}

	sets, err := m.ownedSets()
	if err != nil {
		return err
	}

	for _, chainRules := range rules {
		for _, rule := range chainRules {
			if err := m.conn.DelRule(rule); err != nil {
				return fmt.Errorf("delete owned rule %d: %w", rule.Handle, err)
			}
		}
	}
	for _, name := range policySetNames() {
		m.conn.FlushSet(sets[name])
	}
	for _, name := range domainSetNames() {
		m.conn.FlushSet(sets[name])
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("clear owned nftables policy: %w", err)
	}
	return nil
}

// ApplyDomainSets replaces every owned domain timeout set with the supplied
// entries. The whole replacement flushes in one batch so a stale address cannot
// survive a shorter TTL or a policy change.
func (m *nftablesManager) ApplyDomainSets(ctx context.Context, updates []backend.DomainSetUpdate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.table == nil {
		return errors.New("nftables table is not initialized")
	}
	if err := m.verifySets(); err != nil {
		return err
	}

	sets, err := m.ownedSets()
	if err != nil {
		return err
	}
	for _, name := range domainSetNames() {
		m.conn.FlushSet(sets[name])
	}

	now := time.Now()
	elements := make(map[setName][]nftables.SetElement, len(domainSetNames()))
	for i := range updates {
		update := &updates[i]
		for _, entry := range update.Entries {
			family := familyOfPrefix(entry.Prefix)
			set, ok := domainSetForAction(update.Action, family)
			if !ok {
				return fmt.Errorf("no owned domain set for action %q family %v",
					update.Action, family)
			}
			timeout := domainSetTimeout
			if !entry.ExpiresAt.IsZero() {
				timeout = entry.ExpiresAt.Sub(now)
				if timeout <= 0 {
					continue
				}
				// A zero millisecond value would be encoded as no timeout.
				if timeout < time.Millisecond {
					timeout = time.Millisecond
				}
			}
			elements[set] = append(elements[set], nftables.SetElement{
				Key:     entry.Prefix.Addr().AsSlice(),
				Timeout: timeout,
			})
		}
	}

	for _, name := range domainSetNames() {
		if len(elements[name]) == 0 {
			continue
		}
		if err := m.conn.SetAddElements(sets[name], elements[name]); err != nil {
			return fmt.Errorf("add resolved addresses to set %q: %w", name, err)
		}
	}
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("apply owned domain sets: %w", err)
	}
	return nil
}

func (m *nftablesManager) verifySets() error {
	sets, err := m.conn.GetSets(m.table)
	if err != nil {
		return fmt.Errorf("list nftables sets: %w", err)
	}
	return verifyExistingSets(sets, m.table)
}

func (m *nftablesManager) ownedSets() (map[setName]*nftables.Set, error) {
	sets, err := m.conn.GetSets(m.table)
	if err != nil {
		return nil, fmt.Errorf("list nftables sets: %w", err)
	}

	wanted := append(policySetNames(), domainSetNames()...)
	owned := make(map[setName]*nftables.Set, len(wanted))
	for _, set := range sets {
		name := setName(set.Name)
		for _, expected := range wanted {
			if name == expected {
				owned[expected] = set
			}
		}
	}
	for _, name := range wanted {
		if owned[name] == nil {
			return nil, fmt.Errorf("owned set %q is missing", name)
		}
	}
	return owned, nil
}

func nftRuleExprs(rule nftRule, sets map[setName]*nftables.Set) ([]expr.Any, error) {
	// An inet table sees both families, so every rule has to state which one it
	// applies to. Without the guard an IPv4 rule would also match IPv6 traffic.
	exprs := familyGuardExprs(rule.family)
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	)

	if rule.cgroup != nil {
		exprs = append(exprs,
			&expr.Socket{
				Key:      expr.SocketKeyCgroupv2,
				Level:    rule.cgroup.Level,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint64(rule.cgroup.ID),
			},
		)
	}
	if rule.uid != nil {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(*rule.uid),
			},
		)
	}

	matches, err := nftMatchExprs(rule.family, rule.matches, sets)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, matches...)

	if rule.bypass {
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictReturn})
		return exprs, nil
	}

	exprs = append(exprs,
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(rule.mark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		&expr.Verdict{Kind: expr.VerdictReturn},
	)
	return exprs, nil
}

// nftKillRuleExprs compiles one kill switch rule. Kill switch rules run after
// classification, so they match the mark the route chain already set instead
// of requiring the mark to be zero.
func nftKillRuleExprs(rule nftKillRule, sets map[setName]*nftables.Set) ([]expr.Any, error) {
	exprs := familyGuardExprs(rule.family)
	if rule.mark != nil {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(*rule.mark),
			},
		)
	}

	matches, err := nftMatchExprs(rule.family, rule.matches, sets)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, matches...)

	kind := expr.VerdictReturn
	switch rule.verdict {
	case verdictAccept:
		kind = expr.VerdictAccept
	case verdictDrop:
		kind = expr.VerdictDrop
	}
	return append(exprs, &expr.Verdict{Kind: kind}), nil
}

func familyGuardExprs(family nftFamily) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(family.nfproto()),
		},
	}
}

func nftMatchExprs(
	family nftFamily,
	matches []nftMatch,
	sets map[setName]*nftables.Set,
) ([]expr.Any, error) {
	var exprs []expr.Any
	for _, match := range matches {
		switch {
		case match.set != "":
			set := sets[match.set]
			if set == nil {
				return nil, fmt.Errorf("owned set %q is missing", match.set)
			}
			if setFamily(match.set) != family {
				return nil, fmt.Errorf("set %q does not belong to %v rules",
					match.set, family)
			}
			exprs = append(exprs,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       destinationOffset(family),
					Len:          addressLength(family),
				},
				&expr.Lookup{SourceRegister: 1, SetID: set.ID, SetName: set.Name},
			)
		case match.prefix.IsValid():
			if familyOfPrefix(match.prefix) != family {
				return nil, fmt.Errorf("prefix %s does not belong to %v rules",
					match.prefix, family)
			}
			exprs = append(exprs, prefixExprs(match.prefix)...)
		}

		if match.protocol != "" {
			protocolExprs, err := protocolPortExprs(match.protocol, match.port)
			if err != nil {
				return nil, err
			}
			exprs = append(exprs, protocolExprs...)
		}
	}
	return exprs, nil
}

const (
	ipv4AddressLength       = 4
	ipv4DestinationOffset   = 16
	ipv6AddressLength       = 16
	ipv6DestinationOffset   = 24
	ipv4TransportPortOffset = 2
)

func setFamily(name setName) nftFamily {
	switch name {
	case setVPN6, setDirect6, setBlocked6, setExit6,
		setKillSwitchControl6,
		setDomains6, setDomainDirect6, setDomainBlock6:
		return family6
	default:
		return family4
	}
}

func addressLength(family nftFamily) uint32 {
	if family == family6 {
		return ipv6AddressLength
	}
	return ipv4AddressLength
}

func destinationOffset(family nftFamily) uint32 {
	if family == family6 {
		return ipv6DestinationOffset
	}
	return ipv4DestinationOffset
}

func prefixExprs(prefix netip.Prefix) []expr.Any {
	if familyOfPrefix(prefix) == family6 {
		return ipv6PrefixExprs(prefix)
	}
	return ipv4PrefixExprs(prefix)
}

func ipv4PrefixExprs(prefix netip.Prefix) []expr.Any {
	return prefixExprsFor(prefix, family4)
}

func ipv6PrefixExprs(prefix netip.Prefix) []expr.Any {
	return prefixExprsFor(prefix, family6)
}

func prefixExprsFor(prefix netip.Prefix, family nftFamily) []expr.Any {
	addr := prefix.Masked().Addr()
	length := addressLength(family)
	payload := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       destinationOffset(family),
		Len:          length,
	}
	bits := addr.BitLen()
	if prefix.Bits() == bits {
		return []expr.Any{
			payload,
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()},
		}
	}

	return []expr.Any{
		payload,
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            length,
			Mask:           net.CIDRMask(prefix.Bits(), bits),
			Xor:            make([]byte, length),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()},
	}
}

func protocolPortExprs(protocol config.Protocol, port uint16) ([]expr.Any, error) {
	var number byte
	switch protocol {
	case config.ProtocolTCP:
		number = unix.IPPROTO_TCP
	case config.ProtocolUDP:
		number = unix.IPPROTO_UDP
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	if port == 0 {
		return nil, errors.New("protocol port must not be zero")
	}

	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{number}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       ipv4TransportPortOffset,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}, nil
}

func prefixSetElements(prefixes []netip.Prefix) []nftables.SetElement {
	elements := make([]nftables.SetElement, 0, len(prefixes)*2)
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		first := prefix.Addr()
		last := prefixLastKey(prefix)
		elements = append(elements,
			nftables.SetElement{Key: first.AsSlice()},
			nftables.SetElement{Key: last, IntervalEnd: true},
		)
	}
	return elements
}

func prefixLastKey(prefix netip.Prefix) []byte {
	addr := prefix.Masked().Addr()
	length := addr.BitLen() / 8
	last := addr.AsSlice()
	if prefix.Bits() == 0 {
		return make([]byte, length)
	}

	for bit := prefix.Bits(); bit < addr.BitLen(); bit++ {
		last[bit/8] |= 1 << (7 - bit%8)
	}
	for i := len(last) - 1; i >= 0; i-- {
		last[i]++
		if last[i] != 0 {
			return last
		}
	}
	return make([]byte, length)
}
