//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

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
	sets  map[setName][]netip.Prefix
	rules []nftRule
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

	var classify *nftables.Chain
	for _, chain := range chains {
		if chain.Name == string(chainClassifyOutput) {
			classify = chain
			break
		}
	}
	if classify == nil {
		return fmt.Errorf("owned chain %q is missing", chainClassifyOutput)
	}

	sets, err := m.policySets()
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
		m.conn.AddRule(&nftables.Rule{
			Table:    m.table,
			Chain:    classify,
			Exprs:    exprs,
			UserData: ownedRuleUserData,
		})
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("apply owned nftables policy: %w", err)
	}
	return nil
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

	sets, err := m.policySets()
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

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("clear owned nftables policy: %w", err)
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

func (m *nftablesManager) policySets() (map[setName]*nftables.Set, error) {
	sets, err := m.conn.GetSets(m.table)
	if err != nil {
		return nil, fmt.Errorf("list nftables sets: %w", err)
	}

	owned := make(map[setName]*nftables.Set, len(policySetNames()))
	for _, set := range sets {
		name := setName(set.Name)
		for _, wanted := range policySetNames() {
			if name == wanted {
				owned[wanted] = set
			}
		}
	}
	for _, name := range policySetNames() {
		if owned[name] == nil {
			return nil, fmt.Errorf("owned set %q is missing", name)
		}
	}
	return owned, nil
}

func nftRuleExprs(rule nftRule, sets map[setName]*nftables.Set) ([]expr.Any, error) {
	// An inet table sees both families, so every rule has to state which one it
	// applies to. Without the guard an IPv4 rule would also match IPv6 traffic.
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(rule.family.nfproto()),
		},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}

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

	for _, match := range rule.matches {
		switch {
		case match.set != "":
			set := sets[match.set]
			if set == nil {
				return nil, fmt.Errorf("owned set %q is missing", match.set)
			}
			if setFamily(match.set) != rule.family {
				return nil, fmt.Errorf("set %q does not belong to %v rules",
					match.set, rule.family)
			}
			exprs = append(exprs,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       destinationOffset(rule.family),
					Len:          addressLength(rule.family),
				},
				&expr.Lookup{SourceRegister: 1, SetID: set.ID, SetName: set.Name},
			)
		case match.prefix.IsValid():
			if familyOfPrefix(match.prefix) != rule.family {
				return nil, fmt.Errorf("prefix %s does not belong to %v rules",
					match.prefix, rule.family)
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

const (
	ipv4AddressLength       = 4
	ipv4DestinationOffset   = 16
	ipv6AddressLength       = 16
	ipv6DestinationOffset   = 24
	ipv4TransportPortOffset = 2
)

func setFamily(name setName) nftFamily {
	switch name {
	case setVPN6, setDirect6, setBlocked6, setExit6:
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
