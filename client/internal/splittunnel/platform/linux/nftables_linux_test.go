//go:build linux && !android

package linux

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
)

func TestNFTablesDefaultTableName(t *testing.T) {
	assert.Equal(t, "netbird_split", defaultTableName,
		"the dedicated table name is part of the integration contract")
}

func TestNFTablesCatalogIsCompleteAndUnique(t *testing.T) {
	chains := chainSpecs()
	require.Len(t, chains, 4)

	chainNames := make(map[chainName]struct{}, len(chains))
	for _, spec := range chains {
		assert.NotEmpty(t, spec.name)
		assert.NotEmpty(t, spec.chainTyp)
		_, duplicate := chainNames[spec.name]
		assert.False(t, duplicate, "chain %q is defined twice", spec.name)
		chainNames[spec.name] = struct{}{}
	}
	for _, name := range []chainName{
		chainClassifyOutput,
		chainClassifyConnection,
		chainEnforceOutput,
		chainKillswitch,
	} {
		_, ok := chainNames[name]
		assert.True(t, ok, "chain %q must be owned", name)
	}

	sets := setSpecs()
	require.Len(t, sets, 10)
	setNames := make(map[setName]struct{}, len(sets))
	for _, spec := range sets {
		assert.NotEmpty(t, spec.name)
		_, duplicate := setNames[spec.name]
		assert.False(t, duplicate, "set %q is defined twice", spec.name)
		setNames[spec.name] = struct{}{}
	}
	for _, name := range []setName{
		setVPN4, setVPN6,
		setDirect4, setDirect6,
		setBlocked4, setBlocked6,
		setExit4, setExit6,
		setDomains4, setDomains6,
	} {
		_, ok := setNames[name]
		assert.True(t, ok, "set %q must be owned", name)
	}
}

func TestNFTablesChainHooksAndPriorities(t *testing.T) {
	specs := make(map[chainName]chainSpec, len(chainSpecs()))
	for _, spec := range chainSpecs() {
		specs[spec.name] = spec
	}

	classify := specs[chainClassifyOutput]
	assert.Equal(t, nftables.ChainTypeRoute, classify.chainTyp,
		"classification must use a route-type output hook")
	assert.Equal(t, *nftables.ChainHookOutput, classify.hook)
	assert.Equal(t, *nftables.ChainPriorityMangle, classify.priority)

	connection := specs[chainClassifyConnection]
	assert.Equal(t, nftables.ChainTypeFilter, connection.chainTyp)
	assert.Equal(t, *nftables.ChainPriorityMangle, connection.priority)

	enforce := specs[chainEnforceOutput]
	assert.Equal(t, *nftables.ChainPriorityFilter, enforce.priority)

	killswitch := specs[chainKillswitch]
	assert.Equal(t, *nftables.ChainPrioritySecurity, killswitch.priority,
		"killswitch must run after classification and enforcement")
}

func TestNFTablesIntervalAndTimeoutSets(t *testing.T) {
	specs := make(map[setName]setSpec, len(setSpecs()))
	for _, spec := range setSpecs() {
		specs[spec.name] = spec
	}

	for _, name := range []setName{
		setVPN4, setVPN6, setDirect4, setDirect6, setBlocked4, setBlocked6,
	} {
		spec := specs[name]
		assert.True(t, spec.interval, "prefix set %q must use intervals", name)
		assert.Zero(t, spec.timeout, "policy prefix set %q must not expire", name)
	}

	assert.Equal(t, nftables.TypeIPAddr, specs[setVPN4].keyType)
	assert.Equal(t, nftables.TypeIP6Addr, specs[setVPN6].keyType)
	assert.False(t, specs[setDomains4].interval, "domain address sets are not interval sets")
	assert.True(t, specs[setDomains4].timeout > 0, "domain address sets must use timeouts")
	assert.True(t, specs[setDomains6].timeout > 0, "domain address sets must use timeouts")
}

func TestNewNFTablesManagerRejectsEmptyTable(t *testing.T) {
	_, err := newNFTablesManager("")
	require.Error(t, err)
}

func TestNFTablesOwnedObjects(t *testing.T) {
	manager, err := newNFTablesManager(defaultTableName)
	require.NoError(t, err)

	owned := manager.Owned()
	assert.Equal(t, defaultTableName, owned.Table)
	assert.Len(t, owned.Chains, 4)
	assert.Len(t, owned.Sets, 10)
}

func TestVerifyExistingChains(t *testing.T) {
	spec := chainSpecs()[0]
	priority := spec.priority
	hook := spec.hook
	matching := []*nftables.Chain{{
		Name:     string(spec.name),
		Type:     spec.chainTyp,
		Hooknum:  &hook,
		Priority: &priority,
	}}
	assert.NoError(t, verifyExistingChains(matching))

	foreign := []*nftables.Chain{{Name: "someone_else"}}
	require.ErrorIs(t, verifyExistingChains(foreign), backend.ErrForeignObject)

	wrongPriority := *nftables.ChainPriorityFilter
	mismatch := []*nftables.Chain{{
		Name:     string(spec.name),
		Type:     spec.chainTyp,
		Hooknum:  &hook,
		Priority: &wrongPriority,
	}}
	require.ErrorIs(t, verifyExistingChains(mismatch), backend.ErrObjectMismatch)
}

func TestVerifyExistingSets(t *testing.T) {
	table := &nftables.Table{Name: defaultTableName, Family: nftables.TableFamilyINet}

	vpn4 := setSpecs()[0]
	matching := []*nftables.Set{{
		Name:     string(vpn4.name),
		Table:    table,
		KeyType:  vpn4.keyType,
		Interval: vpn4.interval,
	}}
	assert.NoError(t, verifyExistingSets(matching, table))

	foreign := []*nftables.Set{{
		Name:  "someone_else",
		Table: table,
	}}
	require.ErrorIs(t, verifyExistingSets(foreign, table), backend.ErrForeignObject)

	var domains setSpec
	for _, spec := range setSpecs() {
		if spec.name == setDomains4 {
			domains = spec
		}
	}
	mismatch := []*nftables.Set{{
		Name:       string(domains.name),
		Table:      table,
		KeyType:    domains.keyType,
		HasTimeout: false,
	}}
	require.ErrorIs(t, verifyExistingSets(mismatch, table), backend.ErrObjectMismatch)
}

func TestOwnedRuleMarker(t *testing.T) {
	assert.True(t, isOwnedRule(&nftables.Rule{UserData: ownedRuleUserData}))
	assert.False(t, isOwnedRule(&nftables.Rule{}))
	assert.False(t, isOwnedRule(&nftables.Rule{UserData: []byte("someone-else")}))
}
