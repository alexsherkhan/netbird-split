//go:build linux && !android && privileged

package linux

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
)

func TestNFTablesManagerLifecycleInContainer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}

	tableName := fmt.Sprintf("netbird_split_m03_test_%d", os.Getpid())
	foreignTableName := tableName + "_foreign"

	removeTable(t, tableName)
	removeTable(t, foreignTableName)
	t.Cleanup(func() {
		removeTable(t, foreignTableName)
		removeTable(t, tableName)
	})

	manager, err := newNFTablesManager(tableName)
	require.NoError(t, err)
	require.NoError(t, manager.Ensure(context.Background()))
	require.True(t, manager.CreatedTable())

	table := requireInetTable(t, tableName)
	assert.Len(t, chainsInTable(t, tableName), 4, "only the four owned chains must exist")
	assert.Len(t, setsInTable(t, table), 9, "only the nine owned sets must exist")

	require.NoError(t, manager.Ensure(context.Background()))
	assert.Len(t, chainsInTable(t, tableName), 4, "a repeated Ensure must not duplicate chains")
	assert.Len(t, setsInTable(t, table), 9, "a repeated Ensure must not duplicate sets")

	createForeignTable(t, foreignTableName)

	conn := &nftables.Conn{}
	conn.AddChain(&nftables.Chain{Name: "intruder", Table: table})
	require.NoError(t, conn.Flush())
	t.Cleanup(func() {
		conn := &nftables.Conn{}
		conn.DelChain(&nftables.Chain{Name: "intruder", Table: table})
		_ = conn.Flush()
	})

	err = manager.Cleanup(context.Background())
	require.ErrorIs(t, err, backend.ErrForeignObject,
		"cleanup must refuse a table that contains a foreign chain")
	require.NotNil(t, findInetTable(t, tableName), "a refused cleanup must leave the table in place")
	require.NotNil(t, findInetTable(t, foreignTableName), "cleanup must not touch unrelated tables")

	conn = &nftables.Conn{}
	conn.DelChain(&nftables.Chain{Name: "intruder", Table: table})
	require.NoError(t, conn.Flush())

	require.NoError(t, manager.Cleanup(context.Background()))
	assert.Nil(t, findInetTable(t, tableName), "cleanup must remove the owned table")
	assert.NotNil(t, findInetTable(t, foreignTableName), "cleanup must leave the foreign table")

	require.NoError(t, manager.Cleanup(context.Background()),
		"cleanup must be idempotent after the table is gone")
}

func createForeignTable(t *testing.T, name string) {
	t.Helper()

	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{Name: name, Family: nftables.TableFamilyINet})
	conn.AddChain(&nftables.Chain{Name: "foreign_chain", Table: table})
	require.NoError(t, conn.AddSet(&nftables.Set{
		Name:    "foreign_set",
		Table:   table,
		KeyType: nftables.TypeIPAddr,
	}, nil))
	require.NoError(t, conn.Flush())
}

func removeTable(t *testing.T, name string) {
	t.Helper()

	conn := &nftables.Conn{}
	table := findInetTable(t, name)
	if table == nil {
		return
	}
	conn.DelTable(table)
	_ = conn.Flush()
}

func requireInetTable(t *testing.T, name string) *nftables.Table {
	t.Helper()

	table := findInetTable(t, name)
	require.NotNil(t, table)
	return table
}

func findInetTable(t *testing.T, name string) *nftables.Table {
	t.Helper()

	conn := &nftables.Conn{}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	require.NoError(t, err)
	for _, table := range tables {
		if table.Name == name {
			return table
		}
	}
	return nil
}

func chainsInTable(t *testing.T, name string) []*nftables.Chain {
	t.Helper()

	conn := &nftables.Conn{}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	require.NoError(t, err)

	var found []*nftables.Chain
	for _, chain := range chains {
		if chain.Table != nil && chain.Table.Name == name {
			found = append(found, chain)
		}
	}
	return found
}

func setsInTable(t *testing.T, table *nftables.Table) []*nftables.Set {
	t.Helper()

	conn := &nftables.Conn{}
	sets, err := conn.GetSets(table)
	require.NoError(t, err)
	return sets
}

func TestBackendLifecycleInContainer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}

	tableName := fmt.Sprintf("netbird_split_m03_backend_%d", os.Getpid())
	removeTable(t, tableName)
	t.Cleanup(func() {
		removeTable(t, tableName)
	})

	backendInstance := newBackend(
		systemProber{},
		func(table string) (nftManager, error) {
			return newNFTablesManager(table)
		},
		tableName,
	)
	ctx := context.Background()

	require.NoError(t, backendInstance.Initialize(ctx))
	status, err := backendInstance.GetStatus(ctx)
	require.NoError(t, err)
	assert.Contains(t, []backend.State{backend.StateReady, backend.StateDegraded}, status.State)
	assert.Equal(t, tableName, status.Owned.Table)
	assert.NotEmpty(t, status.Owned.Chains)
	assert.NotEmpty(t, status.Owned.Sets)

	require.ErrorIs(t, backendInstance.ApplyPolicy(ctx, nil, backend.PolicyOptions{}), backend.ErrInvalidPolicyOption)
	require.NoError(t, backendInstance.Rollback(ctx))

	require.NoError(t, backendInstance.Close(ctx))
	require.NoError(t, backendInstance.Close(ctx))
	assert.Nil(t, findInetTable(t, tableName))
}
