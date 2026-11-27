//go:build linux

package application

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func procFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	require.NoError(t, os.CopyFS(dst, os.DirFS(filepath.Join("testdata", "proc"))))

	for pid, target := range map[string]string{
		"100": "/usr/bin/python3",
		"200": "/usr/lib/firefox/firefox",
	} {
		require.NoError(t, os.Symlink(target, filepath.Join(dst, pid, "exe")))
	}
	return dst
}

func TestScanProcesses(t *testing.T) {
	root := procFixture(t)

	processes, err := ScanProcesses(context.Background(), root, 0)
	require.NoError(t, err)
	require.Len(t, processes, 2, "inaccessible and malformed process directories are skipped")

	assert.Equal(t, Process{
		PID:        100,
		StartTime:  987654,
		UID:        1000,
		Executable: "/usr/bin/python3",
		Cgroup:     "/user.slice/user-1000.slice/user@1000.service/app.slice/python3.service",
	}, processes[0])

	assert.Equal(t, Process{
		PID:        200,
		StartTime:  111222,
		UID:        1001,
		Executable: "/usr/lib/firefox/firefox",
		Cgroup:     "/user.slice/user-1001.slice/user@1001.service/app.slice/firefox.scope",
	}, processes[1])
}

func TestScanProcessesRespectsLimit(t *testing.T) {
	root := procFixture(t)

	processes, err := ScanProcesses(context.Background(), root, 1)
	require.NoError(t, err)
	require.Len(t, processes, 1)
	assert.Equal(t, int32(100), processes[0].PID)
}

func TestScanProcessesSkipsDisappearedProcess(t *testing.T) {
	root := procFixture(t)
	require.NoError(t, os.RemoveAll(filepath.Join(root, "200")))

	processes, err := ScanProcesses(context.Background(), root, 0)
	require.NoError(t, err)
	require.Len(t, processes, 1)
	assert.Equal(t, int32(100), processes[0].PID)
}

func TestScanProcessesMissingRoot(t *testing.T) {
	_, err := ScanProcesses(context.Background(), filepath.Join(t.TempDir(), "missing"), 0)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrUnsupported))
}

func TestScanProcessesContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ScanProcesses(ctx, procFixture(t), 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestParseStartTime(t *testing.T) {
	tests := []struct {
		name string
		stat string
		want uint64
		ok   bool
	}{
		{
			name: "normal",
			stat: "42 (comm) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 0 0",
			want: 555,
			ok:   true,
		},
		{
			name: "comm with spaces and parentheses",
			stat: "42 (Web Content)) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0",
			want: 777,
			ok:   true,
		},
		{
			name: "missing fields",
			stat: "42 (comm) S 1 42",
			ok:   false,
		},
		{
			name: "malformed",
			stat: "not a stat line",
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, err := parseStartTime([]byte(tt.stat))
			if !tt.ok {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, start)
		})
	}
}
