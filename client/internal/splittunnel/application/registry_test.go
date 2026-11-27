package application

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func emptyOptions() Options {
	return Options{Sources: []Source{}, ProcRoot: filepath.Join("testdata", "proc")}
}

func TestRegistryAddLookupListRemove(t *testing.T) {
	registry := New(emptyOptions())

	require.NoError(t, registry.Add(Application{
		DesktopID:   "org.example.Tool.desktop",
		Name:        "Tool",
		Executable:  "/opt/tool",
		InstallType: InstallSystem,
	}))

	app, ok := registry.Lookup("org.example.Tool.desktop")
	require.True(t, ok)
	assert.Equal(t, "Tool", app.Name)
	assert.Equal(t, InstallExplicit, app.InstallType)

	apps := registry.List()
	require.Len(t, apps, 1)
	assert.Equal(t, "org.example.Tool.desktop", apps[0].DesktopID)

	assert.True(t, registry.Remove("org.example.Tool.desktop"))
	assert.False(t, registry.Remove("org.example.Tool.desktop"))
	_, ok = registry.Lookup("org.example.Tool.desktop")
	assert.False(t, ok)

	assert.ErrorIs(t, registry.Add(Application{Name: "missing ID"}), ErrDesktopIDRequired)
}

func TestRegistryRefreshDiscoversApplications(t *testing.T) {
	registry := New(Options{
		Sources:  []Source{testSource(t, InstallSystem, "system")},
		ProcRoot: filepath.Join("testdata", "proc"),
	})

	result, err := registry.Refresh(context.Background())
	require.NoError(t, err)
	assert.Positive(t, result.Applications)
	assert.Zero(t, result.Processes, "fixture has no exe links, so no process is readable")

	editor, ok := registry.Lookup("org.example.Editor.desktop")
	require.True(t, ok)
	assert.Equal(t, "System Editor", editor.Name)
	assert.Equal(t, InstallSystem, editor.InstallType)
}

func TestRegistryExplicitEntryShadowsDiscovered(t *testing.T) {
	registry := New(Options{
		Sources:  []Source{testSource(t, InstallSystem, "system")},
		ProcRoot: filepath.Join("testdata", "proc"),
	})
	_, err := registry.Refresh(context.Background())
	require.NoError(t, err)

	discovered, ok := registry.Lookup("org.example.Editor.desktop")
	require.True(t, ok)

	require.NoError(t, registry.Add(Application{
		DesktopID:  "org.example.Editor.desktop",
		Name:       "Explicit Editor",
		Executable: "/opt/explicit-editor",
	}))

	explicit, ok := registry.Lookup("org.example.Editor.desktop")
	require.True(t, ok)
	assert.Equal(t, "Explicit Editor", explicit.Name)
	assert.Equal(t, InstallExplicit, explicit.InstallType)
	require.Len(t, explicit.Shadowed, 1)
	assert.Equal(t, discovered.SourcePath, explicit.Shadowed[0].Path)

	apps, err := Discover(context.Background(), Options{
		Sources: []Source{testSource(t, InstallSystem, "system")},
	})
	require.NoError(t, err)
	assert.True(t, hasApplication(apps, "org.example.Editor.desktop"))

	_, err = registry.Refresh(context.Background())
	require.NoError(t, err)
	explicit, ok = registry.Lookup("org.example.Editor.desktop")
	require.True(t, ok)
	assert.Equal(t, "Explicit Editor", explicit.Name)
	assert.Len(t, explicit.Shadowed, 1, "refresh must not duplicate the shadowed source")
}

func TestRegistryRemoveDiscoveredEntry(t *testing.T) {
	registry := New(Options{
		Sources:  []Source{testSource(t, InstallSystem, "system")},
		ProcRoot: filepath.Join("testdata", "proc"),
	})
	_, err := registry.Refresh(context.Background())
	require.NoError(t, err)

	assert.True(t, registry.Remove("org.example.Editor.desktop"))
	_, ok := registry.Lookup("org.example.Editor.desktop")
	assert.False(t, ok)
}

func TestRegistryProcessPIDReuse(t *testing.T) {
	registry := New(emptyOptions())

	require.NoError(t, registry.AddProcess(Process{PID: 10, StartTime: 100, Executable: "/opt/tool"}))
	require.NoError(t, registry.AddProcess(Process{PID: 10, StartTime: 200, Executable: "/opt/tool"}))

	processes := registry.Processes()
	require.Len(t, processes, 1, "a new start time must replace the stale PID generation")
	assert.Equal(t, uint64(200), processes[0].StartTime)

	assert.False(t, registry.RemoveProcess(10, 100), "the old generation must already be gone")
	assert.True(t, registry.RemoveProcess(10, 200))
	assert.Empty(t, registry.Processes())
	assert.ErrorIs(t, registry.AddProcess(Process{PID: 0}), ErrProcessPID)
}

func TestRegistryMultipleUserSessions(t *testing.T) {
	registry := New(emptyOptions())

	require.NoError(t, registry.AddProcess(Process{PID: 10, StartTime: 1, UID: 1000, Executable: "/opt/tool"}))
	require.NoError(t, registry.AddProcess(Process{PID: 11, StartTime: 1, UID: 1001, Executable: "/opt/tool"}))

	processes := registry.Processes()
	require.Len(t, processes, 2)
	assert.Equal(t, uint32(1000), processes[0].UID)
	assert.Equal(t, uint32(1001), processes[1].UID)
}

func TestRegistryMatchByExecutable(t *testing.T) {
	registry := New(Options{
		Sources:  []Source{testSource(t, InstallSystem, "system")},
		ProcRoot: filepath.Join("testdata", "proc"),
	})
	_, err := registry.Refresh(context.Background())
	require.NoError(t, err)

	app, ok := registry.Match(Process{Executable: "/usr/bin/system-editor"})
	require.True(t, ok)
	assert.Equal(t, "org.example.Editor.desktop", app.DesktopID)

	app, ok = registry.Match(Process{Executable: "/usr/bin/system-editor"})
	require.True(t, ok)
	assert.False(t, app.Unknown)

	require.NoError(t, registry.Add(Application{
		DesktopID:  "org.example.Editor.desktop",
		Name:       "Explicit Editor",
		Executable: "/usr/bin/system-editor",
	}))
	app, ok = registry.Match(Process{Executable: "/usr/bin/system-editor"})
	require.True(t, ok)
	assert.Equal(t, "Explicit Editor", app.Name, "explicit metadata takes precedence")
}

func TestRegistryUnknownApplicationBehavior(t *testing.T) {
	process := Process{Executable: "/opt/unknown-tool"}

	skip := New(emptyOptions())
	_, ok := skip.Match(process)
	assert.False(t, ok)

	track := New(Options{
		Sources: []Source{},
		Unknown: UnknownTrack,
	})
	app, ok := track.Match(process)
	require.True(t, ok)
	assert.True(t, app.Unknown)
	assert.Equal(t, InstallUnknown, app.InstallType)
	assert.Equal(t, "unknown-tool", app.Name)
	assert.Equal(t, "unknown:/opt/unknown-tool", app.DesktopID)

	_, ok = track.Match(Process{})
	assert.False(t, ok, "an empty executable is never synthesized")
}

func TestRegistryLimitsBoundedMemory(t *testing.T) {
	registry := New(Options{
		Sources:         []Source{},
		MaxApplications: 1,
		ScanLimit:       1,
	})

	require.NoError(t, registry.Add(Application{DesktopID: "one", Name: "One"}))
	assert.ErrorIs(t, registry.Add(Application{DesktopID: "two", Name: "Two"}), ErrRegistryFull)

	require.NoError(t, registry.AddProcess(Process{PID: 1, StartTime: 1}))
	assert.ErrorIs(t, registry.AddProcess(Process{PID: 2, StartTime: 1}), ErrRegistryFull)
	require.NoError(t, registry.AddProcess(Process{PID: 1, StartTime: 2}), "a PID generation replacement must not hit the limit")
}

func TestRegistryListReturnsCopies(t *testing.T) {
	registry := New(Options{
		Sources:  []Source{testSource(t, InstallSystem, "system")},
		ProcRoot: filepath.Join("testdata", "proc"),
	})
	_, err := registry.Refresh(context.Background())
	require.NoError(t, err)

	apps := registry.List()
	require.NotEmpty(t, apps)
	for index := range apps {
		apps[index].Name = "mutated"
		apps[index].Shadowed = append(apps[index].Shadowed, SourceRef{Path: "/tmp/mutated"})
	}

	assert.NotEqual(t, "mutated", registry.List()[0].Name)
}

func TestRegistryConcurrentReads(t *testing.T) {
	registry := New(Options{
		Sources: []Source{
			testSource(t, InstallUser, "user"),
			testSource(t, InstallSystem, "system"),
		},
		ProcRoot: filepath.Join("testdata", "proc"),
	})
	_, err := registry.Refresh(context.Background())
	require.NoError(t, err)
	require.NoError(t, registry.AddProcess(Process{PID: 10, StartTime: 1, Executable: "/usr/bin/system-editor"}))

	var wait sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for j := 0; j < 100; j++ {
				registry.List()
				registry.Lookup("org.example.Editor.desktop")
				registry.Match(Process{Executable: "/usr/bin/system-editor"})
				registry.Processes()
			}
		}()
	}

	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		for j := 0; j < 50; j++ {
			_ = registry.Add(Application{DesktopID: "org.example.Temporary.desktop", Name: "Temporary"})
			registry.Remove("org.example.Temporary.desktop")
			_ = registry.AddProcess(Process{PID: int32(100 + j), StartTime: uint64(j + 1)})
			_, _ = registry.Refresh(context.Background())
		}
	}()

	close(start)
	wait.Wait()

	_, ok := registry.Lookup("org.example.Editor.desktop")
	assert.True(t, ok)
}

func TestRegistryRefreshContextCanceled(t *testing.T) {
	registry := New(Options{
		Sources: []Source{testSource(t, InstallSystem, "system")},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := registry.Refresh(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
}
