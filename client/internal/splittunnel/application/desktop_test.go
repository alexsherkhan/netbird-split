package application

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSource(t *testing.T, install InstallType, name string) Source {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", "desktop", name))
	require.NoError(t, err)
	return Source{Path: path, InstallType: install}
}

func findApplication(t *testing.T, apps []Application, desktopID string) Application {
	t.Helper()
	for _, app := range apps {
		if app.DesktopID == desktopID {
			return app
		}
	}
	t.Fatalf("application %q not found in %d entries", desktopID, len(apps))
	return Application{}
}

func hasApplication(apps []Application, desktopID string) bool {
	for _, app := range apps {
		if app.DesktopID == desktopID {
			return true
		}
	}
	return false
}

func TestDiscoverParsesDesktopEntries(t *testing.T) {
	apps, err := Discover(context.Background(), Options{
		Sources: []Source{testSource(t, InstallSystem, "system")},
	})
	require.NoError(t, err)

	editor := findApplication(t, apps, "org.example.Editor.desktop")
	assert.Equal(t, "System Editor", editor.Name)
	assert.Equal(t, "/usr/bin/system-editor", editor.Executable)
	assert.Equal(t, Icon{Name: "org.example.Editor"}, editor.Icon)
	assert.Equal(t, InstallSystem, editor.InstallType)
	assert.True(t, filepath.IsAbs(editor.SourcePath), "source path should be absolute")
	assert.False(t, editor.NoDisplay)
	assert.False(t, editor.Unknown)

	noDisplay := findApplication(t, apps, "org.example.NoDisplay.desktop")
	assert.True(t, noDisplay.NoDisplay, "NoDisplay entries remain discoverable")

	iconPath := findApplication(t, apps, "org.example.IconPath.desktop")
	assert.Equal(t, Icon{Path: "/usr/share/icons/hicolor/128x128/apps/org.example.IconPath.png"}, iconPath.Icon)

	quoted := findApplication(t, apps, "org.example.Quoted.desktop")
	assert.Equal(t, "/opt/Example Editor/bin/editor", quoted.Executable)

	nested := findApplication(t, apps, "subdir-org.example.Nested.desktop")
	assert.Equal(t, "Nested App", nested.Name)

	assert.False(t, hasApplication(apps, "org.example.Link.desktop"), "non-application entry types are skipped")
	assert.False(t, hasApplication(apps, "org.example.Malformed.desktop"), "malformed entries are skipped")
}

func TestDiscoverAppliesSourcePrecedenceAndRecordsShadowed(t *testing.T) {
	apps, err := Discover(context.Background(), Options{
		Sources: []Source{
			testSource(t, InstallUser, "user"),
			testSource(t, InstallSystem, "system"),
			testSource(t, InstallFlatpak, "flatpak"),
			testSource(t, InstallSnap, "snap"),
		},
	})
	require.NoError(t, err)

	duplicate := findApplication(t, apps, "org.example.Duplicate.desktop")
	assert.Equal(t, "User Duplicate", duplicate.Name)
	assert.Equal(t, InstallUser, duplicate.InstallType)
	assert.Equal(t, "/home/user/bin/user-duplicate", duplicate.Executable)
	require.Len(t, duplicate.Shadowed, 3, "all lower precedence sources should be recorded")
	assert.Equal(t, InstallSystem, duplicate.Shadowed[0].InstallType)
	assert.Equal(t, InstallFlatpak, duplicate.Shadowed[1].InstallType)
	assert.Equal(t, InstallSnap, duplicate.Shadowed[2].InstallType)
	for _, shadowed := range duplicate.Shadowed {
		assert.True(t, filepath.IsAbs(shadowed.Path), "shadowed source should be recorded by path")
	}
}

func TestDiscoverFlatpakBeforeSnap(t *testing.T) {
	apps, err := Discover(context.Background(), Options{
		Sources: []Source{
			testSource(t, InstallFlatpak, "flatpak"),
			testSource(t, InstallSnap, "snap"),
		},
	})
	require.NoError(t, err)

	duplicate := findApplication(t, apps, "org.example.Duplicate.desktop")
	assert.Equal(t, "Flatpak Duplicate", duplicate.Name)
	assert.Equal(t, InstallFlatpak, duplicate.InstallType)
	require.Len(t, duplicate.Shadowed, 1)
	assert.Equal(t, InstallSnap, duplicate.Shadowed[0].InstallType)

	assert.True(t, hasApplication(apps, "com.example.Flatpak.desktop"))
	assert.True(t, hasApplication(apps, "com.example.Snap.desktop"))
}

func TestDiscoverHiddenEntryShadowsLowerSource(t *testing.T) {
	apps, err := Discover(context.Background(), Options{
		Sources: []Source{
			testSource(t, InstallUser, "user"),
			testSource(t, InstallSystem, "system"),
		},
	})
	require.NoError(t, err)

	assert.False(t, hasApplication(apps, "org.example.Hidden.desktop"), "hidden entry and the entry it hides must be omitted")
	assert.True(t, hasApplication(apps, "org.example.UserOnly.desktop"))
}

func TestDiscoverMalformedEntryDoesNotShadowLowerSource(t *testing.T) {
	apps, err := Discover(context.Background(), Options{
		Sources: []Source{
			testSource(t, InstallSystem, "system"),
			testSource(t, InstallSnap, "snap"),
		},
	})
	require.NoError(t, err)

	app := findApplication(t, apps, "org.example.Malformed.desktop")
	assert.Equal(t, "Snap Malformed Rival", app.Name)
	assert.Equal(t, InstallSnap, app.InstallType)
}

func TestDiscoverRespectsLimit(t *testing.T) {
	apps, err := Discover(context.Background(), Options{
		Sources:         []Source{testSource(t, InstallSystem, "system")},
		MaxApplications: 2,
	})
	require.NoError(t, err)
	assert.Len(t, apps, 2)
}

func TestDiscoverContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	apps, err := Discover(ctx, Options{
		Sources: []Source{testSource(t, InstallSystem, "system")},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Empty(t, apps)
}

func TestDefaultSourcesUsesXDGEnvironment(t *testing.T) {
	dataHome := t.TempDir()
	dataDir := t.TempDir()
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_DATA_DIRS", dataDir)
	t.Setenv("HOME", home)

	sources := DefaultSources()
	require.NotEmpty(t, sources)
	assert.Equal(t, filepath.Join(dataHome, "applications"), sources[0].Path)
	assert.Equal(t, InstallUser, sources[0].InstallType)
	assert.Equal(t, filepath.Join(dataDir, "applications"), sources[1].Path)
	assert.Equal(t, InstallSystem, sources[1].InstallType)

	if runtime.GOOS != "windows" {
		assert.Equal(t, filepath.Join(dataHome, "flatpak", "exports", "share", "applications"), sources[2].Path)
		assert.Equal(t, InstallFlatpak, sources[2].InstallType)
	}
}

func TestParseExec(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		executable string
		args       []string
	}{
		{
			name:       "plain",
			value:      "/usr/bin/editor --new-window %U",
			executable: "/usr/bin/editor",
			args:       []string{"--new-window"},
		},
		{
			name:       "quoted path",
			value:      `"/opt/Example Editor/bin/editor" --open "%f"`,
			executable: "/opt/Example Editor/bin/editor",
			args:       []string{"--open"},
		},
		{
			name:       "escaped space",
			value:      `/opt/Example\sEditor/bin/editor --flag`,
			executable: "/opt/Example Editor/bin/editor",
			args:       []string{"--flag"},
		},
		{
			name:       "percent literal",
			value:      "/usr/bin/editor --percent=100%%",
			executable: "/usr/bin/editor",
			args:       []string{"--percent=100%"},
		},
		{
			name:       "field code only",
			value:      "%f",
			executable: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executable, args := parseExec(tt.value)
			assert.Equal(t, tt.executable, executable)
			assert.Equal(t, tt.args, args)
		})
	}
}

func TestReadDesktopFileRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.desktop")
	require.NoError(t, os.WriteFile(path, make([]byte, maxDesktopFileSize+1), 0o600))

	_, ok := readDesktopFile(path)
	assert.False(t, ok)
}
