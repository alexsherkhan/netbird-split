package application

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxDesktopFileSize = 1 << 20

// DefaultSources returns the standard desktop entry directories in descending
// precedence. Missing directories are ignored during discovery.
func DefaultSources() []Source {
	var sources []Source

	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dataHome = filepath.Join(home, ".local", "share")
		}
	}
	if dataHome != "" {
		sources = append(sources, Source{
			Path:        filepath.Join(dataHome, "applications"),
			InstallType: InstallUser,
		})
	}

	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = strings.Join([]string{"/usr/local/share", "/usr/share"}, string(os.PathListSeparator))
	}
	for _, dir := range filepath.SplitList(dataDirs) {
		if dir == "" {
			continue
		}
		sources = append(sources, Source{
			Path:        filepath.Join(dir, "applications"),
			InstallType: InstallSystem,
		})
	}

	if dataHome != "" {
		sources = append(sources, Source{
			Path:        filepath.Join(dataHome, "flatpak", "exports", "share", "applications"),
			InstallType: InstallFlatpak,
		})
	}
	sources = append(sources,
		Source{
			Path:        filepath.Join(string(filepath.Separator), "var", "lib", "flatpak", "exports", "share", "applications"),
			InstallType: InstallFlatpak,
		},
		Source{
			Path:        filepath.Join(string(filepath.Separator), "var", "lib", "snapd", "desktop", "applications"),
			InstallType: InstallSnap,
		},
	)
	return dedupeSources(sources)
}

// Discover scans the configured sources and returns applications ordered by
// source precedence and desktop ID. Hidden entries are omitted; a hidden entry
// still shadows the same desktop ID from a lower precedence source.
func Discover(ctx context.Context, opts Options) ([]Application, error) {
	opts = opts.normalized()
	sources := dedupeSources(opts.Sources)

	apps := make([]Application, 0, 64)
	winner := make(map[string]int)
	suppressed := make(map[string]struct{})
	scanned := 0
	truncated := false

	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return apps, err
		}
		walkErr := filepath.WalkDir(source.Path, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() || !isDesktopFile(entry, path) {
				return nil
			}
			if scanned >= opts.MaxApplications {
				truncated = true
				return filepath.SkipAll
			}
			scanned++

			desktopID := desktopIDFor(source.Path, path)
			if desktopID == "" {
				return nil
			}
			if _, hidden := suppressed[desktopID]; hidden {
				return nil
			}
			if index, found := winner[desktopID]; found {
				apps[index].Shadowed = cleanShadowed(append(apps[index].Shadowed, SourceRef{
					Path:        path,
					InstallType: source.InstallType,
				}))
				return nil
			}

			data, ok := readDesktopFile(path)
			if !ok {
				return nil
			}
			app, status := parseDesktopEntry(data, source, path, desktopID)
			switch status {
			case entryHidden:
				suppressed[desktopID] = struct{}{}
			case entryOK:
				winner[desktopID] = len(apps)
				apps = append(apps, app)
			}
			return nil
		})
		if walkErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return apps, ctxErr
			}
		}
		if truncated {
			break
		}
	}
	return apps, nil
}

func dedupeSources(sources []Source) []Source {
	if len(sources) == 0 {
		return nil
	}
	out := make([]Source, 0, len(sources))
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if source.Path == "" {
			continue
		}
		key := filepath.Clean(source.Path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		source.Path = key
		out = append(out, source)
	}
	return out
}

func isDesktopFile(entry fs.DirEntry, path string) bool {
	if !strings.HasSuffix(entry.Name(), ".desktop") {
		return false
	}
	if entry.Type().IsRegular() {
		return true
	}
	if entry.Type()&fs.ModeSymlink == 0 {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func readDesktopFile(path string) ([]byte, bool) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxDesktopFileSize+1))
	if err != nil || len(data) > maxDesktopFileSize {
		return nil, false
	}
	return data, true
}

func desktopIDFor(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(filepath.ToSlash(rel), "/", "-")
}
