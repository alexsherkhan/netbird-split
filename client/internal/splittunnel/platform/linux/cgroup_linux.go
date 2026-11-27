//go:build linux && !android

package linux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const cgroupRoot = "/sys/fs/cgroup"

// cgroupIDResolver turns a cgroup path relative to the cgroup v2 mount point
// into the kernel cgroup ID. The nftables socket cgroupv2 expression compares
// that ID at the level derived from the same path.
type cgroupIDResolver interface {
	ID(relativePath string) (uint64, error)
}

type statCgroupResolver struct {
	root string
}

func newStatCgroupResolver() cgroupIDResolver {
	return statCgroupResolver{root: cgroupRoot}
}

func (r statCgroupResolver) ID(relativePath string) (uint64, error) {
	absolute := filepath.Join(r.root, filepath.FromSlash(relativePath))
	info, err := os.Stat(absolute)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup %q: %w", relativePath, err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("cgroup %q is not a directory", relativePath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("read inode of cgroup %q", relativePath)
	}
	if stat.Ino == 0 {
		return 0, fmt.Errorf("cgroup %q has no inode", relativePath)
	}
	return stat.Ino, nil
}

// nftCgroupMatch is one resolved socket cgroupv2 match. The nftables library
// has no path attribute: nft userspace resolves the path to the cgroup inode
// and the kernel compares the socket's cgroup ID at the requested level.
type nftCgroupMatch struct {
	Path  string
	Level uint32
	ID    uint64
}

func resolveCgroupMatch(relativePath string, resolver cgroupIDResolver) (nftCgroupMatch, error) {
	if err := validateCgroupPath(relativePath); err != nil {
		return nftCgroupMatch{}, err
	}
	if resolver == nil {
		resolver = newStatCgroupResolver()
	}
	id, err := resolver.ID(relativePath)
	if err != nil {
		return nftCgroupMatch{}, err
	}
	return nftCgroupMatch{
		Path:  relativePath,
		Level: cgroupPathLevel(relativePath),
		ID:    id,
	}, nil
}

func validateCgroupPath(relativePath string) error {
	if relativePath == "" {
		return errors.New("cgroup path is empty")
	}
	if strings.HasPrefix(relativePath, "/") {
		return fmt.Errorf("cgroup path %q must be relative to %s", relativePath, cgroupRoot)
	}
	if strings.Contains(relativePath, `\`) {
		return fmt.Errorf("cgroup path %q must use forward slashes", relativePath)
	}
	for _, component := range strings.Split(relativePath, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("cgroup path %q contains an invalid component %q", relativePath, component)
		}
	}
	return nil
}

// cgroupPathLevel is the number of path components, matching nft's
// "socket cgroupv2 level N path" semantics: /a/b/c is level 3.
func cgroupPathLevel(relativePath string) uint32 {
	return uint32(len(strings.Split(relativePath, "/")))
}
