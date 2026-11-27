//go:build linux

package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

const scopePrefix = "nb-"

func (i Identity) canonical() string {
	if i.DesktopID == "" && i.Executable == "" && i.FlatpakID == "" && i.SnapID == "" {
		return ""
	}
	return strings.Join([]string{
		string(i.DesktopID),
		string(i.Executable),
		string(i.FlatpakID),
		string(i.SnapID),
	}, "\x00")
}

func matchesAny(identity Identity, requirements []Requirement) bool {
	for _, requirement := range requirements {
		if requirement.Matches(identity) {
			return true
		}
	}
	return false
}

func validateScopePath(relativePath string) error {
	if relativePath == "" {
		return errors.New("path is empty")
	}
	if strings.HasPrefix(relativePath, "/") {
		return fmt.Errorf("path %q must be relative to the cgroup root", relativePath)
	}
	if strings.Contains(relativePath, `\`) {
		return fmt.Errorf("path %q must use forward slashes", relativePath)
	}
	for _, component := range strings.Split(relativePath, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("path %q contains an invalid component %q", relativePath, component)
		}
	}
	return nil
}

func scopeName(uid config.UID, identity Identity) string {
	sum := sha256.Sum256([]byte(identity.canonical()))
	return fmt.Sprintf("nb-%d-%s", uid, hex.EncodeToString(sum[:8]))
}

func scopeKey(uid config.UID, identity Identity) string {
	return fmt.Sprintf("%d\x00%s", uid, identity.canonical())
}
