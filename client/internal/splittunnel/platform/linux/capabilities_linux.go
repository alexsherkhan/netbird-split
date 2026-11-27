//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
)

const (
	cgroupPath       = "/sys/fs/cgroup"
	ipv6DisablePath  = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	routeHookMajor   = 4
	routeHookMinor   = 10
	probeErrorDetail = "probe %s: %v"
)

type systemProber struct{}

func (systemProber) Probe(ctx context.Context) (backend.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return backend.Capabilities{}, err
	}

	return backend.Capabilities{Items: []backend.Capability{
		probeNFTables(),
		probeNetlink(),
		probePolicyRouting(),
		probeRouteOutputHook(),
		probeCgroupV2(),
		probeIPv6(),
	}}, nil
}

func probeNFTables() backend.Capability {
	conn := &nftables.Conn{}
	if _, err := conn.ListTables(); err != nil {
		return capabilityFromError(backend.CapabilityNFTables, "list nftables tables", err)
	}
	return available(backend.CapabilityNFTables, "nftables netlink interface is available")
}

func probeNetlink() backend.Capability {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return capabilityFromError(backend.CapabilityNetlink, "open netlink route socket", err)
	}
	defer handle.Close()

	if _, err := handle.LinkList(); err != nil {
		return capabilityFromError(backend.CapabilityNetlink, "list links", err)
	}
	return available(backend.CapabilityNetlink, "netlink route socket is available")
}

func probePolicyRouting() backend.Capability {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return capabilityFromError(backend.CapabilityPolicyRouting, "open netlink route socket", err)
	}
	defer handle.Close()

	if _, err := handle.RuleList(netlink.FAMILY_V4); err != nil {
		return capabilityFromError(backend.CapabilityPolicyRouting, "list IPv4 policy rules", err)
	}
	return available(backend.CapabilityPolicyRouting, "IPv4 policy rules are available")
}

func probeRouteOutputHook() backend.Capability {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return backend.Capability{
			ID:     backend.CapabilityRouteOutputHook,
			State:  backend.CapabilityUnknown,
			Detail: fmt.Sprintf("read kernel version: %v", err),
		}
	}

	release := unix.ByteSliceToString(uts.Release[:])
	major, minor, ok := parseKernelVersion(release)
	if !ok {
		return backend.Capability{
			ID:     backend.CapabilityRouteOutputHook,
			State:  backend.CapabilityUnknown,
			Detail: fmt.Sprintf("cannot parse kernel version %q", release),
		}
	}
	if major < routeHookMajor || major == routeHookMajor && minor < routeHookMinor {
		return backend.Capability{
			ID:    backend.CapabilityRouteOutputHook,
			State: backend.CapabilityUnavailable,
			Detail: fmt.Sprintf("kernel %d.%d predates route-type output chains, need %d.%d",
				major, minor, routeHookMajor, routeHookMinor),
		}
	}
	return available(backend.CapabilityRouteOutputHook,
		fmt.Sprintf("kernel %d.%d supports route-type output chains", major, minor))
}

func probeCgroupV2() backend.Capability {
	var stat unix.Statfs_t
	if err := unix.Statfs(cgroupPath, &stat); err != nil {
		return capabilityFromError(backend.CapabilityCgroupV2, "stat "+cgroupPath, err)
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC {
		return backend.Capability{
			ID:     backend.CapabilityCgroupV2,
			State:  backend.CapabilityUnavailable,
			Detail: fmt.Sprintf("%s is not a cgroup v2 hierarchy", cgroupPath),
		}
	}
	return available(backend.CapabilityCgroupV2, "cgroup v2 unified hierarchy is mounted")
}

func probeIPv6() backend.Capability {
	data, err := os.ReadFile(ipv6DisablePath)
	if err != nil {
		return backend.Capability{
			ID:     backend.CapabilityIPv6,
			State:  backend.CapabilityUnavailable,
			Detail: fmt.Sprintf("read %s: %v", ipv6DisablePath, err),
		}
	}

	value := strings.TrimSpace(string(data))
	switch value {
	case "0":
		return available(backend.CapabilityIPv6, "IPv6 is enabled")
	case "1":
		return backend.Capability{
			ID:     backend.CapabilityIPv6,
			State:  backend.CapabilityUnavailable,
			Detail: fmt.Sprintf("IPv6 is disabled by %s", ipv6DisablePath),
		}
	default:
		return backend.Capability{
			ID:     backend.CapabilityIPv6,
			State:  backend.CapabilityUnknown,
			Detail: fmt.Sprintf("unexpected value %q in %s", value, ipv6DisablePath),
		}
	}
}

func parseKernelVersion(release string) (int, int, bool) {
	if index := strings.IndexAny(release, "-+"); index >= 0 {
		release = release[:index]
	}
	parts := strings.Split(release, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	if major < 0 || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

func available(id backend.CapabilityID, detail string) backend.Capability {
	return backend.Capability{ID: id, State: backend.CapabilityAvailable, Detail: detail}
}

func capabilityFromError(id backend.CapabilityID, action string, err error) backend.Capability {
	detail := fmt.Sprintf(probeErrorDetail, action, err)
	switch {
	case errors.Is(err, os.ErrPermission):
		detail = fmt.Sprintf("%s requires CAP_NET_ADMIN: %v", action, err)
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOPROTOOPT):
		detail = fmt.Sprintf("%s is not supported by the kernel: %v", action, err)
	}
	return backend.Capability{
		ID:     id,
		State:  backend.CapabilityUnavailable,
		Detail: detail,
	}
}
