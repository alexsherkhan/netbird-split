# ADR: cgroup v2 attribution before socket creation

- Status: Accepted, GO for kernel mode with constraints
- Date: 2026-11-27
- Issue: #3 (M01), parent #1
- Spec: §6, §10, §26.1

## Context

Spec §6 requires the split engine to resolve an application's cgroup before its
first socket and to classify that socket through the kernel. It explicitly
allows a managed launcher or an application restart when classification before
the first connection cannot be guaranteed, and it forbids claiming that moving a
running process retroactively reclassifies existing sockets.

The current upstream client has no cgroup classification. Searching
`client/` and `shared/` for cgroup matching returns only a debug pretty-printer
for `expr.MetaKeyCGROUP` (`client/internal/debug/debug_linux.go:672`). The
firewall backend is nftables with a table named `netbird` per address family
(`client/firewall/nftables/manager_linux.go:24`), plus an iptables fallback. No
existing rule matches a socket cgroup.

The proposed split table in spec §8.1 is `inet netbird_split`. It is independent
of the upstream `ip`/`ip6` `netbird` tables, so a cgroup match can be added
without changing upstream ACL or NAT rules.

## Questions

1. Can an unprivileged desktop user create a child cgroup, move a process into
   it, and have nftables match packets from a socket created after the move?
2. Does `socket cgroupv2 level N "path"` resolve an existing cgroup path, and
   what happens when the path does not exist?
3. Which identity is stable enough for an application registry: cgroup path,
   `systemd` scope unit, desktop ID, executable, or a combination?
4. Do multi-process browsers and Electron-style applications keep every
   network process in the application cgroup?
5. What is the behavior when a socket already exists before the rule is
   installed, or when the process is moved after socket creation?
6. Can the design fail closed when the cgroup lookup does not match, instead of
   falling through to DIRECT?

## Required environment

- Linux with the cgroup v2 unified hierarchy. Check with
  `stat -fc %T /sys/fs/cgroup`, which must print `cgroup2fs`.
- A delegated user slice or root in a disposable VM. On a normal systemd
  desktop the probe needs `user@UID.service/app.slice` to be writable.
- nftables with the `socket cgroupv2` expression. The probe host had nft 1.0.9,
  Linux 7.0.0-43-generic, `CONFIG_NF_SOCKET_IPV4=m`, and the `nft_socket`
  module loaded. Older kernels without the expression cannot run this path.
- `unshare` with unprivileged user and network namespaces, or a disposable VM
  for the privileged end-to-end variant.
- `python3` for the UDP probe.
- A disposable desktop session for the browser and Flatpak/Snap experiments.
  Do not use a workstation whose connectivity matters.

## Exact commands and script references

Run the reproducible probe:

```bash
./scripts/split-tunnel-spikes/cgroup-attribution.sh
```

The script:

1. Finds the nearest writable ancestor of the caller's own cgroup.
2. Creates a temporary child cgroup and prints its path and nft level.
3. Starts a new user and network namespace with `unshare -Urn`.
4. Moves the namespace shell into the child cgroup.
5. Installs an nft `socket cgroupv2` rule with a counter in an isolated table.
6. Sends two UDP datagrams from a socket created inside that cgroup.
7. Asserts that the counter increased by at least two and removes the cgroup.

The key rule shape is:

```text
nft add rule inet kilo_cgroup_probe out \
  socket cgroupv2 level 5 "user.slice/user-1000.slice/user@1000.service/app.slice/<probe>" \
  counter accept
```

The path is relative to `/sys/fs/cgroup`, and the level is the number of path
components, so the leaf at `/a/b/c` is level 3. The path must already exist.
Adding a rule with a nonexistent path fails with:

```text
Error: cgroupv2 path fails: No such file or directory
```

## Executed observations (2026-11-27)

All commands below were executed unprivileged (`uid=1000`) on the probe host.

- The host uses cgroup v2: `stat -fc %T /sys/fs/cgroup` printed `cgroup2fs`.
- `user@1000.service/app.slice` was writable by the user. Creating and removing
  a child cgroup there succeeded.
- Moving a `sleep` process into the child cgroup succeeded by writing its PID to
  `cgroup.procs`, and the process appeared in `cgroup.procs`.
- `unshare -Urn --map-root-user` succeeded. Inside that namespace, `nft` could
  create a table and chains, so the nftables path was exercised with real kernel
  state rather than a mock.
- `socket cgroupv2 level 5 "<child cgroup path>" counter accept` matched two
  UDP datagrams sent by a Python socket created after the process was moved into
  the child cgroup. The counter read `packets 2 bytes 66`.
- The probe did not establish a negative control. A second rule for an ancestor
  cgroup was added after the matching rule, but the first `accept` terminated
  evaluation, so its zero counter is not evidence about level semantics.
- The kernel exposes `nft_socket`, `nf_socket_ipv4`, and `nf_socket_ipv6`; the
  module was loaded when the rule was installed.
- The host already had NetBird advanced routing active (`wt0`, table 7120,
  `ip rule` priority 110). The cgroup probe did not touch it: it used an
  isolated network namespace, and the host `ip rule` output was unchanged after
  the probe.

## Planned experiments (pending)

These need a disposable VM or a disposable desktop session and are not executed
in this worktree.

1. **Multi-process browser and Electron applications.** Launch Firefox and
   Chromium with a known application cgroup, then inspect
   `systemd-cgls` and `/proc/<pid>/cgroup` for the network process and its
   children. Verify that a rule on the application scope matches a connection
   created by a child process.
2. **Existing socket before rule installation.** Create the socket first, then
   install the rule and verify that the existing connection does not change
   class. This confirms the spec's "no retroactive reclassification" statement.
3. **Scope churn.** Restart the application and record whether the `systemd`
   scope path changes. Test `snap` and Flatpak scopes, which often include a
   random or hash suffix.
4. **Shared services and local proxies.** Test a browser that delegates traffic
   to a shared process, a local HTTP proxy, and a system service. Record which
   cases cannot be attributed to the application.
5. **Root and multi-user sessions.** Repeat under a second user and under a
   system service with a different `user@UID.service` path.
6. **Privileged VM end-to-end.** Run the spec §26 proof: Firefox through the
   NetBird exit node while Chromium uses the physical connection, verify with
   external IP checks and packet capture. This also covers the interaction with
   upstream WireGuard and the real exit node.

Suggested privileged outline for the VM:

```bash
# Inside the disposable VM, with NetBird connected and an exit node available.
systemd-cgls | grep -E 'firefox|chromium|code'
cat /proc/<pid>/cgroup

# Install the split rule in the isolated split table, then start the app.
# Verify with:
curl -4 https://ifconfig.me
tcpdump -ni any 'udp port 53 or tcp port 443'
```

## Expected observations

- A child cgroup created under the delegated user slice is writable without
  root.
- nft `socket cgroupv2` matches sockets created after the process joins the
  cgroup, including sockets created by child processes.
- A rule for a missing cgroup path is rejected.
- A process moved after socket creation does not change the socket's cgroup
  attribute for that existing socket.
- `systemd` application scopes are usually stable for the life of the process,
  but the full path can change across restarts, especially for Snap and
  Flatpak scopes.

## Decision criteria

GO for kernel mode when all of the following hold:

- At least 95 percent of the target application launches can be assigned a
  cgroup before the first socket, or a managed launcher can guarantee the
  assignment.
- The registry can detect a cgroup path change and update the split rule in a
  bounded time, with the stale rule removed in the same transaction.
- Unknown, unclassifiable, or proxy-routed traffic is routed to VPN or BLOCK in
  strict mode, never to DIRECT by default.
- Multi-process browsers keep every relevant network process in the application
  cgroup, or the unsupported cases are reported to the user.
- The per-packet cgroup expression cost is acceptable for the target traffic
  profile. This needs a benchmark in the privileged VM.

NO-GO for kernel mode if the target kernel lacks `socket cgroupv2`, if the
application scope can only be determined after the first socket, or if shared
services make attribution ambiguous for a large part of the target application
set.

## Decision

GO for the kernel-mode path, with these constraints:

- The split engine owns a stable application registry keyed by desktop ID or
  executable plus the live cgroup path. The cgroup path is not the only key
  because it changes across restarts.
- Rules are installed per live application cgroup. A missing or stale rule must
  not silently select DIRECT.
- The split policy uses a default action for unmatched protected traffic. In
  strict mode that default is BLOCK or VPN, not DIRECT.
- Userspace and netstack modes do not use this kernel path. They stay in
  Standard mode or use a documented degraded mode until a userspace classifier
  is validated.

## Fallback

- A managed launcher can start the application in a dedicated cgroup before the
  first socket. This is the preferred fallback for applications whose desktop
  entry launches a wrapper or a shared process.
- Requiring an application restart after a policy change is acceptable and must
  be stated in the UI.
- If cgroup matching is unavailable, fall back to Standard mode or to a
  destination-IP policy. Do not claim application-level accuracy in that mode.

## Risks

- **Race before rule installation.** A socket created before the cgroup rule is
  active keeps its old route. Mitigation: install rules on cgroup creation and
  require a restart or launcher for pre-existing sockets.
- **Path churn.** Snap and Flatpak scopes can include generated suffixes.
  Mitigation: watch the cgroup hierarchy and reconcile rules, not just the
  desktop ID.
- **Shared processes.** A browser, proxy, or system service can carry traffic
  for several applications. Mitigation: report the case as unsupported rather
  than claiming per-application coverage.
- **Rule lookup failure.** The `socket` expression can fail to find a socket for
  a packet. Mitigation: the protected default must be VPN or BLOCK, and the
  enforcement hook must not accept unmatched protected traffic.
- **Kernel and distro coverage.** Older kernels and non-systemd systems may lack
  the expression or delegation. Mitigation: capability probe at startup and a
  documented degraded mode.
- **Containers and user namespaces.** A container or nested user namespace can
  have a cgroup path that differs from the host view. Mitigation: do not claim
  support for containerized clients until tested.
- **Cgroup namespace.** The rule resolves the path in the cgroup namespace of
  the process that creates it. The daemon runs in the host cgroup namespace, so
  the path must be expressed from the host root.

## Current status

- Spike result: GO for kernel mode with constraints.
- Executed: unprivileged cgroup creation, process migration, nft `socket
  cgroupv2` match with counters, namespace isolation, cleanup.
- Pending privileged execution: browser and Electron multi-process behavior,
  Snap/Flatpak scope churn, pre-existing sockets, shared services, root and
  multi-user sessions, and the §26 two-browser exit-node proof in a disposable
  VM.
- Not started: performance benchmark of the cgroup expression and a production
  registry implementation.

## Upstream integration points

- `client/firewall/nftables/manager_linux.go:24` defines the upstream `netbird`
  table name and the per-family layout. The split table must be separate and
  must not flush or replace upstream chains.
- `client/firewall/nftables/chains_linux.go:27` creates the upstream routing,
  NAT, and mangle chains and their priorities. A new `inet netbird_split` table
  needs a documented output-hook priority and must coexist with these hooks.
- `client/internal/routemanager/systemops/systemops_linux.go:99` installs the
  upstream policy rules and `systemops_linux.go:175` installs VPN routes. The
  split engine adds its own marks, tables, and rules without reusing upstream
  control-plane marks.
- `client/internal/routemanager/manager.go:562` applies route selection changes.
  Application policy changes need a similar transactional apply point.
- `client/internal/engine.go` owns the client lifecycle and the firewall and
  route manager wiring. The app registry and split backend must be started and
  stopped there.
- `client/iface/wgaddr/address.go:33` defines `HasIPv6`, which also gates the v6
  side of application matching.
- `client/internal/peer/route.go` maps destination addresses to resources. The
  split engine must not break that mapping when it adds its own marks and
  tables.
- GUI, CLI, and local gRPC API need to expose application identity, cgroup
  status, and unsupported cases.

## References

- Spec §6: application discovery, cgroup assignment before socket creation,
  managed launcher and restart rules.
- Spec §10: strict mode must block unknown protected traffic.
- Spec §26.1: prove cgroup attribution before socket creation.
- `nft(8)`, `socket cgroupv2 level NUM path`: path is relative to
  `/sys/fs/cgroup`; level 1 matches the first ancestor, level N the Nth.
- `client/internal/debug/debug_linux.go:672`: the only existing cgroup reference
  in the client, a debug pretty-printer.
