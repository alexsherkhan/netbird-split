# ADR: IPv6 exit-node behavior and required fallback blocking

- Status: Accepted, GO only with explicit gateway capability and a fail-closed IPv6 default
- Date: 2026-11-27
- Issue: #3 (M01), parent #1
- Spec: §8.2, §9, §10, §26.1

## Context

Spec §9 allows one active exit node in 1.0 and requires that, if the exit node
does not support IPv6 egress, protected IPv6 Internet traffic is blocked. Spec
§8.2 requires IPv6 routes and fail-closed behavior to be validated. Spec §10
requires protection for both IPv4 and IPv6.

Upstream already treats the IPv6 overlay as a soft, opt-in feature:

- The interface exposes `HasIPv6()` (`client/iface/wgaddr/address.go:33`).
- When the local interface has no v6, `filterAllowedIPs` strips v6 entries
  (`client/internal/engine.go:2911`) and peer setup skips v6 AllowedIPs
  (`engine.go:1996`).
- When a v4 default route is installed and the interface has no v6, the client
  adds an unreachable `::/0` to the NetBird table
  (`client/internal/routemanager/systemops/systemops_linux.go:193`).
- In legacy routing mode, a v4 default additionally installs `::/1` and
  `8000::/1` as a blackhole path when there is no v6
  (`systemops_generic.go:227`, `:273`).
- Management can synthesize a paired `-v6` exit route. `ExpandV6ExitPairs`
  adds the v6 counterpart to a v4 exit selection (`route/route.go:236`), and
  `V6ExitMergeSet` hides the paired v6 route from the UI (`route/route.go:250`).
- `mirrorV6ExitPairSelections` keeps the v6 pair's selection in sync with the v4
  base (`client/internal/routemanager/manager.go:757`).
- IPv6 forwarding is requested only through the forwarding state used for
  server-side routes (`client/internal/routemanager/ipfwdstate/ipfwdstate.go:114`),
  and it raises `accept_ra=2` before flipping forwarding on
  (`client/internal/routemanager/systemops/v6forwarding_linux.go:29`).

## Questions

1. How does the client know whether an exit node actually supports IPv6 egress?
2. What happens when a dual-stack client selects a v4-only exit node?
3. Do split policy rules need separate `ip -6 rule` entries?
4. Does adding `::/1` and `8000::/1` cover all IPv6 destinations without
   replacing the main default?
5. What is the fail-closed primitive for IPv6?
6. Does the client need IPv6 forwarding enabled when it is an exit-node user,
   rather than a gateway?
7. How do DNS AAAA answers interact with blocked v6 traffic?
8. What happens on an IPv6-only host or an IPv6-only destination?
9. How are link-local, router advertisements, and temporary privacy addresses
   affected?

## Required environment

- A disposable VM with a global IPv6 default route and working IPv6 egress.
- A NetBird exit node that supports IPv6, and a second exit node that supports
  only IPv4.
- `nft`, `ip`, `sysctl`, `dig`, `tcpdump`, and `curl`.
- Root in the disposable VM for the real-interface test. The unprivileged
  namespace probe needs `unshare` and `python3`.
- A control plane that can advertise a v4-only exit node and a dual-stack exit
  node.

## Exact commands and script references

Run the namespace probe:

```bash
./scripts/split-tunnel-spikes/ipv6-exit-node.sh
```

Manual probes in the disposable VM:

```bash
ip -6 rule show
ip -6 route show table main
ip -6 route show table 7120
ip -6 route get 2001:4860:4860::8888
sysctl net.ipv6.conf.all.forwarding
sysctl net.ipv6.conf.all.accept_ra
dig +noall +answer AAAA example.com

# With NetBird connected to a v4-only exit node:
curl -6 -sS --max-time 5 https://ifconfig.co || echo "IPv6 blocked as expected"
tcpdump -ni any 'ip6 and not (net fe80::/10)'

# With NetBird connected to a dual-stack exit node:
curl -6 -sS --max-time 5 https://ifconfig.co
```

The split table must contain a v6 fail-closed path even when the exit node has
no v6:

```text
ip -6 route add unreachable default table <split table>
```

If the split table uses a policy rule, it must be an IPv6 rule:

```text
ip -6 rule add priority 108 fwmark 0x1bd01/0xff lookup <split table>
```

## Executed observations (2026-11-27)

All IPv6 routing tests ran in `unshare -Urn --map-root-user` namespaces. The
host was inspected read-only.

- The probe host had no global IPv6 default route at the time: `ip -6 route`
  showed link-local `fe80::/64` routes and no `default`. This is why the v6
  routing tests used a namespace with dummy interfaces.
- A v4 `ip rule` did not affect v6 lookups. Adding the same rule with
  `ip -6 rule` made the v6 lookup use the split table. IPv4 and IPv6 policy
  rules are separate.
- `::/1` plus `8000::/1` covered both `2001:db8:dead::1` and `fd00::1`, and the
  main `default dev dB` route was preserved.
- A v6 table with only a specific route fell through to the main default for an
  uncovered destination. That is a leak path.
- Adding `unreachable default` to the v6 table made the uncovered lookup fail
  with `No route to host`, while the covered specific route still worked.
- `net.ipv6.conf.all.forwarding` and `net.ipv6.conf.all.accept_ra` were
  writable inside the network namespace.
- `TestExpandV6ExitPairs` and
  `TestUpdateRouteSelectorFromManagement_MirrorsV6ExitPair` passed. These confirm
  that a v4 exit node with a v6 counterpart expands to both NetIDs and that a v4
  deselect mirrors onto the v6 pair.

## Planned experiments (pending)

These need a disposable VM with real IPv6 and real exit nodes.

1. **Dual-stack exit node.** Verify that `curl -6` egresses through the exit
   node and that the exit node's external v6 address is observed.
2. **V4-only exit node.** Select a v4-only exit node on a dual-stack client and
   verify that protected v6 traffic is blocked, not sent through the physical
   default.
3. **No v6 overlay.** Start the client with no v6 overlay address and verify
   that `HasIPv6()` is false, v6 AllowedIPs are filtered, and the v6 blackhole
   is installed.
4. **IPv6-only destination.** Test a destination with only AAAA records and
   verify the user-visible behavior when v6 is blocked. Verify whether the
   application falls back or reports a failure.
5. **Router advertisements and privacy addresses.** On a host that receives RAs,
   verify that `accept_ra=2` and forwarding changes do not remove the physical
   default or break the physical v6 path.
6. **DNS AAAA policy.** Decide whether blocked domains return NODATA for AAAA or
   return the address and rely on the firewall. Test both with a browser.
7. **Link-local and NDP.** Verify that link-local traffic, neighbor discovery,
   and the overlay's own v6 traffic are not blocked by the split rules.
8. **Path MTU and ICMPv6.** Verify that ICMPv6 Packet Too Big is not dropped and
   that v6 traffic does not black-hole.
9. **Gateway masquerade.** Verify that the exit node masquerades v6 traffic and
   that return traffic reaches the client.
10. **IPv6-only host.** Test a host with no usable IPv4 path and record the
    behavior when the exit node is v4-only.

## Expected observations

- A v4-only exit node on a dual-stack client leaves protected v6 with no
  authorized gateway. Without a blackhole, it follows the physical default.
- `unreachable default` in the v6 split table is the reliable fail-closed
  primitive.
- `::/1` plus `8000::/1` is a complete split default and does not replace the
  main default in the legacy path.
- V4 and v6 policy rules are independent; both are required.
- The client does not need IPv6 forwarding when it is only a tunnel user. The
  gateway needs forwarding and masquerade.

## Decision criteria

GO for IPv6 exit-node support when all of the following hold:

- The overlay has a v6 address and the exit node advertises a v6 route (`::/0`
  or the paired `-v6` route).
- The exit node is verified to have working v6 egress.
- The split table has an `unreachable default` for v6 whenever protected v6 does
  not have an authorized route.
- The v6 blackhole is installed in the same transaction as the v4 policy, not
  after a best-effort delay.
- Kill-switch rules cover v6, including replies and forwarded traffic.
- DNS AAAA behavior is defined and tested.

Otherwise, protected v6 is blocked and the UI explains why.

## Decision

GO conditional on explicit gateway capability and fail-closed v6 defaults.

- One active exit node, as in 1.0. A v4 exit node may have a paired v6 route.
  The pair is selected and deselected together.
- If the exit node has no v6 route, install `unreachable default` for v6 in
  every protected split table. Do not rely on the host default.
- Use a separate v6 policy rule and a separate v6 nftables family table. The
  upstream `family6` component is created only when the overlay has v6
  (`client/firewall/nftables/manager_linux.go:81`).
- Do not enable IPv6 forwarding on a client that only uses an exit node.
  Forwarding belongs to the exit-node gateway.
- In strict mode, block protected v6 on any ambiguity. In include mode, DIRECT
  v6 traffic is allowed only if the policy explicitly permits it.
- Expose v6 capability and the blocked state in status and diagnostics.

## Fallback

- Disable the IPv6 overlay for the client and block all protected v6. This is
  the safest fallback for a v4-only exit node.
- Use the legacy split-default path (`::/1` and `8000::/1`) only when advanced
  routing is unavailable, and keep the blackhole behavior.
- If the user needs IPv6 egress, require an exit node that advertises and
  verifies v6 support.

## Risks

- **Physical v6 default.** A protected v6 packet without an authorized route
  will use the physical default. The unreachable default is mandatory.
- **Rule family separation.** A v4 `ip rule` does not cover v6. Both rule sets
  must be installed and cleaned up.
- **Router advertisements.** Flipping forwarding can change RA acceptance.
  Upstream bumps `accept_ra=2` and restores the saved values; the split engine
  must not fight that logic.
- **Privacy and temporary addresses.** Source address selection may change as
  temporary addresses rotate. Verify the exit node accepts the selected source.
- **ICMPv6 and NDP.** Blocking too broadly can break neighbor discovery, path
  MTU, or the overlay itself.
- **DNS AAAA.** Returning AAAA records for blocked v6 destinations can cause
  application timeouts. Decide between NODATA, blocking, and Happy Eyeballs
  behavior.
- **NAT66 and masquerade.** The exit node must masquerade v6 if it provides v6
  egress. Verify return routing.
- **Pair merge bugs.** The v4 and v6 exit routes are synthesized and mirrored.
  A deselect bug can orphan a `::/0` route and leak v6 onto the tunnel or the
  physical path.
- **IPv6-only host.** A host with no IPv4 path cannot use a v4-only exit node.
  The failure must be clear, not a silent blackhole.

## Current status

- Spike result: GO conditional on gateway capability and fail-closed v6.
- Executed: v6 policy rule family separation, split-default coverage, table-miss
  leak, unreachable `::/0` fail-closed, forwarding and `accept_ra` writability,
  v6 exit pair expansion and selection mirroring tests.
- Pending privileged execution: real dual-stack and v4-only exit nodes, v6
  egress verification, no-v6 overlay, IPv6-only destinations, RA/privacy
  addresses, DNS AAAA policy, NDP/PMTUD, gateway masquerade, and IPv6-only host.
- Not started: production v6 split policy and AAAA policy.

## Upstream integration points

- `client/iface/wgaddr/address.go:33` is the capability gate for every local v6
  path. Treat missing v6 as "skip the v6 work", not as a fatal error.
- `client/internal/routemanager/systemops/systemops_linux.go:175` installs VPN
  routes and `:193` installs the v6 blackhole when the interface has no v6.
- `client/internal/routemanager/systemops/systemops_generic.go:212` and `:273`
  implement the legacy split defaults. Reuse only when advanced routing is off.
- `client/internal/routemanager/systemops/v6forwarding_linux.go:29` enables v6
  forwarding and manages `accept_ra`. Do not duplicate its save/restore logic.
- `client/internal/routemanager/ipfwdstate/ipfwdstate.go:114` reference-counts
  forwarding requests. A client exit-node user must not request it.
- `route/route.go:229` and `:233` identify default routes; `:236` and `:250`
  expand and merge the v6 exit pair.
- `client/internal/routemanager/manager.go:757` mirrors the v6 pair selection.
  Split policy must use the same selection source to avoid an orphaned `::/0`.
- `client/internal/routemanager/selection.go:23` expands v6 pairs on select and
  deselect. Split policy changes must go through the same path.
- `client/internal/engine.go:1996` and `:2911` filter v6 AllowedIPs when the
  local interface has no v6.
- `client/firewall/nftables/manager_linux.go:81` creates the v6 family only when
  the overlay has v6. Split v6 rules need the same capability check.
- `client/internal/dns` must decide the AAAA policy for blocked domains.
- GUI and CLI must expose v6 capability, the blocked state, and the reason.

## References

- Spec §8.2: validate IPv6 routes and fail-closed behavior.
- Spec §9: if IPv6 egress is not supported by the gateway, protected IPv6
  traffic must be blocked.
- Spec §10: kill-switch protection covers IPv4 and IPv6.
- Spec §26.1: establish supported IPv6 exit-node behavior and fallback blocking.
- RFC 4861: Neighbor Discovery for IPv6.
- RFC 8200: IPv6 specification.
- RFC 6724: default address selection for IPv6.
