# ADR: packet marking, policy routing, source selection, and fail-closed behavior

- Status: Accepted, GO with a mandatory unreachable default in every protected table
- Date: 2026-11-27
- Issue: #3 (M01), parent #1
- Spec: §8.1, §8.2, §9, §10, §26.1

## Context

Spec §8.1 proposes a product-owned `inet netbird_split` table with classify,
connection, enforce, and kill-switch chains. It explicitly says to use route-type
output hooks when rerouting after a mark change is required. Spec §8.2 requires
policy routing tables with deterministic table IDs, fwmark bits, and rule
priorities, and states that a protected route must not fall through to physical
egress when its VPN table is unavailable. Spec §10 requires protection to
survive a daemon failure and to cover IPv4 and IPv6.

Upstream NetBird already uses fwmark-based advanced routing. The defaults are:

- `ControlPlaneMark = 0x1BD00` (`client/net/fwmark.go:47`).
- Data plane marks from `0x1BD10` to `0x1BDFF` (`client/net/fwmark.go:50`).
- VPN table ID `0x1BD0` (7120), named `netbird`
  (`client/internal/routemanager/systemops/systemops_linux.go:47`).
- Rules at priority 105 (main, `suppress_prefixlength 0`) and priority 110 (not
  `0x1BD00`, lookup the NetBird table) (`systemops_linux.go:80`).
- Loose reverse-path filtering and `src_valid_mark=1`
  (`client/internal/routemanager/sysctl/sysctl_linux.go:37`, `:44`).

The probe host had exactly these rules installed, which is why all privileged
routing experiments were run in isolated network namespaces instead of on the
host.

## Questions

1. Does setting `meta mark` in a normal `filter` output chain change the egress
   route for locally generated packets?
2. Does a `type route` output chain force a new route lookup after the mark is
   set?
3. Is `SO_MARK` on the socket honored by policy routing? This is the mechanism
   upstream uses for control-plane traffic.
4. What happens when a marked packet's table exists but has no matching route?
5. Does an `unreachable default` in the table make the lookup fail closed?
6. How do source address selection and `pref src` behave with a marked route?
7. Where must split rules sit relative to upstream priorities 105 and 110, and
   what happens if the split table misses?
8. Do fwmark masks isolate one split class from another?

## Required environment

- Linux with netlink policy routing, nftables, `meta mark`, and `SO_MARK`.
- Root or a user and network namespace with `CAP_NET_ADMIN`. The probe used
  unprivileged user and network namespaces (`unshare -Urn`), which is enough to
  create dummy interfaces, routes, rules, and nftables tables inside the
  namespace.
- `nft`, `ip`, `python3`, and `unshare`.
- A disposable VM for the end-to-end experiment with a real NetBird interface,
  a real exit node, and real WireGuard transport.

## Exact commands and script references

Run the reproducible probe:

```bash
./scripts/split-tunnel-spikes/routing-fail-closed.sh
```

The script runs two isolated namespace experiments:

- The first covers marking, rerouting, source selection, masks, and the
  unreachable-default behavior.
- The second reproduces the upstream rule layout (105 and 110) and shows where
  the split rule must be placed, and what a split-table miss does in that
  layout.

The essential rule shapes are:

```text
# Route-type output chain. The mark is applied before the forced route lookup.
nft add chain inet netbird_split classify_output \
  '{ type route hook output priority mangle; }'
nft add rule inet netbird_split classify_output \
  socket cgroupv2 level <N> "<cgroup path>" meta mark set 0x1bd01

# Split policy rule, after upstream 105 and before upstream 110.
ip rule add priority 108 fwmark 0x1bd01/0xff lookup <split table>

# Fail closed when no route in the split table matches.
ip route add unreachable default table <split table>
ip -6 route add unreachable default table <split table>
```

## Executed observations (2026-11-27)

All routing experiments ran in `unshare -Urn --map-root-user` namespaces with
dummy interfaces. The host `ip rule` output was unchanged after each run.

- **No mark** used the main default route.
- **`SO_MARK` on the socket** selected the marked policy table. This confirms the
  upstream control-plane mechanism works for local sockets.
- **`filter` output chain with `meta mark set`** did not reroute the packet. The
  packet still left through the main default. The output filter hook runs after
  the initial route lookup for locally generated traffic.
- **`type route` output chain with `meta mark set`** did reroute the packet. The
  packet left through the marked table's interface. This confirms the spec's
  instruction to use a route-type output hook.
- **Table miss without a default** fell through to the next rule. In the simple
  layout it fell through to the main default, which is a physical leak. In the
  upstream-like layout (105, 110) it fell through to the upstream NetBird table,
  which is not a fail-closed result either.
- **`unreachable default` in the table** made the marked lookup fail with
  `No route to host`. A covered specific route in the same table still worked.
- **Source selection** followed the selected route. A route with an explicit
  `src 10.10.0.99` used that address; otherwise the kernel used the primary
  address of the egress interface.
- **Mark masks** worked as expected. A rule for `0x1bd01/0xff` matched
  `0x1bd01` and `0x1bd101` (same low byte) and did not match `0x1bd02`.
- **Rule priority** mattered. With rules 105, 108, and 110, a split mark at 108
  selected the split table before the upstream rule at 110. The control-plane
  mark `0x1bd00` at 108 did not match and fell through to main, which is the
  intended control-plane bypass. Unmarked traffic reached the upstream-like
  table at 110.
- **Split table miss in the upstream-like layout** fell through to rule 110 and
  the upstream table, not to main. Adding an unreachable default to the split
  table stopped the lookup before rule 110.

## Planned experiments (pending)

These need a disposable VM with real NetBird and WireGuard state.

1. **Real interface and real exit node.** Install the split table alongside the
   upstream `netbird` table, connect to a real exit node, and verify that a
   marked application uses the exit node while an unmarked application uses the
   physical address. Capture packets on both egress paths.
2. **Disconnect behavior.** Remove the exit-node route or stop the tunnel and
   verify that marked protected traffic is blocked, not redirected to the
   physical default. Repeat for IPv4 and IPv6.
3. **Daemon crash.** Kill the daemon while protected traffic is active. Verify
   that the nftables rules and unreachable defaults persist and continue to
   block, and that a restart reconciles only product-owned objects.
4. **Third-party firewall coexistence.** Run with firewalld or another nftables
   manager that has output mangle chains, and verify the chosen priority and
   mark range do not collide.
5. **Netlink monitoring.** Change the physical default route, the gateway, and
   the interface addresses. Verify the DIRECT table and source selection are
   reconciled.
6. **Reverse-path filtering and source validation.** Test with the upstream
   `rp_filter=2` and `src_valid_mark=1` settings, and with strict rp_filter, to
   confirm marked return traffic is accepted.
7. **Conntrack marks.** Test whether per-connection marks are needed for
   replies. Packet marks are not conntrack marks; do not assume reply packets
   inherit the mark.
8. **Rule cleanup.** Verify that rollback and `netbird down` remove only the
   split rules, tables, and marks, and leave upstream and third-party objects
   intact.

## Expected observations

- A route-type output chain reroutes after a mark change; a filter output chain
  does not.
- A table miss is not fail-closed by itself. It continues policy rule
  evaluation.
- An unreachable default in the split table is the mechanism that makes the
  protected class fail closed.
- A split rule placed at priority 108 runs after upstream main precedence (105)
  and before upstream VPN routing (110).
- Without a split rule before 110, every non-control-plane mark is still sent to
  the upstream NetBird table by rule 110.
- Source selection follows the route table selected by the mark, with `pref src`
  overriding the primary address.

## Decision criteria

GO when all of the following hold:

- Marking happens before the route lookup, using a `type route` output chain or
  an equivalent pre-routing mechanism.
- Every protected policy table has an `unreachable default` for IPv4 and IPv6,
  installed and removed in the same transaction as its routes.
- Split policy rules have a documented priority between upstream 105 and 110,
  verified against the running upstream rule set. A collision fails startup
  rather than silently changing behavior.
- Split fwmarks are disjoint from `0x1BD00` and the upstream data-plane range.
- Source selection is correct for the exit-node and DIRECT paths.
- Teardown removes only split-owned objects and leaves a blocking state in
  place when a protected table cannot be removed safely.

NO-GO if the design relies on a filter output chain alone, or if a split table
can miss without an unreachable default.

## Decision

GO with a separate split table and explicit fail-closed defaults.

- Use `inet netbird_split` with a route-type output chain for local traffic.
  Do not use `SO_MARK` as the split classifier; reserve it for control-plane
  traffic as upstream already does.
- Place split policy rules at priority 108 (or another free priority strictly
  between 105 and 110). Verify the actual priorities at startup.
- Reserve split marks from the free low offsets of the upstream base, for
  example `0x1BD01` through `0x1BD0F`. The upstream data plane uses
  `0x1BD10` and above, and control plane uses `0x1BD00`. Add a startup collision
  check and document the allocation.
- Every protected table gets `unreachable default` for both families. This is
  not optional; it is the fail-closed primitive.
- Use the policy tables from spec §8.2: a VPN table, a DIRECT table, a BLOCK
  table, and one table per future exit node. Do not reuse the upstream table.
- Reconcile routes when the physical default, gateway, or interface address
  changes. Upstream already has a notifier and sysops path for this.
- Persist enough state to restore protection after a daemon restart or crash,
  and remove only owned objects on cleanup.

## Fallback

- If rule priority cannot be made safely between 105 and 110, use a dedicated
  higher-priority table for split classes and adjust the upstream rule set only
  through a reviewed upstream-compatible change. Do not silently renumber
  upstream rules at runtime.
- If a protected table cannot be installed, keep the existing kill-switch rules
  and block the affected traffic. Do not remove the old table first.
- If policy routing is unsupported, fall back to the legacy routing path and
  disable strict split mode with a clear user-visible error.

## Risks

- **Fall-through leak.** A table miss is not a drop. Every protected table needs
  an unreachable default, and tests must assert it.
- **Priority collision.** Upstream or a third-party firewall can use the same
  rule priorities or hook priorities. Detect collisions and fail closed.
- **Mark collision.** Another CNI or VPN can claim mark bits. Check the full
  mark at startup and document `NB_FWMARK_BASE` interaction.
- **Reply direction.** Packet marks are not conntrack marks. Replies may take a
  different path unless conntrack state or reverse rules are added.
- **Source selection.** A route in a separate table can select a source address
  that the peer or exit node does not expect. Test with the real overlay
  address and physical address.
- **Reverse-path filtering.** Strict rp_filter can drop marked traffic. Upstream
  already sets loose mode and `src_valid_mark`; the split engine must not
  override those blindly.
- **Daemon crash.** In-memory state is lost. The kernel rules must be enough to
  keep protected traffic blocked until reconciliation.
- **Route churn.** Physical interface changes can leave a stale DIRECT table.
  Monitor netlink and reconcile.
- **Priority inversion with NAT.** A route change after NAT can behave
  differently. Exit-node masquerade is on the server side, but local NAT and
  third-party rules still need testing.

## Current status

- Spike result: GO with a mandatory unreachable default.
- Executed: route versus filter output chains, `SO_MARK`, table-miss leak,
  unreachable default, preferred source, mark masks, and the upstream-like
  priority layout, all in isolated network namespaces.
- Pending privileged execution: real WireGuard exit node, disconnect and crash
  behavior, third-party firewall coexistence, netlink reconciliation, strict
  rp_filter, conntrack reply behavior, and cleanup.
- Not started: production state persistence and startup collision detection.

## Upstream integration points

- `client/net/fwmark.go:21` defines the fwmark base and offsets. Split marks must
  not overlap `ControlPlaneMark` or the data plane range.
- `client/net/env_linux.go:29` decides whether advanced routing is enabled.
  Split mode depends on the same capability probe.
- `client/net/net_linux.go:11` sets `SO_MARK` on control-plane sockets. The
  split engine must not change this behavior.
- `client/internal/routemanager/systemops/systemops_linux.go:80` builds the
  upstream rules. The split rules must fit between 105 and 110.
- `systemops_linux.go:175` and `systemops_linux.go:203` add and remove VPN
  routes. The split engine adds its own tables and must not flush these.
- `systemops_linux.go:645` and `systemops_linux.go:672` implement route and
  unreachable-route installation. Reuse the same netlink batch discipline.
- `systemops_generic.go:212` and `systemops_generic.go:273` implement the
  legacy split-default and v6 split-default behavior. Protocol requirements
  differ; do not reuse the legacy `::/1` trick in the advanced-routing table.
- `client/firewall/nftables/chains_linux.go:27` creates upstream chains at NAT
  source minus one, NAT dest, and mangle priorities. The split table needs a
  documented output-hook priority and must not flush these chains.
- `client/firewall/nftables/routing_linux.go:22` installs server-side NAT for
  routed traffic. Client-side split marking is a different responsibility.
- `client/internal/routemanager/manager.go:562` is the transactional apply point
  for route selection. Split policy apply should follow the same pattern.
- `client/internal/engine.go` owns startup, shutdown, firewall, and route
  manager wiring. Protection persistence and reconciliation belong there.
- `client/internal/routemanager/server/server.go` enables forwarding and NAT for
  an exit-node gateway. The client split path must not enable forwarding.

## References

- Spec §8.1: route-type output hooks, dedicated table, Netlink batches,
  deterministic priorities, owned-object cleanup.
- Spec §8.2: policy tables, fail-closed requirement, source selection and
  reverse-path validation.
- Spec §9: protected IPv6 traffic must be blocked if the gateway cannot egress
  it.
- Spec §10: kill-switch behavior across disconnect, exit-node unavailability,
  reconnection, and daemon crash.
- Spec §26.1: prove marking, route recalculation, source selection, and
  fail-closed behavior.
