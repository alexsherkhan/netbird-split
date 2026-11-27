# ADR: Multiple simultaneous Exit Nodes

- Status: Accepted, NO-GO for 1.0; research item for 1.1
- Date: 2026-11-27
- Issue: #3 (M01), parent #1
- Spec: §8.2, §9, §26.1

## Context

Spec §9 limits 1.0 to one active authorized exit node. It states that multiple
simultaneous exit nodes are a separate research milestone because overlapping
WireGuard AllowedIPs on a single interface cannot be solved by policy routing
tables alone. It requires separate interfaces or upstream-compatible peer
selection changes, including authentication, relay transport, and ACL
semantics, and it forbids claiming compatibility until experimentally
validated. Spec §1.2 lists simultaneous multiple exit nodes as P1 for 1.1,
subject to feasibility.

The current client enforces a single exit node in several places:

- `SelectRoutes` and `selectRoutes` deselect every other exit node when a
  selection activates one (`client/internal/routemanager/selection.go:23`,
  `selection.go:84`).
- `SelectAllRoutes` reconciles the selection to one node
  (`selection.go:61`).
- `enforceSingleExitNode` calls `RouteSelector.SetExclusiveExitNode`
  (`client/internal/routemanager/manager.go:847`,
  `client/internal/routeselector/routeselector.go:136`).
- The peer routing lookup treats a prefix with zero bits as an exit node
  (`client/internal/peer/route.go:102`).
- The AllowedIPs refcounter is explicitly peer-aware because WireGuard allows a
  prefix on exactly one peer. Its comment states that when a different peer
  already owns the prefix, the first peer wins and HA at the WireGuard layer is
  not possible (`client/internal/routemanager/refcounter/allowedips.go:16`).
- The configurer store repeats the invariant: an allowed IP belongs to exactly
  one peer, and configuring a prefix on a peer takes it away from the previous
  holder (`client/iface/configurer/allowedips.go:20`).
- The kernel configurer applies allowed IPs to one device
  (`client/iface/configurer/kernel_unix.go:198`).

## Questions

1. Why can policy routing alone not provide two simultaneous exit nodes on one
   interface?
2. Can one WireGuard interface carry `0.0.0.0/0` on two peers? What does the
   kernel do with the second assignment?
3. Can multiple interfaces, each with its own peer and default route, solve the
   problem while keeping the server unchanged?
4. What is required for per-application exit-node selection?
5. What is required for authentication, relay transport, and ACL semantics?
6. What are the resource and lifecycle costs?
7. What is the minimum viable 1.1 experiment?

## Required environment

- A disposable VM with a real WireGuard interface, root, and two exit nodes
  reachable through an unmodified NetBird management, signal, and relay stack.
- Two exit nodes with distinct public keys and distinct external addresses.
- `wg`, `ip`, `nft`, `tcpdump`, and `curl`.
- A control plane that can advertise two exit-node routes.
- The unprivileged namespace probe for the routing table layout. The real
  WireGuard peer experiment needs root and a disposable VM.

## Exact commands and script references

Run the read-only unit evidence:

```bash
./scripts/split-tunnel-spikes/multi-exit-node.sh
```

The script runs:

- `TestSelectRoutes_ExitNodeExclusivity`
- `TestEnforceSingleExitNode`
- `TestUpdateRouteSelectorFromManagement_MirrorsV6ExitPair`
- `TestExpandV6ExitPairs`
- `TestAllowedIPs_SwapOnActivePeerRemoval`
- `TestAllowedIPs_SamePeerMultipleRefs`

It then prints the pending privileged commands. The real experiment is:

```bash
# In a disposable VM with one WireGuard interface:
wg show <iface> allowedips
wg set <iface> peer <pubkey-A> allowed-ips 0.0.0.0/0
wg set <iface> peer <pubkey-B> allowed-ips 0.0.0.0/0
wg show <iface> allowedips

# With one interface per exit node:
ip link add dev wg-split-a type wireguard
ip link add dev wg-split-b type wireguard
wg set wg-split-a peer <pubkey-A> allowed-ips 0.0.0.0/0
wg set wg-split-b peer <pubkey-B> allowed-ips 0.0.0.0/0
ip route add default dev wg-split-a table 100
ip route add default dev wg-split-b table 101
ip rule add fwmark 0x1bd01/0xff lookup 100 priority 108
ip rule add fwmark 0x1bd02/0xff lookup 101 priority 109
```

## Executed observations (2026-11-27)

- All listed unit tests passed. The in-process model explicitly treats an
  AllowedIP prefix as a singleton owned by one peer and hands it over on
  removal; it does not model two active owners.
- The selection tests confirm that selecting one exit node deselects its
  siblings and that the v6 pair follows the v4 base.
- The v4/v6 pair expansion test confirms that a v4 exit node with a `-v6`
  counterpart expands to both NetIDs.
- No privileged WireGuard peer experiment was run in this worktree. The real
  kernel behavior of two peers with `0.0.0.0/0` on one interface is pending a
  disposable VM.
- No production code was changed.

## Planned experiments (pending)

1. **Single interface, two peers.** Assign `0.0.0.0/0` to peer A, then to peer
   B. Inspect `wg show <iface> allowedips` and `ip route`. Verify that the
   prefix has one owner and that the second assignment moves it.
2. **Separate interfaces.** Create two WireGuard interfaces, one per exit node,
   each with `0.0.0.0/0` and its own policy table. Verify that marked traffic
   reaches the intended exit node and that the external address matches.
3. **Handshake and transport.** Verify that each interface can complete a
   handshake through the existing signal and relay services, with one NetBird
   identity and the existing authentication flow.
4. **ACL semantics.** Verify that server-side ACLs still apply per peer and per
   resource when two exit nodes are active.
5. **Relay allocation.** Measure relay sessions and resources with two active
   exit nodes.
6. **Per-application selection.** Assign one application to exit A and another
   to exit B with distinct marks and tables. Verify with external IP checks and
   packet capture.
7. **Failure isolation.** Take one exit node down and verify that its assigned
   applications are blocked or moved according to policy, while the other exit
   node keeps working.
8. **Lifecycle.** Add and remove the second interface while traffic is active.
   Verify route, rule, AllowedIPs, and state cleanup.
9. **IPv6.** Repeat with dual-stack exit nodes and with one v4-only node.
10. **Management compatibility.** Confirm that an unmodified management service
    can advertise and authorize two exit nodes without a protocol change. If a
    change is required, treat it as a separate upstream-compatible proposal.

## Expected observations

- On one interface, the prefix `0.0.0.0/0` has exactly one owning peer. The
  second assignment moves ownership; it does not create two paths.
- Policy routing tables can select different interfaces, but they cannot split
  one WireGuard interface's AllowedIPs between two peers.
- Two interfaces can each own `0.0.0.0/0` and be selected by mark and policy
  table.
- Each interface adds a peer, a handshake path, transport state, and resource
  cost. The management and ACL model must still authorize both.

## Decision criteria

GO for multiple exit nodes only when all of the following hold:

- Two exit nodes can be active simultaneously without changing the upstream
  management, signal, or relay protocols, or with a fully backward-compatible
  addition.
- Each application or policy rule is assigned to exactly one exit node, and the
  assignment is enforceable with marks and policy tables.
- Server-side ACLs and authentication remain per peer and are not weakened.
- Failure of one exit node does not silently move its protected traffic to the
  physical default or to another unauthorized exit node.
- The resource cost and lifecycle are acceptable for the target desktop.
- The UI can explain which application uses which exit node.

NO-GO if the design requires overlapping AllowedIPs on one interface, if it
requires an unauthenticated or non-upstream peer selection, or if it cannot
fail closed per exit node.

## Decision

NO-GO for 1.0. The 1.0 client keeps one active exit node.

For 1.1, the research direction is a separate WireGuard interface per exit
node, each with its own policy table, mark, routes, and lifecycle. A
single-interface peer-selection change is not acceptable unless an upstream
protocol design is agreed and experimentally validated.

The 1.1 prototype must cover:

- authentication and peer authorization for each exit node;
- signal and relay transport per interface;
- ACL enforcement per exit node;
- per-application assignment and fail-closed behavior;
- IPv4 and IPv6;
- resource limits and cleanup;
- GUI, CLI, and local API status.

## Fallback

- 1.0 supports one active exit node. Switching exit nodes is a selection change
  that may interrupt flows; the client already deselects siblings.
- Users who need two egress paths can use two machines or two profiles that are
  not active simultaneously. This is a product limitation, not a claim of
  simultaneous support.
- Multi-exit support remains P1 for 1.1 and is not promised until the
  experiments above pass.

## Risks

- **AllowedIPs overlap.** The core blocker. One interface cannot route the same
  prefix to two peers. Policy routing does not change WireGuard's peer
  selection.
- **Protocol compatibility.** Separate interfaces may still need management,
  signal, and relay changes. Any change must be additive and backward
  compatible with released clients.
- **Authentication and ACL.** A second exit node must not bypass group,
  posture, or route ACLs.
- **Relay and resource cost.** Each interface and peer adds handshakes, relay
  sessions, and state.
- **Failure isolation.** Losing one exit node must not degrade the other or
  leak traffic.
- **Routing complexity.** Multiple marks, tables, rules, and source addresses
  increase the chance of a priority or cleanup bug.
- **UI complexity.** Users need to understand per-application exit selection
  and failure states.
- **Testing cost.** The matrix grows with exit-node count, address family, and
  transport.

## Current status

- Spike result: NO-GO for 1.0. This matches spec §9 and the 1.1 P1 priority.
- Executed: unit tests for exit-node exclusivity, v6 pair expansion, and
  AllowedIPs singleton handover. Code inspection of the peer and configurer
  invariants.
- Pending privileged execution: the real WireGuard peer experiment, separate
  interface prototype, handshake and relay validation, ACL validation,
  per-application selection, failure isolation, IPv6, and management
  compatibility.
- Not started: any 1.1 implementation.

## Upstream integration points

- `client/internal/routemanager/selection.go:23` and `:84`: exit-node
  exclusivity. A future multi-exit design must change this policy without
  breaking the single-exit path.
- `client/internal/routemanager/manager.go:847` and
  `client/internal/routeselector/routeselector.go:136`: the single-exit
  reconciliation.
- `client/internal/routemanager/refcounter/allowedips.go:16`: the peer-aware
  AllowedIPs invariant. Multi-exit cannot reuse one counter across one device
  for two owners of `0.0.0.0/0`.
- `client/iface/configurer/allowedips.go:20` and
  `client/iface/configurer/kernel_unix.go:198`: the single-device AllowedIPs
  store and kernel write path. A second interface needs its own device and
  configurer.
- `client/iface/iface.go:180`: the public AddAllowedIP surface. Multi-interface
  support must not change the single-interface contract for existing callers.
- `client/internal/peer/route.go:102`: exit-node detection by prefix length.
  Multiple exit nodes need a resource-to-exit mapping, not a global default.
- `client/net/fwmark.go:21`: split marks per exit node must not collide with
  upstream marks or with each other.
- `client/internal/routemanager/systemops/systemops_linux.go:80`: policy rule
  priority allocation must remain stable as the number of exit nodes grows.
- `client/internal/engine.go`: lifecycle, peer setup, and firewall wiring must
  handle N interfaces and N exit assignments.
- Management, signal, relay, and proxy: only additive, backward-compatible
  changes are acceptable. A server change is a separate proposal.

## References

- Spec §1.2: simultaneous multiple exit nodes is P1 for 1.1, subject to
  feasibility.
- Spec §8.2: policy tables include `SPLIT_EXIT_N` for future independent exit
  nodes.
- Spec §9: overlapping AllowedIPs on one interface cannot be solved by policy
  routing tables alone; separate interfaces or upstream-compatible peer
  selection changes are required.
- Spec §26.1: investigate simultaneous multiple exit nodes independently of
  1.0.
- WireGuard AllowedIPs semantics: a prefix is owned by one peer per interface.
