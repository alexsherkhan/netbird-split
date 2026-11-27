# ADR: DNS observation ordering, TTL/refcount handling, and shared caches

- Status: Accepted, GO with a new observer handler above upstream
- Date: 2026-11-27
- Issue: #3 (M01), parent #1
- Spec: §7, §8.1, §26.1

## Context

Spec §7 requires domain rules to support exact names, wildcard subdomains,
A/AAAA, CNAME chains, and TTL expiry. It requires the kernel sets to be updated
before the DNS response is released, TTLs to be respected, and multiple names
that reference the same IP not to remove shared entries prematurely. It also
requires upstream private DNS zones to be preserved and the limitations of DoH,
DoT, shared CDN IPs, and application caches to be disclosed.

The current client has a prioritized DNS handler chain
(`client/internal/dns/handler_chain.go:44`). Priorities are:

| Handler | Priority |
|---|---|
| Management cache | 150 (`handler_chain.go:21`) |
| DNS route interceptor | 100 (`handler_chain.go:22`) |
| Local zones | 75 (`handler_chain.go:23`) |
| Upstream resolvers | 50 (`handler_chain.go:24`) |
| Default | 1 |
| Fallback original nameservers | -100 (`handler_chain.go:26`) |

`dispatch` tries matching handlers in descending priority
(`handler_chain.go:203`). A handler either writes a response, which ends the
chain, or writes a continue signal (`RcodeNameError` with the zero bit) so the
next handler is tried (`handler_chain.go:72`). A handler cannot observe the
response written by a handler it delegates to.

The DNS route interceptor already implements the "update routing before
responding" pattern. `writeMsg` updates routes and AllowedIPs
(`client/internal/routemanager/dnsinterceptor/handler.go:353`), waits for route
settlement (`handler.go:360`), rewrites the answer, and only then writes it
(`handler.go:366`). It is not a TTL store: `updateDomainPrefixes`
(`handler.go:389`) replaces the prefix set for a resolved domain and does not
expire entries by the DNS TTL.

The management cache has a separate fixed TTL of 300 seconds and a
stale-while-revalidate refresh (`client/internal/dns/mgmt/mgmt.go:27`,
`mgmt.go:111`, `mgmt.go:436`). That is appropriate for NetBird infrastructure
names, not for user domain rules.

## Questions

1. Where in the handler chain should split-domain observation sit so that
   private DNS zones and upstream DNS routes keep precedence?
2. How can an observer see the upstream answer, update kernel sets, and still
   return the original answer without a second DNS server or an application
   proxy?
3. What happens if the kernel set update fails? Is the DNS answer still
   returned?
4. How are TTLs represented and expired?
5. How are shared IPs tracked when several domains resolve to the same address?
6. How are CNAME chains and the effective expiry computed?
7. What happens when an application or the system resolver caches an answer and
   the client never observes the query?
8. What happens with DoH, DoT, ECH, and DNS rebinding?
9. Should the resolver itself use VPN or DIRECT?

## Required environment

- A disposable VM or an isolated network namespace with NetBird DNS enabled.
- A resolver mode for the test: the probe host used `systemd-resolved` with the
  stub at `127.0.0.53`, and NetBird listened on the overlay address
  `100.109.113.166:53`. A second test should use `resolvconf` or a static
  `/etc/resolv.conf`.
- A local authoritative DNS server or a controlled upstream for deterministic
  TTLs and CNAME chains.
- `dig` or `kdig`, `tcpdump`, and the NetBird debug logs.
- A disposable desktop profile for Firefox and Chromium cache tests.

## Exact commands and script references

Run the read-only ordering and TTL tests:

```bash
./scripts/split-tunnel-spikes/dns-ordering.sh
```

The script prints the resolver configuration, then runs the handler chain tests
and the management cache TTL tests. It does not change resolver configuration.

Manual probes for the disposable VM:

```bash
# Observe which server answers and whether the client's DNS server is in path.
resolvectl status
dig +noall +answer example.com
dig +noall +answer +tcp example.com
tcpdump -ni any 'udp port 53 or tcp port 53'

# Inspect the handler chain and priority decisions.
# Set NB_LOG_LEVEL=trace and search for "handler chain" and "question:".
```

The planned observer handler shape is:

```go
// Register above upstream (50) but below local (75) so private zones win.
dnsServer.RegisterHandler(domains, observer, nbdns.PriorityUpstream+1)

// Inside ServeDNS: resolve through the chain below the observer, update sets,
// then write the original response.
reply, err := chain.ResolveInternal(ctx, req, nbdns.PriorityUpstream)
if err != nil {
    writeSERVFAIL(w, req)
    return
}
if err := updateKernelSets(reply); err != nil {
    writeSERVFAIL(w, req)
    return
}
w.WriteMsg(reply)
```

## Executed observations (2026-11-27)

- `TestHandlerChain_ServeDNS_Priorities`,
  `TestHandlerChain_DomainSpecificityOrdering`,
  `TestHandlerChain_ServeDNS_ChainContinuation`, and
  `TestHandlerChain_ResolveInternal_SkipsAboveMaxPriority` passed. These confirm
  that higher priority wins, equal priority is ordered by domain specificity,
  a continue signal advances the chain, and `ResolveInternal` skips handlers
  above its `maxPriority`.
- `TestResolver_ServeDNS`, `TestResolver_ResponseTTL`,
  `TestResolver_CacheTTLGatesRefresh`, and `TestResolver_StaleTriggersAsyncRefresh`
  passed. These confirm the management cache serves cached A/AAAA records,
  caps the returned TTL at the cache TTL, gates refresh on staleness, and
  refreshes stale entries asynchronously.
- The probe host uses `systemd-resolved` with `/etc/resolv.conf` pointing at
  `127.0.0.53`. NetBird's DNS listener is bound on the overlay address
  `100.109.113.166:53`.
- The code already updates routes and AllowedIPs before writing the DNS
  response in the DNS route path (`dnsinterceptor/handler.go:303`,
  `handler.go:360`). This is a working precedent for the required ordering.
- The code does not track DNS TTLs for user domains. The route interceptor keeps
  the last prefix set per resolved domain and replaces it on the next answer.
- No production resolver configuration was changed.

## Planned experiments (pending)

These need a disposable VM or a controlled DNS server.

1. **Ordering with a real local zone.** Configure a NetBird private DNS zone
   that overlaps `example.com`, add a split rule for `example.com`, and verify
   the private zone still answers and the split set is not applied to the
   private answer.
2. **TTL expiry.** Serve a record with TTL 5, observe the set, wait for expiry,
   and verify the address is removed only after the last domain referencing it
   expires.
3. **Shared IP.** Make `a.example` and `b.example` resolve to the same address,
   then expire one. Verify the other keeps the set entry.
4. **CNAME chain.** Serve `www.example` as a CNAME to `edge.example` with a
   short TTL, verify the effective expiry follows the chain.
5. **Application cache.** Resolve a name, let the application cache it, and
   verify whether a policy change is observed. Repeat with a browser and with
   `nscd` or `systemd-resolved` caching.
6. **DoH/DoT.** Configure the browser to use DoH and verify that queries bypass
   the NetBird DNS server. Record the user-visible limitation.
7. **Resolver failure.** Make the upstream fail while a set entry is live.
   Verify the response is SERVFAIL and the old set is not widened to DIRECT.
8. **Update failure.** Inject a kernel set update failure. Verify the client
   returns SERVFAIL and enters a degraded protection state.
9. **TCP and EDNS.** Test truncated UDP responses, TCP fallback, and large
   answers.
10. **Rebinding.** Serve a private-network address then a public address for the
    same name. Verify mandatory private routes and private zones are not
    overridden.

## Expected observations

- A handler at priority 51 sees only questions that local (75) and route (100)
  handlers did not answer.
- `ResolveInternal(ctx, req, 50)` returns the upstream answer and skips the
  observer itself, so there is no loop.
- Updating kernel sets before `WriteMsg` is possible and adds latency bounded by
  the netlink batch time plus any explicit settlement wait.
- A cached answer that never reaches the client cannot update a set. A TTL-aware
  refresher can reduce but not eliminate this gap.
- DoH and DoT bypass the client resolver and cannot be observed without
  interception, which is out of scope.

## Decision criteria

GO when all of the following hold:

- The observer never overrides a higher-priority private zone.
- The kernel set update completes before the DNS response is written.
- On update failure, the response is not a usable answer that would lead to a
  DIRECT leak. SERVFAIL is acceptable; the exact response is a product decision.
- TTL expiry and shared-IP refcounting are correct under concurrent queries.
- Memory, entry count, and update rate are bounded.
- A missed query due to an application or system cache is detected or disclosed.
- The resolver path does not create a routing loop when NetBird is the system
  resolver.

NO-GO if the design requires TLS interception, if private DNS zones are
overridden, or if a kernel update failure still returns a usable address.

## Decision

GO with a dedicated observer handler at priority 51 and a separate TTL-aware
domain registry.

- The observer resolves through `HandlerChain.ResolveInternal` with
  `maxPriority = PriorityUpstream` (50). This includes upstream, default, and
  fallback handlers and excludes management cache, DNS routes, local zones, and
  the observer itself.
- The observer updates the split sets and, in strict mode, a protected
  unresolved/ambiguous default before writing the answer. On failure it returns
  SERVFAIL and records a protection error.
- A new `DomainRegistry` owns:
  - canonical name and original pattern;
  - A and AAAA addresses;
  - expiry per address, computed from the minimum TTL in the answer;
  - a refcount from every domain that references an address;
  - a bounded set of tracked domains and addresses;
  - a refresher that re-resolves entries before expiry to compensate for
    resolver caches.
- Expiry removes an address only when its refcount reaches zero and the last
  TTL has elapsed. Removal is a single kernel set update.
- CNAME chains are followed from the answer. If the chain is not complete,
  resolve the canonical name through the same chain before installing the set.
- Private DNS zones and DNS routes keep priority. A split rule must not replace
  a private zone answer.
- DoH, DoT, ECH, and application caches are documented limitations. Strict mode
  blocks ambiguous protected traffic within its enforceable scope rather than
  claiming universal domain recognition.

## Fallback

- Standard DNS mode uses destination-IP classification and does not attempt
  per-domain observation. This is the fallback when the observer cannot be
  installed or when the application uses encrypted DNS.
- Pre-resolve explicit names at policy apply time and refresh them on a timer.
  This helps when the application caches an answer but the client never sees the
  query.
- In strict mode, block traffic whose destination is not in a known set instead
  of allowing it to DIRECT.

## Risks

- **Shared CDN IPs.** The same address can belong to several domains with
  different actions. Detect conflicts and use a documented VPN-preferred or
  block policy.
- **Application and system caches.** A cached answer can outlive the observed
  set. TTL refreshers reduce the window; they do not eliminate it.
- **DoH and DoT.** Encrypted DNS bypasses the observer. Disclose it and offer a
  managed resolver where supported.
- **ECH and connection reuse.** The destination IP can be reached before a new
  DNS query is observed. The IP set is the only enforceable signal.
- **TTL zero and negative caching.** A zero TTL means the set entry must not be
  used after the response; negative answers need a separate policy.
- **CNAME and multiple A/AAAA records.** The effective expiry is the minimum
  across the chain and all addresses.
- **DNS rebinding.** A domain rule must not override a mandatory private route
  or private zone, even if the answer points at a private address.
- **Latency.** A synchronous kernel update before the response adds latency.
  Bound it with a netlink batch and a timeout, and fail closed on timeout.
- **Kernel update failure.** If the set cannot be updated, returning the answer
  can leak. SERVFAIL is the safe default.
- **Resolver loop.** If NetBird is the system resolver, forwarding must use the
  handler chain or a marked socket, not the system resolver.
- **Zones.** A wildcard or exact rule can overlap a local zone or a management
  domain. Priority and the registry must make the winner deterministic.

## Current status

- Spike result: GO with a new observer handler and a TTL-aware registry.
- Executed: handler chain ordering, chain continuation, `ResolveInternal`
  priority skipping, management cache TTL and stale refresh tests. Resolver
  configuration was inspected read-only.
- Pending privileged execution: real local zone overlap, TTL expiry, shared IP,
  CNAME, application and system caches, DoH/DoT, upstream failure, kernel update
  failure, TCP/EDNS, and rebinding. These need a disposable VM and a controlled
  DNS server.
- Not started: the `DomainRegistry` implementation and the observer handler.

## Upstream integration points

- `client/internal/dns/handler_chain.go:21` defines the priority table. A new
  priority constant is needed, or use `PriorityUpstream + 1` with a named
  constant.
- `client/internal/dns/handler_chain.go:203` dispatches handlers. The observer
  must not write a continue signal after it has written a final answer.
- `client/internal/dns/handler_chain.go:293` provides `ResolveInternal`, the
  supported way to resolve through the chain without a loop.
- `client/internal/dns/server.go:358` registers handlers, and
  `server.go:564` applies DNS configuration updates. The observer is registered
  and removed with policy updates.
- `client/internal/dns/server.go:736` applies the host resolver configuration.
  The split engine must not bypass this path.
- `client/internal/dns/mgmt/mgmt.go:111` is the existing cache pattern for
  NetBird infrastructure names. Do not reuse its fixed TTL for policy domains.
- `client/internal/routemanager/dnsinterceptor/handler.go:303` and
  `handler.go:360` show the existing "update before response" ordering. Reuse
  the pattern, but update nft sets instead of only routes.
- `client/internal/routemanager/dnsinterceptor/handler.go:389` shows the current
  prefix-set replacement. It lacks TTL and shared-IP refcounting, so it is not
  sufficient for the split registry.
- `client/firewall/nftables` must expose timeout sets or an equivalent update
  path for DNS entries. The split set update must flush in one batch.
- `client/internal/routemanager/systemops` and `client/internal/engine.go` must
  reconcile sets after DNS and policy changes.
- GUI and CLI must show resolved addresses, expiry, conflicts, and the encrypted
  DNS limitation.

## References

- Spec §7: domain rules, TTL, shared IPs, CNAME, DoH/DoT, caches, rebinding,
  private zones.
- Spec §8.1: timeout sets for DNS entries and Netlink batches.
- Spec §26.1: confirm DNS integration ordering and shared resolver and
  application caches.
- RFC 1034 and RFC 1035: DNS TTL semantics.
- RFC 2181 section 5.2: TTL of a resource record set is the minimum TTL of its
  records.
- RFC 8499: DNS terminology for CNAME, canonical name, and caching.
