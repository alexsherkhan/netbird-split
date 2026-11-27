#!/usr/bin/env bash
set -euo pipefail

# WARNING: Run this script only in a disposable VM or an isolated network
# namespace. This script only reads the resolver configuration and runs unit
# tests, so it does not change host networking, but run it only on a disposable
# system. Never run it on a workstation or server whose connectivity matters.

cd "$(git rev-parse --show-toplevel)"

echo "== resolver configuration (read-only) =="
if [[ -L /etc/resolv.conf || -f /etc/resolv.conf ]]; then
    grep -vE '^(#|;|$)' /etc/resolv.conf || true
fi
if command -v resolvectl >/dev/null 2>&1; then
    resolvectl status --no-pager 2>/dev/null | sed -n '1,25p' || true
fi
echo

echo "== handler chain ordering and priority tests =="
go test ./client/internal/dns/ -count=1 -v \
    -run 'TestHandlerChain_ServeDNS_Priorities|TestHandlerChain_DomainSpecificityOrdering|TestHandlerChain_ServeDNS_ChainContinuation|TestHandlerChain_ResolveInternal_SkipsAboveMaxPriority'

echo "== management cache TTL and stale-while-revalidate tests =="
go test ./client/internal/dns/mgmt/ -count=1 -v \
    -run 'TestResolver_ServeDNS|TestResolver_ResponseTTL|TestResolver_CacheTTLGatesRefresh|TestResolver_StaleTriggersAsyncRefresh'

echo "PASS: DNS ordering and TTL probes"
