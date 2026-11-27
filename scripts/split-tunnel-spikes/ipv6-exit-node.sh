#!/usr/bin/env bash
set -euo pipefail

# WARNING: Run this script only in a disposable VM or an isolated network
# namespace. It creates dummy interfaces, IPv6 routes and policy rules inside a
# new network namespace and enables IPv6 forwarding inside that namespace. The
# host network namespace is not modified, but run it only on a disposable
# system. Never run it on a workstation or server whose connectivity matters.

if ! command -v unshare >/dev/null 2>&1; then
    echo "unshare is required (util-linux)." >&2
    exit 1
fi
if ! unshare -Urn true >/dev/null 2>&1; then
    echo "unprivileged user and network namespaces are not available." >&2
    exit 1
fi

unshare -Urn --map-root-user bash -eu -c '
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ip link set lo up
ip link add dA type dummy
ip link set dA up
ip -6 addr add 2001:db8:a::1/64 dev dA nodad
ip link add dB type dummy
ip link set dB up
ip -6 addr add 2001:db8:b::1/64 dev dB nodad

ip -6 route add default dev dB
ip -6 route add ::/1 dev dA table 100
ip -6 route add 8000::/1 dev dA table 100
ip -6 rule add fwmark 0x42/0xff lookup 100 priority 1000

echo "== 1. marked IPv6 traffic uses the split table =="
out=$(ip -6 route get 2001:db8::1 mark 0x42)
[[ "$out" == *"dev dA"* && "$out" == *"table 100"* ]] || fail "expected table 100 via dA: $out"

echo "== 2. unmarked IPv6 traffic stays on the main default =="
out=$(ip -6 route get 2001:db8::1)
[[ "$out" == *"dev dB"* ]] || fail "expected main default via dB: $out"
ip -6 route show table main | grep -q "default dev dB" || fail "main default was replaced"

echo "== 3. split ::/1 and 8000::/1 cover all IPv6 destinations =="
out=$(ip -6 route get 2001:db8:dead::1 mark 0x42)
[[ "$out" == *"dev dA"* && "$out" == *"table 100"* ]] || fail "2001:db8:dead::1 not covered: $out"
out=$(ip -6 route get fd00::1 mark 0x42)
[[ "$out" == *"dev dA"* && "$out" == *"table 100"* ]] || fail "fd00::1 not covered: $out"

echo "== 4. a table miss falls through to the main default until ::/0 is unreachable =="
ip -6 route add 2001:db8:c::/64 dev dA table 101
ip -6 rule add fwmark 0x43/0xff lookup 101 priority 1001
out=$(ip -6 route get 2001:db8:dead::1 mark 0x43)
[[ "$out" == *"dev dB"* ]] || fail "expected fall-through to dB: $out"
ip -6 route add unreachable default table 101
if ip -6 route get 2001:db8:dead::1 mark 0x43 >/dev/null 2>&1; then
    fail "unreachable ::/0 in table 101 did not stop the lookup"
fi
out=$(ip -6 route get 2001:db8:c::5 mark 0x43)
[[ "$out" == *"dev dA"* && "$out" == *"table 101"* ]] || fail "covered route in table 101 stopped working: $out"

echo "== 5. IPv6 forwarding and accept_ra are writable in the namespace =="
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
sysctl -w net.ipv6.conf.all.accept_ra=2 >/dev/null
[[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" == "1" ]] || fail "forwarding sysctl not applied"
[[ "$(cat /proc/sys/net/ipv6/conf/all/accept_ra)" == "2" ]] || fail "accept_ra sysctl not applied"

echo "PASS: IPv6 split-default, fail-closed and forwarding probes"
'
