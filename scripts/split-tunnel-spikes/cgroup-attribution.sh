#!/usr/bin/env bash
set -euo pipefail

# WARNING: Run this script only in a disposable VM or an isolated network
# namespace. It creates a temporary cgroup in the caller's delegated systemd
# subtree and installs nftables rules inside a new network namespace. The
# cgroup is removed on exit and the host routing table is never touched, but
# run it only on a disposable system. Never run it on a workstation or server
# whose connectivity matters.

CGROOT=/sys/fs/cgroup

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

if ! command -v nft >/dev/null 2>&1; then
    fail "nft is required"
fi
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to send a UDP probe"
fi
if ! command -v unshare >/dev/null 2>&1; then
    fail "unshare is required (util-linux)"
fi
if [[ "$(stat -fc %T "$CGROOT")" != "cgroup2fs" ]]; then
    fail "$CGROOT is not cgroup v2 (unified hierarchy)"
fi
if ! unshare -Urn true >/dev/null 2>&1; then
    fail "unprivileged user and network namespaces are not available"
fi

# Find the nearest writable ancestor of our own cgroup. systemd delegates
# user@UID.service/app.slice to the user on a normal desktop session.
own=$(awk -F: '$1 == "0" { print $3; exit }' /proc/self/cgroup)
[[ -n "$own" ]] || fail "cannot determine the caller cgroup from /proc/self/cgroup"
parent=$(dirname "$own")
while [[ "$parent" != "/" && ! -w "$CGROOT$parent" ]]; do
    parent=$(dirname "$parent")
done
[[ "$parent" != "/" ]] || fail "no writable delegated cgroup ancestor found"

probe="$parent/kilo-cgroup-probe-$$"
probe_dir="$CGROOT$probe"
rel=${probe#/}
level=$(awk -F/ '{ print NF }' <<< "$rel")

cleanup() {
    if [[ -d "$probe_dir" ]]; then
        while read -r pid; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
        done < "$probe_dir/cgroup.procs" 2>/dev/null || true
        rmdir "$probe_dir" 2>/dev/null || true
    fi
}
trap cleanup EXIT

mkdir "$probe_dir"
echo "created cgroup $probe (relative path $rel, nft level $level)"

# The probe runs inside an isolated network namespace. The cgroup hierarchy is
# host-global, so the socket is created in the host cgroup by a process that
# has been moved into it from inside the user namespace.
unshare -Urn --map-root-user bash -eu -c '
    cgdir=$1
    rel=$2
    level=$3

    ip link set lo up
    echo $$ > "$cgdir/cgroup.procs"

    nft add table inet kilo_cgroup_probe
    nft add chain inet kilo_cgroup_probe out "{ type filter hook output priority mangle; }"
    nft add rule inet kilo_cgroup_probe out socket cgroupv2 level "$level" "\"$rel\"" counter accept

    python3 - <<PY
import socket
for _ in range(2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"probe", ("127.0.0.1", 9))
    s.close()
print("sent 2 UDP datagrams from cgroup", open("/proc/self/cgroup").read().strip())
PY

    nft -a list chain inet kilo_cgroup_probe out
    line=$(nft -a list chain inet kilo_cgroup_probe out | grep "socket cgroupv2" || true)
    [[ -n "$line" ]] || { echo "FAIL: cgroupv2 rule not present" >&2; exit 1; }
    packets=$(awk "{ for (i = 1; i <= NF; i++) if (\$i == \"packets\") { print \$(i + 1); exit } }" <<< "$line")
    [[ -n "$packets" ]] || { echo "FAIL: could not read counter" >&2; exit 1; }
    if [[ "$packets" -lt 2 ]]; then
        echo "FAIL: expected at least 2 matching packets, got $packets" >&2
        exit 1
    fi
    echo "PASS: nft socket cgroupv2 matched $packets packets from $rel"
' _ "$probe_dir" "$rel" "$level"

echo "cleaning up cgroup $probe"
