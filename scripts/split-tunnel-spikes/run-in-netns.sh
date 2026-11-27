#!/usr/bin/env bash
set -euo pipefail

# WARNING: Run this script only in a disposable VM or an isolated network
# namespace. It creates a user and network namespace, but a mistake in the
# command it wraps can still affect the host if the wrapper is bypassed.
# Never run this on a workstation or server whose connectivity matters.

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

if ! command -v unshare >/dev/null 2>&1; then
    echo "unshare is required (util-linux)." >&2
    exit 1
fi

if ! unshare -Urn true >/dev/null 2>&1; then
    echo "unprivileged user and network namespaces are not available." >&2
    echo "Enable them or run the command inside a disposable VM." >&2
    exit 1
fi

exec unshare -Urn --map-root-user "$@"
