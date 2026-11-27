#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: uninstall.sh [--root DIR] [--no-systemd] [--purge]

Stop and remove the split-tunnel client installed by install.sh. --purge also
removes split-owned configuration and state. Upstream netbird files are never
touched. --root is for disposable test prefixes and disables systemd management.
EOF
}

root="/"
use_systemd=1
purge=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            if [ "$#" -lt 2 ]; then
                echo "uninstall.sh: --root needs a directory" >&2
                exit 2
            fi
            root="$2"
            shift 2
            ;;
        --no-systemd)
            use_systemd=0
            shift
            ;;
        --purge)
            purge=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "uninstall.sh: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

case "$root" in
    /*) ;;
    *)
        echo "uninstall.sh: --root must be an absolute path" >&2
        exit 2
        ;;
esac
root="${root%/}"
if [ -n "$root" ]; then
    use_systemd=0
fi

split_path() {
    printf '%s%s' "$root" "$1"
}

# A package install and a manual archive install share the same paths. Refuse to
# delete paths owned by dpkg; the package manager must remove those.
if [ -z "$root" ] && command -v dpkg >/dev/null 2>&1; then
    if dpkg -S /usr/bin/netbird-split >/dev/null 2>&1; then
        echo "uninstall.sh: /usr/bin/netbird-split is owned by a package; use apt remove or apt purge" >&2
        exit 1
    fi
fi

split_bin="$(split_path /usr/bin/netbird-split)"
socket="$(split_path /run/netbird-split/netbird-split.sock)"

if [ "$use_systemd" = "1" ]; then
    if [ -x "$split_bin" ] && [ -S "$socket" ]; then
        "$split_bin" down --daemon-addr "unix://$socket" >/dev/null 2>&1 || true
    fi
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop netbird-split.service >/dev/null 2>&1 || true
        systemctl disable netbird-split.service >/dev/null 2>&1 || true
    fi
fi

rm -f "$(split_path /lib/systemd/system/netbird-split.service)"
rm -f "$(split_path /etc/systemd/system/netbird-split.service)"
rm -f "$(split_path /usr/bin/netbird-split)"
rm -rf "$(split_path /usr/lib/netbird-split)"
rm -rf "$(split_path /usr/share/doc/netbird-split)"

if [ "$purge" = "1" ]; then
    rm -f "$(split_path /etc/default/netbird-split)"
    rm -rf "$(split_path /etc/netbird-split)"
    rm -rf "$(split_path /var/lib/netbird-split)"
    rm -rf "$(split_path /var/log/netbird-split)"
    rm -rf "$(split_path /run/netbird-split)"
fi

if [ "$use_systemd" = "1" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "$purge" = "1" ]; then
    echo "netbird-split files, configuration and state removed"
else
    echo "netbird-split service and binary removed; run with --purge to remove /etc/default/netbird-split and split state"
fi
