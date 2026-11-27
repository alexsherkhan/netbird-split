#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: install.sh [--root DIR] [--no-systemd]

Install the split-tunnel client from this archive. The default root is /.
--root is for disposable test prefixes and disables systemd management.
EOF
}

root="/"
use_systemd=1
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            if [ "$#" -lt 2 ]; then
                echo "install.sh: --root needs a directory" >&2
                exit 2
            fi
            root="$2"
            shift 2
            ;;
        --no-systemd)
            use_systemd=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "install.sh: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

case "$root" in
    /*) ;;
    *)
        echo "install.sh: --root must be an absolute path" >&2
        exit 2
        ;;
esac
root="${root%/}"
if [ -n "$root" ]; then
    use_systemd=0
fi

CDPATH=
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"

split_path() {
    printf '%s%s' "$root" "$1"
}

if [ -z "$root" ] && command -v dpkg >/dev/null 2>&1; then
    if dpkg -S /usr/bin/netbird-split >/dev/null 2>&1; then
        echo "install.sh: /usr/bin/netbird-split is owned by a package; use apt install instead" >&2
        exit 1
    fi
fi

for file in netbird-split netbird-split-wrapper netbird-split.service netbird-split.env.example README.md UNINSTALL.md; do
    if [ ! -f "$script_dir/$file" ]; then
        echo "install.sh: archive is missing $file" >&2
        exit 1
    fi
done

install -D -m 0755 "$script_dir/netbird-split" "$(split_path /usr/lib/netbird-split/netbird-split)"
install -D -m 0755 "$script_dir/netbird-split-wrapper" "$(split_path /usr/bin/netbird-split)"
install -D -m 0644 "$script_dir/netbird-split.service" "$(split_path /lib/systemd/system/netbird-split.service)"
install -D -m 0644 "$script_dir/README.md" "$(split_path /usr/share/doc/netbird-split/README.md)"
install -D -m 0644 "$script_dir/UNINSTALL.md" "$(split_path /usr/share/doc/netbird-split/UNINSTALL.md)"
install -D -m 0644 "$script_dir/netbird-split.env.example" "$(split_path /usr/share/doc/netbird-split/netbird-split.env.example)"

install -d -m 0750 "$(split_path /var/lib/netbird-split)"
install -d -m 0750 "$(split_path /var/log/netbird-split)"
install -d -m 0755 "$(split_path /run/netbird-split)"
install -d -m 0750 "$(split_path /etc/netbird-split)"

if [ ! -e "$(split_path /etc/default/netbird-split)" ]; then
    install -D -m 0644 "$script_dir/netbird-split.env.example" "$(split_path /etc/default/netbird-split)"
fi

if [ "$use_systemd" = "1" ]; then
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable netbird-split.service
        systemctl restart netbird-split.service
        echo "netbird-split has been installed and started"
    else
        echo "netbird-split files installed; systemd is not running, so the service was not started"
    fi
else
    echo "netbird-split files installed under ${root:-/}; systemd management skipped"
fi

cat <<'EOF'
The service is netbird-split.service. It uses /etc/default/netbird-split,
/var/lib/netbird-split, /var/log/netbird-split and /run/netbird-split; it never
uses an upstream netbird unit, state directory or socket.

Run "sudo netbird-split up" to connect. See UNINSTALL.md for removal.
EOF
