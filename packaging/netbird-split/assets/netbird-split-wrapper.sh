#!/bin/sh
# Keep the CLI on the split daemon and split state. Upstream netbird uses
# /var/run/netbird.sock and /var/lib/netbird; neither is touched here.
# An explicit --daemon-addr stays authoritative, and an already exported
# NB_DAEMON_ADDR is left alone.

set -eu

# The client defaults its service name to the upstream "netbird". Keep service
# commands on netbird-split so "service stop" cannot stop an upstream unit.
if [ "${1:-}" = "service" ]; then
    shift
    service_name_on_command_line=0
    for arg in "$@"; do
        case "$arg" in
            --service | --service=* | -s)
                service_name_on_command_line=1
                ;;
        esac
    done
    if [ "$service_name_on_command_line" = "0" ]; then
        set -- service --service netbird-split "$@"
    else
        set -- service "$@"
    fi
fi

daemon_addr_on_command_line=0
for arg in "$@"; do
    case "$arg" in
        --daemon-addr | --daemon-addr=*)
            daemon_addr_on_command_line=1
            ;;
    esac
done

if [ "$daemon_addr_on_command_line" = "0" ] && [ -z "${NB_DAEMON_ADDR:-}" ]; then
    export NB_DAEMON_ADDR="unix:///run/netbird-split/netbird-split.sock"
fi
if [ -z "${NB_STATE_DIR:-}" ]; then
    export NB_STATE_DIR="/var/lib/netbird-split"
fi
if [ -z "${NB_RUNTIME_DIR:-}" ]; then
    export NB_RUNTIME_DIR="/run/netbird-split"
fi

exec /usr/lib/netbird-split/netbird-split "$@"
