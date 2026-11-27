#!/usr/bin/env bash
set -euo pipefail

CDPATH=
pkg_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd -- "$pkg_dir/../.." && pwd)"
dist="${NETBIRD_SPLIT_DIST:-$repo_root/dist/netbird-split}"

tmp="$(mktemp -d /tmp/netbird-split-test.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_file() {
    [ -f "$1" ] || fail "expected file $1"
}

assert_dir() {
    [ -d "$1" ] || fail "expected directory $1"
}

assert_missing() {
    [ ! -e "$1" ] || fail "expected path to be removed: $1"
}

assert_contains() {
    printf '%s' "$1" | grep -qF -- "$2" || fail "expected output to contain: $2"
}

assert_log_contains() {
    [ -f "$1" ] || fail "expected action log $1"
    grep -qF -- "$2" "$1" || fail "expected action log to contain: $2"
}

assert_no_upstream_removed() {
    root="$1"
    [ "$(cat "$root/usr/bin/netbird")" = "upstream-netbird" ] || fail "upstream binary changed"
    [ "$(cat "$root/etc/netbird/config.json")" = "upstream-config" ] || fail "upstream config changed"
    [ "$(cat "$root/lib/systemd/system/netbird.service")" = "upstream-unit" ] || fail "upstream unit changed"
}

check_shell_syntax() {
    for script in \
        "$pkg_dir/scripts/postinst" \
        "$pkg_dir/scripts/prerm" \
        "$pkg_dir/scripts/postrm" \
        "$pkg_dir/assets/netbird-split-wrapper.sh"; do
        sh -n "$script"
    done
    for script in \
        "$pkg_dir/scripts/build.sh" \
        "$pkg_dir/scripts/tarball-install.sh" \
        "$pkg_dir/scripts/tarball-uninstall.sh" \
        "$pkg_dir/tests/run.sh"; do
        bash -n "$script"
    done
}

find_artifact() {
    pattern="$1"
    path="$(find "$dist" -maxdepth 1 -name "$pattern" -print -quit)"
    [ -n "$path" ] || fail "missing artifact matching $pattern in $dist"
    printf '%s' "$path"
}

inspect_deb() {
    deb="$1"
    arch="$2"

    if command -v dpkg-deb >/dev/null 2>&1; then
        package="$(dpkg-deb --field "$deb" Package)"
        version="$(dpkg-deb --field "$deb" Version)"
        deb_arch="$(dpkg-deb --field "$deb" Architecture)"
        [ "$package" = "netbird-split" ] || fail "unexpected package name: $package"
        [ "$deb_arch" = "$arch" ] || fail "unexpected architecture: $deb_arch"
        [ -n "$version" ] || fail "missing package version"

        contents="$(dpkg-deb --contents "$deb")"
        conffiles="$(dpkg-deb --ctrl-tarfile "$deb" | tar -xO ./conffiles)"
        assert_contains "$contents" "./usr/bin/netbird-split"
        assert_contains "$contents" "./usr/lib/netbird-split/netbird-split"
        assert_contains "$contents" "./lib/systemd/system/netbird-split.service"
        assert_contains "$contents" "./etc/default/netbird-split"
        assert_contains "$contents" "./usr/share/doc/netbird-split/README.md"
        assert_contains "$contents" "./usr/share/doc/netbird-split/UNINSTALL.md"
        assert_contains "$conffiles" "/etc/default/netbird-split"

        if printf '%s' "$contents" | grep -Eq '(^|/)usr/bin/netbird$'; then
            fail "DEB contains an upstream /usr/bin/netbird"
        fi
        if printf '%s' "$contents" | grep -Eq '(^|/)lib/systemd/system/netbird\.service$'; then
            fail "DEB contains an upstream netbird.service"
        fi
        if printf '%s' "$contents" | grep -Eq '(^|/)etc/netbird(/|$)'; then
            fail "DEB contains an upstream /etc/netbird path"
        fi
    else
        mkdir -p "$tmp/deb-control-$arch"
        ar p "$deb" control.tar.gz | tar -xz -C "$tmp/deb-control-$arch"
        control_file="$(find "$tmp/deb-control-$arch" -name control -type f -print -quit)"
        assert_file "$control_file"
        assert_contains "$(cat "$control_file")" "Package: netbird-split"
        assert_contains "$(cat "$control_file")" "Architecture: $arch"

        ar p "$deb" data.tar.gz | tar -tz > "$tmp/deb-data-$arch.list"
        assert_contains "$(cat "$tmp/deb-data-$arch.list")" "usr/bin/netbird-split"
        assert_contains "$(cat "$tmp/deb-data-$arch.list")" "usr/lib/netbird-split/netbird-split"
        assert_contains "$(cat "$tmp/deb-data-$arch.list")" "lib/systemd/system/netbird-split.service"
        assert_contains "$(cat "$tmp/deb-data-$arch.list")" "etc/default/netbird-split"
        if grep -Eq '(^|/)usr/bin/netbird$' "$tmp/deb-data-$arch.list"; then
            fail "DEB contains an upstream /usr/bin/netbird"
        fi
    fi
}

extract_control() {
    deb="$1"
    out="$2"
    mkdir -p "$out"
    if command -v dpkg-deb >/dev/null 2>&1; then
        dpkg-deb -e "$deb" "$out"
    else
        ar p "$deb" control.tar.gz | tar -xz -C "$out"
    fi
}

test_maintainer_scripts() {
    deb="$1"
    arch="$2"
    control_dir="$tmp/maintainer-control-$arch"
    root="$tmp/maintainer-root-$arch"
    extract_control "$deb" "$control_dir"

    mkdir -p "$root/usr/bin" "$root/etc/netbird" "$root/lib/systemd/system" "$root/var/lib/netbird"
    printf 'upstream-netbird' > "$root/usr/bin/netbird"
    printf 'upstream-config' > "$root/etc/netbird/config.json"
    printf 'upstream-unit' > "$root/lib/systemd/system/netbird.service"

    cat > "$root/usr/bin/netbird-split" <<'EOF'
#!/bin/sh
printf 'netbird-split %s\n' "$*" >> "${NETBIRD_SPLIT_TEST_LOG:?}"
EOF
    chmod 0755 "$root/usr/bin/netbird-split"

    export NETBIRD_SPLIT_TEST_MODE=1
    export NETBIRD_SPLIT_TEST_ROOT="$root"
    export NETBIRD_SPLIT_TEST_LOG="$root/var/log/netbird-split-package-actions.log"

    sh "$control_dir/postinst" configure
    assert_dir "$root/var/lib/netbird-split"
    assert_dir "$root/var/log/netbird-split"
    assert_dir "$root/run/netbird-split"
    assert_dir "$root/etc/netbird-split"
    assert_log_contains "$NETBIRD_SPLIT_TEST_LOG" "systemctl daemon-reload"
    assert_log_contains "$NETBIRD_SPLIT_TEST_LOG" "systemctl enable netbird-split.service"
    assert_log_contains "$NETBIRD_SPLIT_TEST_LOG" "systemctl start netbird-split.service"
    assert_no_upstream_removed "$root"

    sh "$control_dir/postinst" configure 0.0.0~older
    assert_log_contains "$NETBIRD_SPLIT_TEST_LOG" "systemctl try-restart netbird-split.service"
    assert_no_upstream_removed "$root"

    sh "$control_dir/prerm" upgrade
    assert_no_upstream_removed "$root"

    sh "$control_dir/prerm" remove
    assert_log_contains "$NETBIRD_SPLIT_TEST_LOG" "netbird-split down"
    assert_log_contains "$NETBIRD_SPLIT_TEST_LOG" "systemctl stop netbird-split.service"
    assert_log_contains "$NETBIRD_SPLIT_TEST_LOG" "systemctl disable netbird-split.service"
    assert_no_upstream_removed "$root"

    sh "$control_dir/postrm" remove
    assert_missing "$root/run/netbird-split"
    assert_dir "$root/etc/netbird-split"
    assert_dir "$root/var/lib/netbird-split"
    assert_dir "$root/var/log/netbird-split"
    assert_no_upstream_removed "$root"

    sh "$control_dir/postrm" purge
    assert_missing "$root/etc/netbird-split"
    assert_missing "$root/var/lib/netbird-split"
    assert_missing "$root/var/log/netbird-split"
    assert_missing "$root/run/netbird-split"
    assert_no_upstream_removed "$root"

    unset NETBIRD_SPLIT_TEST_MODE NETBIRD_SPLIT_TEST_ROOT NETBIRD_SPLIT_TEST_LOG
}

test_tarball_scripts() {
    tarball="$1"
    arch="$2"
    unpack="$tmp/tarball-$arch"
    root="$tmp/tarball-root-$arch"
    mkdir -p "$unpack"
    tar -xzf "$tarball" -C "$unpack"
    bundle="$(find "$unpack" -maxdepth 1 -type d -name 'netbird-split_*' -print -quit)"
    [ -n "$bundle" ] || fail "tarball has no bundle directory"
    assert_file "$bundle/netbird-split"
    assert_file "$bundle/netbird-split-wrapper"
    assert_file "$bundle/netbird-split.service"
    assert_file "$bundle/netbird-split.env.example"
    assert_file "$bundle/README.md"
    assert_file "$bundle/UNINSTALL.md"
    assert_file "$bundle/install.sh"
    assert_file "$bundle/uninstall.sh"

    mkdir -p "$root/usr/bin" "$root/etc/netbird" "$root/lib/systemd/system" "$root/var/lib/netbird"
    printf 'upstream-netbird' > "$root/usr/bin/netbird"
    printf 'upstream-config' > "$root/etc/netbird/config.json"
    printf 'upstream-unit' > "$root/lib/systemd/system/netbird.service"

    bash "$bundle/install.sh" --root "$root" --no-systemd >/dev/null
    assert_file "$root/usr/bin/netbird-split"
    assert_file "$root/usr/lib/netbird-split/netbird-split"
    assert_contains "$(cat "$root/usr/bin/netbird-split")" "NB_DAEMON_ADDR"
    assert_file "$root/lib/systemd/system/netbird-split.service"
    assert_file "$root/etc/default/netbird-split"
    assert_file "$root/usr/share/doc/netbird-split/README.md"
    assert_no_upstream_removed "$root"

    printf 'custom-env' > "$root/etc/default/netbird-split"
    bash "$bundle/install.sh" --root "$root" --no-systemd >/dev/null
    [ "$(cat "$root/etc/default/netbird-split")" = "custom-env" ] || fail "install overwrote an existing env file"
    assert_no_upstream_removed "$root"

    bash "$bundle/uninstall.sh" --root "$root" --no-systemd >/dev/null
    assert_missing "$root/usr/bin/netbird-split"
    assert_missing "$root/usr/lib/netbird-split"
    assert_missing "$root/lib/systemd/system/netbird-split.service"
    assert_missing "$root/usr/share/doc/netbird-split"
    assert_file "$root/etc/default/netbird-split"
    assert_dir "$root/etc/netbird-split"
    assert_dir "$root/var/lib/netbird-split"
    assert_dir "$root/var/log/netbird-split"
    assert_no_upstream_removed "$root"

    bash "$bundle/install.sh" --root "$root" --no-systemd >/dev/null
    bash "$bundle/uninstall.sh" --root "$root" --no-systemd --purge >/dev/null
    assert_missing "$root/usr/bin/netbird-split"
    assert_missing "$root/etc/default/netbird-split"
    assert_missing "$root/etc/netbird-split"
    assert_missing "$root/var/lib/netbird-split"
    assert_missing "$root/var/log/netbird-split"
    assert_missing "$root/run/netbird-split"
    assert_no_upstream_removed "$root"
}

test_container() {
    deb="$1"
    case "$(uname -m)" in
        x86_64 | amd64) host_arch="amd64" ;;
        aarch64 | arm64) host_arch="arm64" ;;
        *) echo "SKIP: unsupported container host architecture"; return 0 ;;
    esac
    case "$deb" in
        *"_${host_arch}.deb") ;;
        *) echo "SKIP: no $host_arch DEB for the container test"; return 0 ;;
    esac

    if [ "${NETBIRD_SPLIT_SKIP_CONTAINER:-0}" = "1" ]; then
        echo "SKIP: NETBIRD_SPLIT_SKIP_CONTAINER=1"
        return 0
    fi
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        echo "SKIP: Docker is not available"
        return 0
    fi

    deb_name="$(basename "$deb")"
    container_script="$(cat <<EOF
set -e
mkdir -p /etc/netbird /lib/systemd/system /usr/bin /var/lib/netbird
printf 'upstream-netbird' > /usr/bin/netbird
printf 'upstream-config' > /etc/netbird/config.json
printf 'upstream-unit' > /lib/systemd/system/netbird.service
if ! dpkg -s ca-certificates >/dev/null 2>&1; then
  apt-get update >/dev/null
  apt-get install -y --no-install-recommends ca-certificates >/dev/null
fi
dpkg -i /packages/${deb_name}
test -x /usr/bin/netbird-split
test -x /usr/lib/netbird-split/netbird-split
grep -q NB_DAEMON_ADDR /usr/bin/netbird-split
test -f /lib/systemd/system/netbird-split.service
test -f /etc/default/netbird-split
test "\$(cat /usr/bin/netbird)" = "upstream-netbird"
test "\$(cat /etc/netbird/config.json)" = "upstream-config"
test "\$(cat /lib/systemd/system/netbird.service)" = "upstream-unit"
dpkg -i /packages/${deb_name}
dpkg -r netbird-split
test ! -e /usr/bin/netbird-split
test ! -e /usr/lib/netbird-split/netbird-split
test ! -e /lib/systemd/system/netbird-split.service
test -f /etc/default/netbird-split
dpkg --purge netbird-split
test ! -e /etc/default/netbird-split
test ! -e /etc/netbird-split
test ! -e /var/lib/netbird-split
test "\$(cat /usr/bin/netbird)" = "upstream-netbird"
test "\$(cat /etc/netbird/config.json)" = "upstream-config"
test "\$(cat /lib/systemd/system/netbird.service)" = "upstream-unit"
EOF
)"
    docker run --rm -v "$dist:/packages:ro" debian:12 bash -c "$container_script"
    echo "container install/upgrade/remove/purge passed"
}

check_shell_syntax

if [ "${NETBIRD_SPLIT_SKIP_BUILD:-0}" != "1" ]; then
    echo "Building packages"
    bash "$pkg_dir/scripts/build.sh"
fi

for arch in amd64 arm64; do
    deb="$(find_artifact "netbird-split_*_${arch}.deb")"
    tarball="$(find_artifact "netbird-split_*_linux_${arch}.tar.gz")"

    echo "Validating $arch artifacts"
    inspect_deb "$deb" "$arch"
    assert_file "$dist/SHA256SUMS"
    (cd "$dist" && sha256sum -c SHA256SUMS >/dev/null)
    test_maintainer_scripts "$deb" "$arch"
    test_tarball_scripts "$tarball" "$arch"
done

deb="$(find_artifact 'netbird-split_*_amd64.deb')"
test_container "$deb"

echo "All netbird-split package tests passed"
