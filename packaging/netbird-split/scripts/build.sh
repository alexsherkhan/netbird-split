#!/usr/bin/env bash
set -euo pipefail

CDPATH=
pkg_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd -- "$pkg_dir/../.." && pwd)"
dist="${NETBIRD_SPLIT_DIST:-$repo_root/dist/netbird-split}"
arches="${NETBIRD_SPLIT_ARCHES:-amd64 arm64}"
maintainer="${NETBIRD_SPLIT_MAINTAINER:-Alexander Syrykh <alexsherkhan@users.noreply.github.com>}"

commit="$(git -C "$repo_root" rev-parse HEAD)"
short_commit="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" show -s --format=%ct HEAD)}"
export SOURCE_DATE_EPOCH="$source_date_epoch"

if [ -n "${NETBIRD_SPLIT_VERSION:-}" ]; then
    version="$NETBIRD_SPLIT_VERSION"
else
    if date -u -d "@$source_date_epoch" +%Y%m%d >/dev/null 2>&1; then
        build_date="$(date -u -d "@$source_date_epoch" +%Y%m%d)"
        touch_time="$(date -u -d "@$source_date_epoch" +%Y%m%d%H%M.%S)"
    else
        build_date="$(date -u -r "$source_date_epoch" +%Y%m%d)"
        touch_time="$(date -u -r "$source_date_epoch" +%Y%m%d%H%M.%S)"
    fi
    version="0.0.0~git${build_date}.${short_commit}"
    if [ -n "$(git -C "$repo_root" status --porcelain)" ]; then
        version="${version}.dirty"
    fi
fi

rm -rf "$dist"
mkdir -p "$dist"

install_file() {
    src="$1"
    dst="$2"
    mode="$3"
    install -D -m "$mode" "$src" "$dst"
}

build_binary() {
    arch="$1"
    out="$2"
    (
        cd "$repo_root"
        GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build \
            -trimpath \
            -buildvcs=false \
            -ldflags "-s -w -X github.com/netbirdio/netbird/version.version=$version" \
            -o "$out" ./client
    )
}

stage_deb_tree() {
    arch="$1"
    binary="$2"
    stage="$dist/.stage/$arch"

    rm -rf "$stage"
    mkdir -p "$stage/DEBIAN"
    chmod 0755 "$stage"

    install_file "$binary" "$stage/usr/lib/netbird-split/netbird-split" 0755
    install_file "$pkg_dir/assets/netbird-split-wrapper.sh" "$stage/usr/bin/netbird-split" 0755
    install_file "$pkg_dir/assets/netbird-split.service" "$stage/lib/systemd/system/netbird-split.service" 0644
    install_file "$pkg_dir/assets/netbird-split.env.example" "$stage/etc/default/netbird-split" 0644
    install_file "$pkg_dir/README.md" "$stage/usr/share/doc/netbird-split/README.md" 0644
    install_file "$pkg_dir/UNINSTALL.md" "$stage/usr/share/doc/netbird-split/UNINSTALL.md" 0644
    install_file "$repo_root/LICENSE" "$stage/usr/share/doc/netbird-split/copyright" 0644
    install_file "$pkg_dir/scripts/postinst" "$stage/DEBIAN/postinst" 0755
    install_file "$pkg_dir/scripts/prerm" "$stage/DEBIAN/prerm" 0755
    install_file "$pkg_dir/scripts/postrm" "$stage/DEBIAN/postrm" 0755

    installed_size="$(du -sk "$stage" | awk '{print $1}')"
    cat > "$stage/DEBIAN/control" <<EOF
Package: netbird-split
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $installed_size
Depends: ca-certificates
Recommends: nftables | iptables
Homepage: https://github.com/alexsherkhan/netbird-split
Description: NetBird split-tunnel client for the alexsherkhan fork
 A separately packaged NetBird client carrying the split-tunnel work. It
 installs only split-owned files and does not replace or remove an upstream
 netbird package.
EOF

    printf '%s\n' /etc/default/netbird-split > "$stage/DEBIAN/conffiles"

    find "$stage" -exec touch -h -t "$touch_time" {} +
}

build_deb_with_dpkg() {
    stage="$1"
    out="$2"
    if dpkg-deb --root-owner-group --build "$stage" "$out" >/dev/null 2>&1; then
        return 0
    fi
    dpkg-deb --build "$stage" "$out" >/dev/null
}

build_deb_with_ar() {
    stage="$1"
    out="$2"
    work="$dist/.work/$(basename "$out")"
    rm -rf "$work"
    mkdir -p "$work"

    printf '2.0\n' > "$work/debian-binary"
    (cd "$stage/DEBIAN" && tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -cf - .) | gzip -n -9 > "$work/control.tar.gz"
    (cd "$stage" && tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner --exclude=./DEBIAN -cf - .) | gzip -n -9 > "$work/data.tar.gz"

    rm -f "$out"
    if ! (cd "$work" && ar rD "$out" debian-binary control.tar.gz data.tar.gz >/dev/null 2>&1); then
        rm -f "$out"
        (cd "$work" && ar r "$out" debian-binary control.tar.gz data.tar.gz >/dev/null)
    fi
}

build_deb() {
    arch="$1"
    binary="$2"
    out="$dist/netbird-split_${version}_${arch}.deb"
    stage_deb_tree "$arch" "$binary"
    if command -v dpkg-deb >/dev/null 2>&1; then
        build_deb_with_dpkg "$dist/.stage/$arch" "$out"
    else
        build_deb_with_ar "$dist/.stage/$arch" "$out"
    fi
    echo "$out"
}

build_tarball() {
    arch="$1"
    binary="$2"
    bundle="$dist/.bundle/netbird-split_${version}_linux_${arch}"

    rm -rf "$bundle"
    mkdir -p "$bundle"
    install_file "$binary" "$bundle/netbird-split" 0755
    install_file "$pkg_dir/assets/netbird-split-wrapper.sh" "$bundle/netbird-split-wrapper" 0755
    install_file "$pkg_dir/assets/netbird-split.service" "$bundle/netbird-split.service" 0644
    install_file "$pkg_dir/assets/netbird-split.env.example" "$bundle/netbird-split.env.example" 0644
    install_file "$pkg_dir/README.md" "$bundle/README.md" 0644
    install_file "$pkg_dir/UNINSTALL.md" "$bundle/UNINSTALL.md" 0644
    install_file "$pkg_dir/scripts/tarball-install.sh" "$bundle/install.sh" 0755
    install_file "$pkg_dir/scripts/tarball-uninstall.sh" "$bundle/uninstall.sh" 0755

    out="$dist/netbird-split_${version}_linux_${arch}.tar.gz"
    tar \
        --sort=name \
        --mtime="@$source_date_epoch" \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        -C "$dist/.bundle" \
        -cf - "netbird-split_${version}_linux_${arch}" | gzip -n -9 > "$out"
    echo "$out"
}

echo "Building netbird-split $version from $short_commit"
echo "Architectures: $arches"
echo "Source date epoch: $source_date_epoch"

for arch in $arches; do
    binary="$dist/.bin/netbird-split-linux-$arch"
    mkdir -p "$dist/.bin"
    build_binary "$arch" "$binary"
    build_deb "$arch" "$binary" >/dev/null
    build_tarball "$arch" "$binary" >/dev/null
done

(
    cd "$dist"
    sha256sum ./*.deb ./*.tar.gz > SHA256SUMS
    {
        echo "package=netbird-split"
        echo "version=$version"
        echo "commit=$commit"
        echo "source_date_epoch=$source_date_epoch"
        echo "go=$(go version)"
        echo "signature=not-produced"
        echo "sbom=not-produced"
        echo "provenance=not-produced"
    } > release-manifest.txt
)

rm -rf "$dist/.bin" "$dist/.stage" "$dist/.work" "$dist/.bundle"

echo "Artifacts written to $dist"
ls -l "$dist"
