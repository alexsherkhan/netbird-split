# netbird-split packaging

This directory builds the fork's Linux artifacts:

- `netbird-split_<version>_<arch>.deb` for `amd64` and `arm64`
- `netbird-split_<version>_linux_<arch>.tar.gz` containing the client binary,
  the systemd unit, a configuration example, this README, and uninstall notes
- `SHA256SUMS` and `release-manifest.txt`

The package and service are named `netbird-split`. Every path the package owns
is split specific: `/usr/bin/netbird-split` (a small wrapper),
`/usr/lib/netbird-split/netbird-split` (the client binary),
`/lib/systemd/system/netbird-split.service`, `/etc/default/netbird-split`,
`/etc/netbird-split`, `/var/lib/netbird-split`, `/var/log/netbird-split`, and
`/run/netbird-split`. An upstream `netbird` package and service are not
replaced, stopped, or removed.

The wrapper sets `NB_DAEMON_ADDR`, `NB_STATE_DIR` and `NB_RUNTIME_DIR` to the
split paths unless they are already set or `--daemon-addr` is passed explicitly.
It also defaults `service` commands to the `netbird-split` service name. That
keeps `netbird-split status`, `netbird-split split`, `netbird-split down`, and
`netbird-split service stop` on the split daemon and unit instead of an upstream
socket or service.

## Standalone mode

`netbird-split` can be installed next to an upstream `netbird` package. The
package system paths and the service are disjoint, so both packages can be
installed. The two clients cannot share the same overlay interface, routes,
firewall rules, DNS settings, or kill switch state at the same time.

Use a distinct overlay interface when an upstream client is also active:

```bash
sudo netbird-split up --interface-name nbs0
```

The interface name is a property of the profile chosen by `up`, not of the
service unit. The service itself only owns the split socket, state, logs and
configuration.

The fork does not declare `Conflicts: netbird`, because the file layout is
disjoint and side-by-side installation is the intended standalone mode. The
runtime conflict is the overlay and kernel state described above, not a package
file conflict.

## Replacement mode

Replacement mode means the upstream `netbird` package is removed and the fork
becomes the only client. The package still installs `netbird-split`, not
`netbird`; commands and the service name change accordingly. Do not install the
fork over an upstream tree or create a `/usr/bin/netbird` symlink.

```bash
sudo apt remove netbird netbird-ui
sudo apt install ./netbird-split_<version>_amd64.deb
```

After removal, existing upstream state under `/etc/netbird`, `/var/lib/netbird`,
`/var/log/netbird` and `/run/netbird` is left in place. The fork does not import
it automatically. Reconnect with `netbird-split up` and the desired profile.

## Install, upgrade, rollback, uninstall

Build the artifacts:

```bash
bash packaging/netbird-split/scripts/build.sh
```

`NETBIRD_SPLIT_VERSION`, `NETBIRD_SPLIT_ARCHES`, `NETBIRD_SPLIT_DIST` and
`SOURCE_DATE_EPOCH` override the default version, architecture list, output
directory and timestamp.

Install or upgrade:

```bash
sudo apt install ./netbird-split_<version>_amd64.deb
```

`postinst` creates the split directories, reloads systemd, enables
`netbird-split.service`, starts it on a clean install, and restarts it on an
upgrade only if it was already active. `prerm` on upgrade leaves the running
daemon in place so the postinst restart can pick up the new binary.

Rollback to a previously downloaded package:

```bash
sudo apt install --allow-downgrades ./netbird-split_<older-version>_amd64.deb
```

The same postinst path runs. Rollback is a package downgrade, not a separate
state migration. Split state written by a newer build may not be readable by an
older one; keep a copy of `/var/lib/netbird-split` and
`/etc/default/netbird-split` before downgrading if that matters.

Remove:

```bash
sudo apt remove netbird-split      # stops and removes the service and binary
sudo apt purge netbird-split       # also removes split configuration and state
```

`prerm` calls `netbird-split down` when the split socket is present, then stops
and disables the unit so the daemon can release its kernel state. The
`postrm remove` stage removes the split runtime directory. The `postrm purge`
stage additionally removes `/etc/default/netbird-split`, `/etc/netbird-split`,
`/var/lib/netbird-split`, `/var/log/netbird-split` and `/run/netbird-split`.
No stage removes `/usr/bin/netbird`, `/lib/systemd/system/netbird.service`,
`/etc/netbird`, `/var/lib/netbird`, `/var/log/netbird` or `/run/netbird`.

## Tarball install

```bash
tar -xzf netbird-split_<version>_linux_amd64.tar.gz
cd netbird-split_<version>_linux_amd64
sudo ./install.sh
```

The archive contains the client binary as `netbird-split`; `install.sh` places
it under `/usr/lib/netbird-split/` and installs the split wrapper at
`/usr/bin/netbird-split`. It writes the same paths as the DEB, creates
`/etc/default/netbird-split` only when it does not exist, and restarts the unit.
It refuses to manage systemd when `--root` points at a test prefix. Remove with
`sudo ./uninstall.sh` and add `--purge` to remove split configuration and state.
`uninstall.sh` refuses to delete paths owned by dpkg, so use `apt` for a package
install.

## Reproducible builds

The build uses `-trimpath`, `-buildvcs=false`, `SOURCE_DATE_EPOCH`, sorted tar
entries, normalized ownership and gzip without a timestamp. The default version
is derived from the commit date and SHA:

```text
0.0.0~git<YYYYMMDD>.<12-char-sha>[.dirty]
```

A bit-for-bit reproduction also needs the same Go toolchain version and the same
`SOURCE_DATE_EPOCH`. The build manifest records the Go version, commit and
epoch. Reproducibility is not verified by this repository's checks; compare two
independent builds with `sha256sum` before claiming it.

## Signing, SBOM and provenance checklist

This repository currently produces checksums, not signatures. No step in the
fork workflow fakes a signature or publishes to an upstream repository.

Before a release is described as signed:

- [ ] Create a fork-only GPG key. Store the private key and passphrase in a
      protected release environment with required reviewers. Never reuse an
      upstream key and never expose the key to `pull_request` runs.
- [ ] Sign `SHA256SUMS` with `gpg --batch --armor --detach-sign` and verify the
      result with the public key on a separate machine.
- [ ] If an APT repository is published, sign the repository `Release` file so
      clients fetch `InRelease` or `Release.gpg`, and publish only from a
      protected branch or tag with a dedicated least-privilege credential.
- [ ] Generate an SBOM with a pinned tool, for example
      `syft dir:dist -o spdx-json=dist/sbom.spdx.json`, and attach it to the
      release. The workflow has a TODO for this; it is not generated today.
- [ ] Generate build provenance with a pinned SLSA or in-toto generator, and
      grant `id-token: write` only to that job in the protected environment.
- [ ] Verify every artifact and signature from a clean machine before publishing.

The fork workflow signs only when the dedicated signing secret is present and the
run is not a pull request. It never publishes a package or a repository.

## Validation

```bash
bash packaging/netbird-split/tests/run.sh
```

The test builds both architectures, validates DEB metadata and file contents
with `dpkg-deb` when available (and with `ar` plus `tar` otherwise), checks the
tarball layout, and runs the maintainer and tarball scripts against temporary
prefixes. If Docker is available it also installs, reinstalls, removes and purges
the amd64 DEB in a disposable Debian container, with upstream file fixtures in
place to prove they survive.

## CI

`.github/workflows/netbird-split-package.yml` builds the client, runs the
split-tunnel unit and race tests, runs the privileged suite when Docker is
available, lints the shell scripts and Go packages, runs the existing release
script tests, builds and validates both packages, and uploads the artifacts with
checksums. It has read-only permissions and no publishing step.
