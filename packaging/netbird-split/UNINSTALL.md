# Removing netbird-split

The split client is split-owned. Removing it must not remove an upstream NetBird
installation.

## Debian package

```bash
sudo apt remove netbird-split
```

This stops and disables `netbird-split.service`, asks the daemon to release its
routes and firewall state, and removes the split wrapper, binary, unit and
documentation. It keeps `/etc/default/netbird-split`, `/etc/netbird-split`,
`/var/lib/netbird-split` and `/var/log/netbird-split` so a reinstall keeps the
configuration and state.

To remove those split-owned files as well:

```bash
sudo apt purge netbird-split
```

## Tarball install

```bash
sudo ./uninstall.sh
```

The script stops and disables the unit, removes the split binary, unit and
documentation, and keeps the split configuration and state. Add `--purge` to
remove them too:

```bash
sudo ./uninstall.sh --purge
```

The tarball uninstaller refuses to run when `dpkg` owns
`/usr/bin/netbird-split`; use `apt` in that case.

## What is never removed

Neither uninstall path removes any of these upstream paths:

- `/usr/bin/netbird`
- `/lib/systemd/system/netbird.service`
- `/etc/netbird`
- `/var/lib/netbird`
- `/var/log/netbird`
- `/run/netbird`

If the split service is not running, `netbird-split down` cannot reach the
daemon. Start the split service once, run `sudo netbird-split down`, and stop it
again before removing the package if you need to release residual kernel state.
