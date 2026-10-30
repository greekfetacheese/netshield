# NetShield

NetShield is a Linux application firewall: the root daemon `netshieldd` holds the first
packet of every new outbound flow in the kernel and asks the unprivileged `netshield-gui`
what to do with it, per application, with an optional scope to the domain being contacted.
Rules and decisions are persisted as JSON in `/etc/netshield`.

## Install

Linux with nftables and systemd, root for the daemon, and a logged-in user for the GUI.
Build the binaries first, then install them:

```sh
cargo build --profile prod
sudo packaging/install.sh --bin-dir target/prod
```

The installer never builds. It installs `netshieldd` and `netshield-gui` to
`/usr/local/bin`, writes `/etc/netshield/config.json` (keeping an existing one), installs
the hardened systemd unit and the XDG autostart entry, and enables the service. Use
`--prefix DIR` to install under a different prefix, and `--help` for every flag. It
refuses to run while OpenSnitch is active: stop and disable OpenSnitch first.

## First run

The daemon creates the rule store on first start, and the GUI starts with your session
from `/etc/xdg/autostart/netshield-gui.desktop` and connects to
`/run/netshield/control.sock`. New connections then raise an alert; Allow or Deny, choose
how long the decision lasts, and optionally scope it to the observed domain. If the GUI is
not running when a prompt is raised, the daemon logs a warning and denies the prompt when
it times out.

## Uninstall

```sh
sudo packaging/install.sh --uninstall   # keeps /etc/netshield
sudo packaging/install.sh --purge       # also removes /etc/netshield
```

Both stop and disable the service, remove the unit, the autostart entry and the binaries,
and delete the `inet netshield` nftables table.

## Known limitations

- Linux only; the firewall is nftables and the daemon is a systemd service.
- Outbound traffic only: inbound connections are not filtered.
- No blocklists yet; every rule is per application or per domain.
- `Reject` (TCP RST) is deferred; a denied flow is dropped.
- Domain learning depends on plaintext DNS, so clients using DoH/DoT show an address
  rather than a name.
- The control socket's executable check is a convenience boundary, not a security boundary: a process
  running as your user can run any code under the GUI's own path (`LD_PRELOAD` is enough) and be accepted
  as the GUI. Closing it properly needs the GUI to have its own identity, which is not implemented yet.

## Debugging

See [docs/DEBUGGING.md](docs/DEBUGGING.md) for the runbook and [dev/](dev/README.md) for the
non-root harnesses it uses.

## Requirements

Linux with nftables (kernel ≥ 5.10 realistic, developed against 7.0), Rust ≥ 1.90 to
build, systemd. Root is required for the daemon; the GUI runs as the logged-in user.

## Licence

Dual-licensed under MIT or Apache-2.0, at your option — see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
