# NetShield
NetShield is an interactive application firewall for Linux.

## How it works
The root daemon `netshieldd` holds the first
packet of every new outbound flow in the kernel and asks the unprivileged `netshield-gui`
what to do with it, per application, with an optional scope to the domain being contacted.
Rules and decisions are persisted in `/etc/netshield`.

> [!WARNING]
> **NetShield is alpha software. It has not been hardened and may contain security bugs.**
>
> The daemon runs as root, holds the first packet of every new outbound flow, and is the only thing
> deciding whether that traffic proceeds. A bug in it can let through traffic it meant to block, or
> block traffic it meant to allow — and the control socket's executable check is a convenience
> boundary, not a security boundary (see [Known limitations](#known-limitations)).

## Install

### From .deb package (Easiest)
Go to the latest [release](https://github.com/greekfetacheese/netshield/releases), download and run the .deb package installer

### From source

Build the binaries first, then install them:

```sh
cargo build --profile prod
sudo packaging/install.sh --bin-dir target/prod
```

The installer never builds. It installs `netshieldd`, `netshield-gui` and `netshieldctl` to
`/usr/local/bin`, writes `/etc/netshield/config.json` (keeping an existing one), installs
the hardened systemd unit, the application-menu entry with its icon set, and the XDG
autostart entry, and enables the service. Use
`--prefix DIR` to install under a different prefix, and `--help` for every flag. It
refuses to run while OpenSnitch is active: stop and disable OpenSnitch first.

### Build your own .deb package

amd64, on Ubuntu 20.04+ / Mint 20+ / Debian 11+ when built against glibc 2.31 (see below); a plain host build needs Ubuntu 24.04+ / Mint 22+:

```sh
cargo build --profile prod
packaging/deb/build-deb.sh
sudo apt install ./packaging/deb/out/netshield_*_amd64.deb
```

`build-deb.sh` takes the version from `[workspace.package]` in `Cargo.toml`, so a version bump needs no
other edit: the Debian changelog is generated from that version and the commit subjects since the last
bump (`--notes FILE` overrides it). The package installs the same file set
`packaging/install.sh` installs — the daemon, the GUI and
`netshieldctl` in `/usr/bin`, the hardened unit in `/usr/lib/systemd/system`, the menu entry with its
icon set, and the tray autostart — creates `/etc/netshield/config.json` for the user who installed it,
and enables the service. It **refuses to unpack over a source install**: remove that first with
`sudo packaging/install.sh --uninstall`, which keeps `/etc/netshield` and its rules. If no desktop user
can be determined the package configures but does not start the service, and says so: a control socket
without an `allowed_uid` would time out every prompt into a deny.

#### Building for older distributions

`cargo build --profile prod` links against the glibc of the machine it runs on, and the package inherits
that floor (glibc 2.39 on Mint 22 / Ubuntu 24.04). For a package that installs on Ubuntu 20.04+, Mint 20+
and Debian 11+ (glibc 2.31), link against that glibc instead:

```sh
cargo install cargo-zigbuild          # one-off; needs a zig on PATH (>= 0.15)
cargo zigbuild --profile prod --target x86_64-unknown-linux-gnu.2.31
packaging/deb/build-deb.sh --bin-dir target/x86_64-unknown-linux-gnu/prod
```

`build-deb.sh` reads the floor out of the binaries themselves and writes it into `Depends`, so the package
cannot claim a glibc older than it needs; it warns when the binaries in `--bin-dir` need more than 2.31.
The 2.31 build references nothing newer than `GLIBC_2.30` and runs on both 2.31 and 2.39. `--glibc X`
overrides the derived value.

## First run

The daemon creates the rule store on first start, and the GUI starts with your session
from `/etc/xdg/autostart/netshield.desktop`, in the tray with no window on screen, and
connects to `/run/netshield/control.sock`. New connections then raise an alert; Allow or
Deny, choose how long the decision lasts, and optionally scope it to the observed
domain. If the GUI is not running when a prompt is raised, the daemon logs a warning and
denies the prompt when it times out.

## Uninstall

For a package install:

```sh
sudo apt purge netshield               # also removes /etc/netshield; `apt remove` keeps it
```

For a source install:

```sh
sudo packaging/install.sh --uninstall   # keeps /etc/netshield
sudo packaging/install.sh --purge       # also removes /etc/netshield
```

All of these stop and disable the service, remove the unit, the autostart entry and the binaries,
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
