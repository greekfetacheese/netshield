#!/usr/bin/env bash
# Builds the NetShield .deb from prebuilt binaries.
#
# It never builds Rust: run `cargo build --profile prod` first, or pass --bin-dir with
# binaries built elsewhere. The file layout comes from packaging/install.sh in staging
# mode (--root), so a package install and a source install cannot drift apart; this
# script adds only what is package-specific: control metadata, conffiles, md5sums, the
# maintainer scripts and /usr/share/doc.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO="$(cd "$PACKAGING/.." && pwd)"

PACKAGE="netshield"
PREFIX="/usr"
UNIT_DIR="/usr/lib/systemd/system"
BIN_DIR="$REPO/target/prod"
OUT_DIR="$SCRIPT_DIR/out"
VERSION=""
REVISION="1"
ARCH="$(dpkg --print-architecture)"
MAINTAINER="Michalis Molfetas <greekfetacheese@proton.me>"
KEEP=0

usage() {
   cat <<'EOF'
Usage: packaging/deb/build-deb.sh [options]

Builds netshield_<version>-<revision>_<arch>.deb from prebuilt binaries. It never
builds Rust.

Options:
  --version VERSION   upstream version (default: [workspace.package].version)
  --revision N        Debian revision (default: 1)
  --bin-dir DIR       directory holding netshieldd, netshield-gui and netshieldctl
                      (default: target/prod)
  --out DIR           output directory (default: packaging/deb/out)
  --arch ARCH         architecture (default: dpkg --print-architecture)
  --maintainer TEXT   Maintainer field (default: Michalis Molfetas <...>)
  --keep              keep the staging tree and print its path
  --help              print this help and exit
EOF
}

note() {
   printf '%s\n' "$*"
}

fail() {
   printf 'error: %s\n' "$*" >&2
   exit 1
}

while [ "$#" -gt 0 ]; do
   case "$1" in
      --version)
         [ "$#" -ge 2 ] || fail "--version needs a value"
         VERSION="$2"
         shift 2
         ;;
      --version=*)
         VERSION="${1#--version=}"
         shift
         ;;
      --revision)
         [ "$#" -ge 2 ] || fail "--revision needs a value"
         REVISION="$2"
         shift 2
         ;;
      --revision=*)
         REVISION="${1#--revision=}"
         shift
         ;;
      --bin-dir)
         [ "$#" -ge 2 ] || fail "--bin-dir needs a directory"
         BIN_DIR="$2"
         shift 2
         ;;
      --bin-dir=*)
         BIN_DIR="${1#--bin-dir=}"
         shift
         ;;
      --out)
         [ "$#" -ge 2 ] || fail "--out needs a directory"
         OUT_DIR="$2"
         shift 2
         ;;
      --out=*)
         OUT_DIR="${1#--out=}"
         shift
         ;;
      --arch)
         [ "$#" -ge 2 ] || fail "--arch needs a value"
         ARCH="$2"
         shift 2
         ;;
      --arch=*)
         ARCH="${1#--arch=}"
         shift
         ;;
      --maintainer)
         [ "$#" -ge 2 ] || fail "--maintainer needs a value"
         MAINTAINER="$2"
         shift 2
         ;;
      --maintainer=*)
         MAINTAINER="${1#--maintainer=}"
         shift
         ;;
      --keep)
         KEEP=1
         shift
         ;;
      --help)
         usage
         exit 0
         ;;
      *)
         fail "unknown option: $1 (try --help)"
         ;;
   esac
done

if [ -z "$VERSION" ]; then
   VERSION="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' \
      "$REPO/Cargo.toml" | head -1)"
   [ -n "$VERSION" ] || fail "could not read [workspace.package] version from $REPO/Cargo.toml"
fi
DEB_VERSION="$VERSION-$REVISION"

command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is not installed"
for binary in netshieldd netshield-gui netshieldctl; do
   [ -x "$BIN_DIR/$binary" ] || fail "missing prebuilt binary: $BIN_DIR/$binary (run 'cargo build --profile prod', or pass --bin-dir)"
done
for script in preinst postinst prerm postrm; do
   [ -f "$SCRIPT_DIR/$script" ] || fail "missing maintainer script: $SCRIPT_DIR/$script"
done
for size in 16 24 32 48 64 128 256; do
   [ -f "$PACKAGING/icons/hicolor/${size}x${size}/apps/netshield.png" ] \
      || fail "missing icon ${size}x${size} (regenerate with python3 scripts/make-icons.py)"
done

changelog_version="$(sed -n "1s/^$PACKAGE (\([^)]*\)).*/\1/p" "$SCRIPT_DIR/changelog")"
[ "$changelog_version" = "$DEB_VERSION" ] \
   || fail "packaging/deb/changelog's top entry is '${changelog_version:-missing}', expected '$DEB_VERSION'"

STAGE_ROOT="$(mktemp -d "$REPO/target/deb-stage.XXXXXX")"
cleanup() {
   if [ "$KEEP" -eq 1 ]; then
      note "stage kept at $STAGE_ROOT/$PACKAGE"
   else
      rm -rf "$STAGE_ROOT"
   fi
}
trap cleanup EXIT
STAGE="$STAGE_ROOT/$PACKAGE"
install -d -m 0755 "$STAGE"

note "staging the file set with packaging/install.sh"
"$PACKAGING/install.sh" --root "$STAGE" --prefix "$PREFIX" --unit-dir "$UNIT_DIR" --bin-dir "$BIN_DIR"

# The config merge helper ships beside the binaries' layout so postinst can add the keys a
# newer version needs without carrying its own copy of that logic.
install -D -m 0755 "$PACKAGING/merge-config.sh" "$STAGE/usr/share/netshield/merge-config.sh"

DOC_DIR="$STAGE/usr/share/doc/$PACKAGE"
install -d -m 0755 "$DOC_DIR"
install -m 0644 "$REPO/README.md" "$REPO/LICENSE-MIT" "$REPO/LICENSE-APACHE" "$DOC_DIR/"
install -m 0644 "$SCRIPT_DIR/copyright" "$DOC_DIR/copyright"
gzip -9n -c "$SCRIPT_DIR/changelog" > "$DOC_DIR/changelog.gz"
chmod 0644 "$DOC_DIR/changelog.gz"

CONTROL_DIR="$STAGE/DEBIAN"
install -d -m 0755 "$CONTROL_DIR"
for script in preinst postinst prerm postrm; do
   install -m 0755 "$SCRIPT_DIR/$script" "$CONTROL_DIR/$script"
done

# The autostart entry is the one file in /etc a user is expected to edit (delay, NoDisplay),
# so it is a conffile. config.json is NOT: its allowed_uid and gui_path are per-machine and
# postinst writes them, so dpkg must not read that as a local modification.
printf '/etc/xdg/autostart/%s.desktop\n' "$PACKAGE" > "$CONTROL_DIR/conffiles"
chmod 0644 "$CONTROL_DIR/conffiles"

installed_size="$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)"

cat > "$CONTROL_DIR/control" <<EOF
Package: $PACKAGE
Version: $DEB_VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $installed_size
Depends: libc6 (>= 2.39), libgcc-s1, nftables, systemd, python3-minimal
Recommends: libgl1, libegl1, libxkbcommon0, libx11-6, libwayland-client0
Section: net
Priority: optional
Homepage: https://github.com/greekfetacheese/netshield
Description: Linux application firewall with per-application connection prompts
 NetShield holds the first packet of every new outbound flow in the kernel and asks an
 unprivileged desktop GUI what to do with it: allow or deny, per application, optionally
 scoped to the domain being contacted. The root daemon programs nftables and NFQUEUE;
 the GUI runs in the system tray and answers the alerts.
 .
 Rules marked permanent survive a restart. Configuration and rules live in /etc/netshield.
EOF
chmod 0644 "$CONTROL_DIR/control"

( cd "$STAGE" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' | sort -z | xargs -0 md5sum ) \
   > "$CONTROL_DIR/md5sums"
chmod 0644 "$CONTROL_DIR/md5sums"

install -d -m 0755 "$OUT_DIR"
DEB="$OUT_DIR/${PACKAGE}_${DEB_VERSION}_${ARCH}.deb"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"

note ""
dpkg-deb -I "$DEB"
note ""
note "built: $DEB"
( cd "$OUT_DIR" && sha256sum "$(basename "$DEB")" )
note "contents:  dpkg-deb -c $DEB"
note "install:   sudo apt install $DEB"
