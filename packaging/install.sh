#!/usr/bin/env bash
# Installs or removes NetShield. Prebuilt binaries only: this script never builds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr/local"
BIN_DIR="target/release"
DRY_RUN=0
UNINSTALL=0
PURGE=0

UNIT_DEST="/etc/systemd/system/netshield.service"
DESKTOP_DEST="/etc/xdg/autostart/netshield-gui.desktop"
CONFIG_DIR="/etc/netshield"
CONFIG_FILE="$CONFIG_DIR/config.json"
SOCKET_PATH="/run/netshield/control.sock"

usage() {
   cat <<'EOF'
Usage: packaging/install.sh [options]

Installs the prebuilt netshieldd and netshield-gui from --bin-dir, the hardened
systemd unit and the XDG autostart entry. It never builds anything.

Options:
  --prefix DIR     install binaries under DIR/bin and use them in the unit and
                   the autostart entry (default: /usr/local)
  --bin-dir DIR    directory holding the prebuilt netshieldd and netshield-gui
                   (default: target/release)
  --dry-run        print every path and command instead of touching anything
  --uninstall      stop and disable the service, remove the unit, the autostart
                   entry, the nftables table and the binaries; keep /etc/netshield
  --purge          like --uninstall, and also remove /etc/netshield
  --help           print this help and exit
EOF
}

note() {
   printf '%s\n' "$*"
}

fail() {
   printf 'error: %s\n' "$*" >&2
   exit 1
}

run() {
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would run: $*"
   else
      "$@"
   fi
}

require_root() {
   if [ "$(id -u)" -ne 0 ]; then
      fail "must run as root (run with sudo)"
   fi
}

refuse_second_firewall() {
   if systemctl is-active --quiet opensnitch; then
      if [ "$DRY_RUN" -eq 1 ]; then
         note "warning: OpenSnitch is active; a real install would refuse because two firewalls must not share NFQUEUE. Continuing because this is only a dry run."
      else
         fail "OpenSnitch is active; two firewalls must not share NFQUEUE. Run:
  systemctl stop opensnitch && systemctl disable opensnitch"
      fi
   fi
}

render() {
   # Substitutes the install prefix into a packaging template. `|` and `&` would break
   # the sed expression, so a prefix containing either is refused up front.
   case "$PREFIX" in
      *'|'*|*'&'*)
         fail "prefix must not contain '|' or '&': $PREFIX"
         ;;
   esac
   sed "s|/usr/local|$PREFIX|g" "$1"
}

install_binaries() {
   local daemon="$BIN_DIR/netshieldd"
   local gui="$BIN_DIR/netshield-gui"
   [ -x "$daemon" ] || fail "missing prebuilt binary: $daemon (pass --bin-dir DIR)"
   [ -x "$gui" ] || fail "missing prebuilt binary: $gui (pass --bin-dir DIR)"

   run install -d -m 0755 "$PREFIX/bin"
   run install -m 0755 "$daemon" "$PREFIX/bin/netshieldd"
   run install -m 0755 "$gui" "$PREFIX/bin/netshield-gui"
}

install_config() {
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would create $CONFIG_DIR (mode 0750 root:root)"
   else
      install -d -m 0750 -o root -g root "$CONFIG_DIR"
   fi

   if [ -e "$CONFIG_FILE" ]; then
      note "updating $CONFIG_FILE: adding any key this version needs"
      if [ "$DRY_RUN" -eq 1 ]; then
         "$SCRIPT_DIR/merge-config.sh" --dry-run "$CONFIG_FILE" "$PREFIX"
      else
         "$SCRIPT_DIR/merge-config.sh" "$CONFIG_FILE" "$PREFIX"
      fi
      return
   fi

   local allowed_uid="null"
   if [ -n "${SUDO_UID:-}" ] && [[ "${SUDO_UID}" =~ ^[0-9]+$ ]]; then
      allowed_uid="$SUDO_UID"
   fi

   if [ "$DRY_RUN" -eq 1 ]; then
      note "would write $CONFIG_FILE (allowed_uid: $allowed_uid)"
      return
   fi

   cat > "$CONFIG_FILE" <<EOF
{
  "queue_num": 0,
  "dns_queue_num": 1,
  "prompt_timeout_secs": 30,
  "default_action": "prompt",
  "unattributable_closed_flow": "drop",
  "allowed_uid": $allowed_uid,
  "gui_path": "$PREFIX/bin/netshield-gui",
  "log_level": "info",
  "socket_path": "$SOCKET_PATH",
  "rules_path": "/etc/netshield/rules.db"
}
EOF
   chmod 0640 "$CONFIG_FILE"
}

install_unit() {
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would write $UNIT_DEST (prefix $PREFIX)"
      return
   fi
   render "$SCRIPT_DIR/netshield.service" > "$UNIT_DEST"
   chmod 0644 "$UNIT_DEST"
}

install_desktop() {
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would write $DESKTOP_DEST (prefix $PREFIX)"
      return
   fi
   install -d -m 0755 "$(dirname "$DESKTOP_DEST")"
   render "$SCRIPT_DIR/netshield-gui.desktop" > "$DESKTOP_DEST"
   chmod 0644 "$DESKTOP_DEST"
}

do_install() {
   require_root
   refuse_second_firewall
   install_binaries
   install_config
   install_unit
   install_desktop

   run systemctl daemon-reload
   run systemctl enable --now netshield.service

   if [ "$DRY_RUN" -eq 1 ]; then
      note "would print the service state and the socket path $SOCKET_PATH"
      return
   fi
   systemctl --no-pager --full status netshield.service || true
   note "control socket: $SOCKET_PATH"
}

do_uninstall() {
   require_root

   systemctl disable --now netshield.service || true
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would remove $UNIT_DEST"
   else
      rm -f "$UNIT_DEST"
   fi
   run systemctl daemon-reload
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would run: nft delete table inet netshield || true"
   else
      nft delete table inet netshield || true
   fi

   if [ "$DRY_RUN" -eq 1 ]; then
      note "would remove $PREFIX/bin/netshieldd and $PREFIX/bin/netshield-gui"
      note "would remove $DESKTOP_DEST"
   else
      rm -f "$PREFIX/bin/netshieldd" "$PREFIX/bin/netshield-gui"
      rm -f "$DESKTOP_DEST"
   fi

   if [ "$PURGE" -eq 1 ]; then
      if [ "$DRY_RUN" -eq 1 ]; then
         note "would remove $CONFIG_DIR"
      else
         rm -rf "$CONFIG_DIR"
      fi
   else
      note "kept $CONFIG_DIR"
   fi
}

while [ "$#" -gt 0 ]; do
   case "$1" in
      --prefix)
         [ "$#" -ge 2 ] || fail "--prefix needs a directory"
         PREFIX="$2"
         shift 2
         ;;
      --prefix=*)
         PREFIX="${1#--prefix=}"
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
      --dry-run)
         DRY_RUN=1
         shift
         ;;
      --uninstall)
         UNINSTALL=1
         shift
         ;;
      --purge)
         UNINSTALL=1
         PURGE=1
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

if [ "$UNINSTALL" -eq 1 ]; then
   do_uninstall
else
   do_install
fi
