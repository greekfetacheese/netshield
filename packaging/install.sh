#!/usr/bin/env bash
# Installs or removes NetShield. Prebuilt binaries only: this script never builds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr/local"
BIN_DIR="target/prod"
DRY_RUN=0
UNINSTALL=0
PURGE=0

UNIT_DEST="/etc/systemd/system/netshield.service"
AUTOSTART_DEST="/etc/xdg/autostart/netshield.desktop"
MENU_DEST="/usr/share/applications/netshield.desktop"
ICON_ROOT="/usr/share/icons/hicolor"
ICON_SIZES="16 24 32 48 64 128 256"
CONFIG_DIR="/etc/netshield"
CONFIG_FILE="$CONFIG_DIR/config.json"
SOCKET_PATH="/run/netshield/control.sock"

usage() {
   cat <<'EOF'
Usage: packaging/install.sh [options]

Installs the prebuilt netshieldd, netshield-gui and netshieldctl from --bin-dir, the
hardened systemd unit, the application-menu entry with its icon set, and the XDG
autostart entry. It never builds anything.

Options:
  --prefix DIR     install binaries under DIR/bin and use them in the unit and
                   the autostart entry (default: /usr/local)
  --bin-dir DIR    directory holding the prebuilt netshieldd and netshield-gui
                   (default: target/prod)
  --dry-run        print every path and command instead of touching anything
  --uninstall      stop and disable the service, remove the unit, the menu entry,
                   the autostart entry, the icon set, the nftables table and the
                   binaries; keep /etc/netshield
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
   local ctl="$BIN_DIR/netshieldctl"
   [ -x "$daemon" ] || fail "missing prebuilt binary: $daemon (pass --bin-dir DIR)"
   [ -x "$gui" ] || fail "missing prebuilt binary: $gui (pass --bin-dir DIR)"
   [ -x "$ctl" ] || fail "missing prebuilt binary: $ctl (pass --bin-dir DIR)"

   run install -d -m 0755 "$PREFIX/bin"
   run install -m 0755 "$daemon" "$PREFIX/bin/netshieldd"
   run install -m 0755 "$gui" "$PREFIX/bin/netshield-gui"
   run install -m 0755 "$ctl" "$PREFIX/bin/netshieldctl"
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

   local dns_servers
   dns_servers="$("$SCRIPT_DIR/merge-config.sh" --print-dns-servers)" \
      || fail "could not read the default dns_servers from merge-config.sh"
   [ -n "$dns_servers" ] || fail "merge-config.sh printed no default dns_servers"

   cat > "$CONFIG_FILE" <<EOF
{
  "queue_num": 0,
  "dns_queue_num": 1,
  "prompt_timeout_secs": 30,
  "default_action": "prompt",
  "unattributable_closed_flow": "drop",
  "allowed_uid": $allowed_uid,
  "gui_path": "$PREFIX/bin/netshield-gui",
  "dns_servers": $dns_servers,
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

# A stale cache shows the generic fallback and reads exactly like a missing icon, so the
# theme caches are refreshed after every change. Both tools are optional on a minimal
# system, and a missing one is not a failed install.
refresh_caches() {
   if [ "$DRY_RUN" -eq 1 ]; then
      return 0
   fi
   if command -v gtk-update-icon-cache >/dev/null 2>&1; then
      gtk-update-icon-cache -f -t "$ICON_ROOT" >/dev/null 2>&1 \
         || note "warning: gtk-update-icon-cache failed; the menu icon may stay generic until it does"
   fi
   if command -v update-desktop-database >/dev/null 2>&1; then
      update-desktop-database -q "$(dirname "$MENU_DEST")" >/dev/null 2>&1 || true
   fi
}

install_icons() {
   local size source
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would install the netshield mark at these sizes under $ICON_ROOT: $ICON_SIZES"
      return
   fi
   for size in $ICON_SIZES; do
      source="$SCRIPT_DIR/icons/hicolor/${size}x${size}/apps/netshield.png"
      [ -f "$source" ] || fail "missing icon: $source (regenerate with python3 scripts/make-icons.py)"
      install -d -m 0755 "$ICON_ROOT/${size}x${size}/apps"
      install -m 0644 "$source" "$ICON_ROOT/${size}x${size}/apps/netshield.png"
   done
}

install_desktop() {
   if [ "$DRY_RUN" -eq 1 ]; then
      note "would write $MENU_DEST and $AUTOSTART_DEST (prefix $PREFIX)"
      return
   fi
   install -d -m 0755 "$(dirname "$MENU_DEST")" "$(dirname "$AUTOSTART_DEST")"
   render "$SCRIPT_DIR/netshield.desktop" > "$MENU_DEST"
   chmod 0644 "$MENU_DEST"
   render "$SCRIPT_DIR/netshield-autostart.desktop" > "$AUTOSTART_DEST"
   chmod 0644 "$AUTOSTART_DEST"
}

remove_icons() {
   local size
   for size in $ICON_SIZES; do
      rm -f "$ICON_ROOT/${size}x${size}/apps/netshield.png"
   done
}

do_install() {
   require_root
   refuse_second_firewall
   install_binaries
   install_config
   install_unit
   install_icons
   install_desktop
   refresh_caches

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
      note "would remove $PREFIX/bin/netshieldd, $PREFIX/bin/netshield-gui and $PREFIX/bin/netshieldctl"
      note "would remove $MENU_DEST and $AUTOSTART_DEST"
      note "would remove the netshield mark from $ICON_ROOT ($ICON_SIZES)"
   else
      rm -f "$PREFIX/bin/netshieldd" "$PREFIX/bin/netshield-gui" "$PREFIX/bin/netshieldctl"
      rm -f "$MENU_DEST" "$AUTOSTART_DEST"
      remove_icons
      refresh_caches
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
