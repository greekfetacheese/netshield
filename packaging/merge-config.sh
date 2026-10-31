#!/usr/bin/env bash
# Adds the keys a NetShield config from an older install lacks, without changing any
# value that is already there. Called by packaging/install.sh. It needs python3: the
# daemon's config is JSON and bash must not hand-edit JSON.
set -euo pipefail

note() {
   printf '%s\n' "$*"
}

fail() {
   printf 'error: %s\n' "$*" >&2
   exit 1
}

usage() {
   cat <<'EOF'
Usage: merge-config.sh [--dry-run] CONFIG_FILE PREFIX
       merge-config.sh --self-test
       merge-config.sh --print-dns-servers  print the default dns_servers JSON and exit

Adds the config keys this NetShield version needs, preserving every existing key and
value. --dry-run prints what would be added without writing anything.
EOF
}

# The DNS answer sources this box should trust.
#
# An empty list means any sender may teach the name cache, which lets a peer that answers a
# query name its own address — so a domain rule can be made to match it. systemd-resolved's
# stub is the tight answer on a box that uses it: applications consume the stub's answers, so
# domain rules keep working, and a loopback source cannot be forged from the network.
# `NETSHIELD_RESOLV_CONF` exists so the self-test can point at a fixture.
dns_servers_default() {
   local resolv="${NETSHIELD_RESOLV_CONF:-/etc/resolv.conf}"
   if grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.53([[:space:]]|$)' "$resolv" 2>/dev/null; then
      printf '["127.0.0.53"]'
      return
   fi
   printf 'note: no local resolver stub in %s; dns_servers stays empty and any sender may name its own address — set it to your resolver addresses\n' "$resolv" >&2
   printf '[]'
}

merge_file() {
   local config="$1"
   local prefix="$2"
   local dry_run="$3"

   if [ ! -e "$config" ]; then
      note "no config at $config; nothing to merge"
      return 0
   fi

   if ! command -v python3 >/dev/null 2>&1; then
      fail "python3 is required to merge $config safely; add these keys by hand instead: table, unattributable_closed_flow, unmatched_transport, icmp_echo, gui_path=$prefix/bin/netshield-gui, dns_servers=[...]"
   fi

   local dns_servers
   dns_servers="$(dns_servers_default)"
   python3 - "$config" "$prefix" "$dry_run" "$dns_servers" <<'PY'
import json
import os
import sys
import tempfile

config_path, prefix, dry_run, dns_servers_json = (
    sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4]
)
dns_servers = json.loads(dns_servers_json)

try:
    with open(config_path, "r", encoding="utf-8") as handle:
        existing = json.load(handle)
except (OSError, json.JSONDecodeError) as exc:
    sys.stderr.write(
        f"error: {config_path} is not valid JSON; fix or remove it ({exc})\n"
    )
    sys.exit(1)

if not isinstance(existing, dict):
    sys.stderr.write(f"error: {config_path} is not a JSON object; fix or remove it\n")
    sys.exit(1)

if "allowed_uid" not in existing:
    sys.stderr.write(
        f"error: {config_path} has no allowed_uid; the daemon cannot start without it. "
        "Add it by hand.\n"
    )
    sys.exit(1)

wanted = [
    ("table", "netshield"),
    ("unattributable_closed_flow", "drop"),
    ("unmatched_transport", "deny"),
    ("icmp_echo", "deny"),
    ("gui_path", f"{prefix}/bin/netshield-gui"),
    ("dns_servers", dns_servers),
]
missing = [(key, value) for key, value in wanted if key not in existing]

if not missing:
    print(f"{config_path} already has every key")
    sys.exit(0)

merged = dict(existing)
for key, value in missing:
    merged[key] = value

if dry_run:
    for key, value in missing:
        print(f"added {key}={value} to {config_path}")
    sys.exit(0)

directory = os.path.dirname(os.path.abspath(config_path))
tmp_path = None
try:
    fd, tmp_path = tempfile.mkstemp(
        prefix=".netshield-config.", suffix=".tmp", dir=directory
    )
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(merged, handle, indent=2)
        handle.write("\n")
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, config_path)
except OSError as exc:
    if tmp_path is not None:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    sys.stderr.write(f"error: could not write {config_path}: {exc}\n")
    sys.exit(1)

for key, value in missing:
    print(f"added {key}={value} to {config_path}")
PY
}

selftest_pass() {
   printf 'self-test: %s/7 ok\n' "$1"
}

selftest_fail() {
   printf 'self-test: %s/7 failed: %s\n' "$1" "$2" >&2
   exit 1
}

self_test() {
   SELFTEST_TMP="$(mktemp -d)" || fail "mktemp -d failed"
   trap 'rm -rf "$SELFTEST_TMP"' EXIT

   local self="$0"
   local tmp="$SELFTEST_TMP"
   local prefix="$tmp/prefix"
   local legacy="$tmp/legacy.json"
   local before="$tmp/legacy.before.json"
   local merged_copy="$tmp/legacy.merged.json"
   local dry_copy="$tmp/legacy.dry-run.json"

   cat > "$legacy" <<'EOF'
{"queue_num":0,"dns_queue_num":1,"prompt_timeout_secs":30,"default_action":"prompt","allowed_uid":1000,"log_level":"info","socket_path":"/run/netshield/control.sock","rules_path":"/etc/netshield/rules.db"}
EOF
   cp "$legacy" "$before"
   cp "$legacy" "$dry_copy"

   if ! "$self" "$legacy" "$prefix" >/dev/null; then
      selftest_fail 1 "merge of the legacy config failed"
   fi

   if ! python3 - "$legacy" "$prefix" <<'PY'
import json
import sys

path, prefix = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as handle:
    config = json.load(handle)

original = {
    "queue_num",
    "dns_queue_num",
    "prompt_timeout_secs",
    "default_action",
    "allowed_uid",
    "log_level",
    "socket_path",
    "rules_path",
}
expected = {
    "table",
    "unattributable_closed_flow",
    "unmatched_transport",
    "icmp_echo",
    "gui_path",
    "dns_servers",
}
if set(config) != original | expected:
    sys.exit(f"keys after merge: {sorted(config)}")
if config["gui_path"] != f"{prefix}/bin/netshield-gui":
    sys.exit(f"gui_path is {config['gui_path']!r}")
PY
   then
      selftest_fail 1 "legacy config did not gain exactly the six keys"
   fi
   selftest_pass 1

   if ! python3 - "$legacy" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)

expected = {
    "queue_num": 0,
    "dns_queue_num": 1,
    "prompt_timeout_secs": 30,
    "default_action": "prompt",
    "allowed_uid": 1000,
    "log_level": "info",
    "socket_path": "/run/netshield/control.sock",
    "rules_path": "/etc/netshield/rules.db",
}
for key, value in expected.items():
    if config.get(key) != value:
        sys.exit(f"{key} is {config.get(key)!r}, expected {value!r}")
if config["allowed_uid"] != 1000:
    sys.exit("allowed_uid is not 1000")
if config["queue_num"] != 0:
    sys.exit("queue_num is not 0")
PY
   then
      selftest_fail 2 "a pre-existing value changed"
   fi
   selftest_pass 2

   cp "$legacy" "$merged_copy"
   if ! second_output="$("$self" "$legacy" "$prefix")"; then
      selftest_fail 3 "second merge failed"
   fi
   if printf '%s\n' "$second_output" | grep -q '^added '; then
      selftest_fail 3 "second merge added a key"
   fi
   if ! cmp -s "$legacy" "$merged_copy"; then
      selftest_fail 3 "second merge changed the file"
   fi
   selftest_pass 3

   if ! dry_output="$("$self" --dry-run "$dry_copy" "$prefix")"; then
      selftest_fail 4 "--dry-run failed"
   fi
   if ! cmp -s "$dry_copy" "$before"; then
      selftest_fail 4 "--dry-run changed the file"
   fi
   if [ "$(printf '%s\n' "$dry_output" | grep -c '^added ')" -ne 6 ]; then
      selftest_fail 4 "--dry-run did not print one added line per key"
   fi
   selftest_pass 4

   if ! python3 -m json.tool "$legacy" >/dev/null 2>&1; then
      selftest_fail 5 "the merged file is not valid JSON"
   fi
   if [ "$(stat -c '%a' "$legacy")" != "640" ]; then
      selftest_fail 5 "the merged file mode is not 0640"
   fi
   selftest_pass 5

   # The default must follow the box's resolver: the stub when it is there, empty when it is not.
   local stub_resolv="$tmp/resolv.stub"
   local plain_resolv="$tmp/resolv.plain"
   printf 'nameserver 127.0.0.53\n' > "$stub_resolv"
   printf 'nameserver 192.0.2.53\n' > "$plain_resolv"

   cp "$before" "$tmp/stub.json"
   if ! NETSHIELD_RESOLV_CONF="$stub_resolv" "$self" "$tmp/stub.json" "$prefix" >/dev/null; then
      selftest_fail 6 "merge with a resolver stub failed"
   fi
   if ! python3 - "$tmp/stub.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
sys.exit(0 if config["dns_servers"] == ["127.0.0.53"] else f"dns_servers is {config['dns_servers']!r}")
PY
   then
      selftest_fail 6 "the stub was not used as the dns_servers default"
   fi
   selftest_pass 6

   cp "$before" "$tmp/plain.json"
   if ! NETSHIELD_RESOLV_CONF="$plain_resolv" "$self" "$tmp/plain.json" "$prefix" >/dev/null; then
      selftest_fail 7 "merge without a resolver stub failed"
   fi
   if ! python3 - "$tmp/plain.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
sys.exit(0 if config["dns_servers"] == [] else f"dns_servers is {config['dns_servers']!r}")
PY
   then
      selftest_fail 7 "an empty default was not kept without a stub"
   fi
   selftest_pass 7
}

DRY_RUN=0
SELF_TEST=0

while [ "$#" -gt 0 ]; do
   case "$1" in
      --print-dns-servers)
         dns_servers_default
         printf '\n'
         exit 0
         ;;
      --dry-run)
         DRY_RUN=1
         shift
         ;;
      --self-test)
         SELF_TEST=1
         shift
         ;;
      --help)
         usage
         exit 0
         ;;
      --)
         shift
         break
         ;;
      -*)
         usage >&2
         fail "unknown option: $1"
         ;;
      *)
         break
         ;;
   esac
done

if [ "$SELF_TEST" -eq 1 ]; then
   [ "$#" -eq 0 ] || fail "--self-test takes no arguments"
   self_test
   exit 0
fi

[ "$#" -eq 2 ] || {
   usage >&2
   fail "expected CONFIG_FILE and PREFIX"
}
merge_file "$1" "$2" "$DRY_RUN"
