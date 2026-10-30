#!/bin/bash
# Run netshieldd without root and without touching the host firewall: the daemon runs
# inside a throwaway network namespace with a dummy interface at 10.88.0.1/24.
#
# This is how the queue-sweep and attribution fixes were proved.  The host's real nftables
# table is never touched: `unshare -rn` gives a private network namespace, so the only
# `inet netshield` table that exists is the one inside it.  On exit the daemon is stopped,
# which removes that table, and the namespace is destroyed with every process in it.
#
# The dummy interface exists only inside the namespace, so a host-side `curl` cannot reach
# it.  Instead, the namespace runs a small loop that reads a trigger line from
# target/dev/netns/trigger and then executes the `curl` to 10.88.0.2 *inside* the
# namespace.  That keeps the whole harness unprivileged and is why the printed
# instructions say `echo go > .../trigger` rather than showing a host curl.
#
# Runtime files live under target/dev/netns/ (target/ is gitignored):
#   config.json   the generated daemon configuration
#   daemon.log    the daemon's stderr, which is the log to read
#   daemon.pid    the daemon's PID, so the trap can stop it
#   trigger       write a line here to make the namespace create a flow
#   control.sock  the control socket dev/decide-client.py connects to
#   rules.db      the rule store; `forever` rules land here, memory-only ones do not
set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
run="$repo/target/dev/netns"
config="$run/config.json"
daemon_log="$run/daemon.log"
pid_file="$run/daemon.pid"
trigger="$run/trigger"
sock="$run/control.sock"
rules="$run/rules.db"
dummy_ip="10.88.0.1/24"
dummy_peer="10.88.0.2"

usage() {
    cat <<EOF
usage: netns-run.sh [OPTIONS]

Runs netshieldd as mapped root in a private network namespace, prints where its log is
and how to drive it, then holds the namespace open until Ctrl-C.

Options:
  --build       build the daemon first: cargo build --release -p netshield-daemon
  --demo        run the whole proof automatically: subscribe, trigger a flow, print the
                decision line from the daemon log, then exit
  --timeout N   hold the namespace for N seconds instead of waiting for Ctrl-C
  --help        print this help

Without --demo or --timeout the script waits for Ctrl-C interactively; a non-interactive
run without them holds for 60 s so an automated caller cannot hang forever.
EOF
}

build=0
demo=0
seconds=""
while [ $# -gt 0 ]; do
    case "$1" in
        --build) build=1; shift ;;
        --demo) demo=1; shift ;;
        --timeout) seconds="${2:?--timeout needs a count}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "netns-run: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done

daemon_bin="$repo/target/release/netshieldd"
if [ "$build" -eq 1 ]; then
    ( cd "$repo" && cargo build --release -p netshield-daemon ) || exit 1
fi
if [ ! -x "$daemon_bin" ]; then
    echo "netns-run: $daemon_bin is missing; run with --build or build it first" >&2
    exit 1
fi
for tool in unshare ip; do
    if ! command -v "$tool" >/dev/null; then
        echo "netns-run: $tool is required (util-linux / iproute2)" >&2
        exit 1
    fi
done

mkdir -p "$run"
rm -f "$sock" "$daemon_log" "$pid_file" "$rules" "$trigger"
# The trigger is a FIFO: the namespace blocks reading it, and each line written outside
# makes the namespace run the curl on the dummy interface.
mkfifo "$trigger"

cat > "$config" <<EOF
{
  "queue_num": 0,
  "dns_queue_num": 1,
  "prompt_timeout_secs": 30,
  "default_action": "prompt",
  "allowed_uid": 0,
  "log_level": "info",
  "socket_path": "$sock",
  "rules_path": "$rules"
}
EOF

ns_pid=""
cleanup() {
    local code=$?
    trap - EXIT INT TERM HUP
    # SIGTERM lets the daemon remove its own table and socket and log that it did; -9 is
    # the fallback, and destroying the namespace takes the table with it either way.
    if [ -f "$pid_file" ]; then
        daemon_pid="$(cat "$pid_file" 2>/dev/null)"
        if [ -n "$daemon_pid" ]; then
            kill "$daemon_pid" 2>/dev/null
            for _ in $(seq 1 30); do
                kill -0 "$daemon_pid" 2>/dev/null || break
                sleep 0.1
            done
            kill -9 "$daemon_pid" 2>/dev/null
        fi
    fi
    if [ -n "$ns_pid" ]; then
        kill "$ns_pid" 2>/dev/null
        wait "$ns_pid" 2>/dev/null
    fi
    rm -f "$pid_file" "$trigger"
    exit "$code"
}
trap cleanup EXIT INT TERM HUP

echo "namespace: dummy $dummy_ip on a private interface; host traffic is untouched"
echo "config:    $config"
echo "log:       $daemon_log"

# `-r` maps the current user to root, so the daemon passes its effective-uid check and can
# open NFQUEUE sockets; `-n` gives a private network namespace.  nft lives in /usr/sbin on
# most distributions, which the mapped environment may not have on PATH.
unshare -rn --map-root-user sh -c '
    set -eu
    PATH="/usr/sbin:/sbin:$PATH"
    ip link add nstest0 type dummy
    ip addr add "$1" dev nstest0
    ip link set nstest0 up
    "$6" --config "$2" >> "$3" 2>&1 &
    echo $! > "$4"
    # Create a flow on request.  Opening the read side first is what lets the outer
    # writer open the FIFO without blocking; a host-side curl could not reach this device.
    exec 3< "$5"
    while IFS= read -r line <&3; do
        echo "trigger: curl -s -m 5 http://$7/ (inside the namespace)" >> "$3"
        curl -s -m 5 "http://$7/" >/dev/null 2>&1 || true
    done
    wait
' sh "$dummy_ip" "$config" "$daemon_log" "$pid_file" "$trigger" \
    "$daemon_bin" "$dummy_peer" &
ns_pid=$!

for _ in $(seq 1 50); do
    if grep -q 'netshieldd running' "$daemon_log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$ns_pid" 2>/dev/null; then
        echo "netns-run: the namespace exited during startup; last log lines:" >&2
        tail -20 "$daemon_log" >&2 2>/dev/null
        exit 1
    fi
    sleep 0.1
done

if ! grep -q 'netshieldd running' "$daemon_log" 2>/dev/null; then
    echo "netns-run: the daemon did not report running within 5s; see $daemon_log" >&2
    exit 1
fi

echo
echo "daemon is up.  From another shell, in this order:"
echo "  1. subscribe first (the daemon does not replay an already-open prompt):"
echo "     $repo/dev/decide-client.py --socket $sock --action allow --duration once &"
echo "  2. make the namespace create a flow to the dummy address:"
echo "     echo go > $trigger"
echo "     (that runs 'curl -s -m 5 http://$dummy_peer/' inside the namespace)"
echo "  3. read the decision from the daemon log:"
echo "     grep 'prompt .* for ' $daemon_log"
echo "stop: Ctrl-C (stops the daemon, which removes the inet netshield table)"
echo

if [ "$demo" -eq 1 ]; then
    "$repo/dev/decide-client.py" --socket "$sock" --action allow --duration once &
    client=$!
    sleep 0.5
    echo go > "$trigger"
    wait "$client"
    # The decide client returning only means the daemon received the answer; the decision
    # is applied (and logged) a moment later.  Grepping immediately raced the shutdown and
    # printed only the raise line, so poll for the decision before reporting or stopping.
    decided=""
    for _ in $(seq 1 25); do
        decided="$(grep -E 'prompt [0-9]+ for .*: (allow|deny),' "$daemon_log" 2>/dev/null || true)"
        [ -n "$decided" ] && break
        sleep 0.2
    done
    echo
    echo "prompt lines from $daemon_log (raise line, then decision line):"
    grep 'prompt .* for ' "$daemon_log" || echo "  (none: no prompt was raised)"
    if [ -z "$decided" ]; then
        echo "  (no decision line after 5 s)"
        exit 1
    fi
    exit 0
fi

if [ -n "$seconds" ]; then
    sleep "$seconds"
elif [ ! -t 0 ]; then
    # A non-interactive caller cannot press Ctrl-C, so bound the run instead of hanging.
    sleep 60
else
    wait "$ns_pid"
fi
