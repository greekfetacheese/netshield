#!/bin/bash
# Regression check for the bug fixed in PR #5: does an alert appear while the main window
# is minimised, and does the main window stay `Iconic` when it does?
#
# No root, no filtering and no nftables: dev/fake-daemon.py sends one prompt after a
# deliberate delay, so the prompt arrives once the main window is already iconified.
# Exit 0 = an alert appeared within 20 s while the main window stayed Iconic.
# Exit 1 = no alert, or the main window came back while the alert appeared (the bug).
set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
run="$repo/target/dev"
sock="$run/alert-minimised.sock"
fake_log="$run/alert-minimised-fake.log"
gui_log="$run/alert-minimised-gui.log"
gui_bin="$repo/target/release/netshield-gui"
iconify_bin="$run/iconify"

# The GUI-side harness needs a real X display; agent-sandbox cannot map a window.
export DISPLAY="${DISPLAY:-:0}"
if ! xwininfo -root >/dev/null 2>&1; then
    echo "FAIL: no X display at DISPLAY=$DISPLAY (this harness does not run in agent-sandbox)"
    exit 1
fi
if [ ! -x "$gui_bin" ]; then
    echo "FAIL: $gui_bin is missing; build it with: cargo build -p netshield-gui --release"
    exit 1
fi
if [ ! -x "$iconify_bin" ]; then
    echo "FAIL: $iconify_bin is missing; build it with:"
    echo "      gcc -O2 -o $iconify_bin $repo/dev/iconify.c -lX11"
    exit 1
fi

mkdir -p "$run"
rm -f "$sock" "$fake_log" "$gui_log"
pkill -x netshield-gui 2>/dev/null
sleep 0.5

# The prompt is sent 9 s after subscribe, which is after the 4 s settle and the iconify.
python3 "$repo/dev/fake-daemon.py" \
    --socket "$sock" --duration 30 --prompt-delay 9 --app curl --domain example.com \
    > "$fake_log" 2>&1 &
fake=$!
sleep 1

"$gui_bin" --socket "$sock" > "$gui_log" 2>&1 &
gui=$!
sleep 4

# The main window is the 980-wide shell; the alert is 480 wide (alert::WIDTH).
main=$(wmctrl -lG | awk '/NetShield/ && $5 != 480 {print $1; exit}')
if [ -z "${main:-}" ]; then
    echo "FAIL: no main window (see $gui_log)"
    kill -9 "$gui" "$fake" 2>/dev/null
    exit 1
fi
"$iconify_bin" "$main"
sleep 1
state=$(xprop -id "$main" WM_STATE | grep -o 'Iconic\|Normal' | head -1)
if [ "$state" != "Iconic" ]; then
    echo "FAIL: the main window is $state, not Iconic; the iconify step did not take"
    kill -9 "$gui" "$fake" 2>/dev/null
    exit 1
fi
echo "main window: $state (the prompt arrives in ~9s)"

alert=""
for i in $(seq 1 20); do
    sleep 1
    window=$(wmctrl -lG | awk '/NetShield/ && $5 == 480 {print $1}' | head -1)
    if [ -n "${window:-}" ]; then
        alert="$window"
        echo "alert appeared after ~${i}s: $alert"
        xwd -id "$alert" -silent > "$run/alert-minimised.xwd" 2>/dev/null
        break
    fi
done

state2=$(xprop -id "$main" WM_STATE | grep -o 'Iconic\|Normal' | head -1)
echo "main window after: $state2"
kill -9 "$gui" "$fake" 2>/dev/null

if [ -z "$alert" ]; then
    echo "FAIL: no alert within 20s while minimised (see $fake_log)"
    exit 1
fi
if [ "$state2" != "Iconic" ]; then
    echo "FAIL: the alert appeared but the main window was restored ($state2)"
    exit 1
fi
echo "PASS: alert appeared while the main window stayed minimised"
exit 0
