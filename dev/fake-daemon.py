#!/usr/bin/env python3
"""A fake NetShield daemon: speaks the control protocol, sends prompts, and records every
frame the GUI sends back.  Nothing is filtered, no privileges are needed, and no firewall
table is touched.

Purpose: exercise the GUI's alert path without root.  The log is the assertion: every frame
received is printed as ``-> ...`` and every frame sent as ``<- ...``, flushed immediately.

The GUI opens one connection for events (hello + subscribe) and another for answers
(``Decider``).  Both are accepted here; prompts are broadcast to every subscriber and a
decision is accepted on any connection.
"""
import argparse
import json
import os
import socket
import sys
import threading
import time

PROMPT_ID = 7
SECOND_ID = 8


def log(line):
    print(line, flush=True)


class State:
    """Everything shared between the accept loop and the per-connection readers."""

    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.subscribers = []
        self.decides = []
        self.clients = 0
        self.first_prompt_sent = False
        self.first_prompt_at = None
        self.second_scheduled = False
        self.stop = threading.Event()
        self.started = time.monotonic()

    def deadline_passed(self):
        return time.monotonic() - self.started >= self.args.duration


def encode(obj):
    return (json.dumps(obj) + "\n").encode()


def send(state, conn, obj, label):
    """Sends one frame and prints it.  A dead client is dropped, never fatal."""
    data = encode(obj)
    try:
        with state.send_lock:
            conn.sendall(data)
    except OSError as err:
        log(f"<- FAILED {label} ({err})")
        return False
    log(f"<- {label} {json.dumps(obj['value'])}")
    return True


def broadcast(state, obj, label):
    with state.lock:
        targets = list(state.subscribers)
    for conn in targets:
        if not send(state, conn, obj, label):
            with state.lock:
                if conn in state.subscribers:
                    state.subscribers.remove(conn)


def connection_view(state):
    args = state.args
    if args.app == "unknown":
        # The unattributed shape: no exe, no pid, no uid and no name.  This is the alert
        # layout with the address-only scope, which is what `--app unknown` is for.
        return {
            "app_name": "unknown",
            "exe": None,
            "pid": None,
            "uid": None,
            "family": "v4",
            "proto": {"kind": "tcp"},
            "remote_ip": "93.184.216.34",
            "remote_port": 443,
            "local_port": 51000,
            "domain": None,
            "domain_candidates": [],
        }
    domain = args.domain or None
    return {
        "app_name": args.app,
        "exe": f"/usr/bin/{args.app}",
        "pid": 1234,
        "uid": 1000,
        "family": "v4",
        "proto": {"kind": "tcp"},
        "remote_ip": "93.184.216.34",
        "remote_port": 443,
        "local_port": 51000,
        "domain": domain,
        "domain_candidates": [domain] if domain else [],
    }


def prompt_frame(state, prompt_id, second=False):
    view = connection_view(state)
    frame = {
        "kind": "prompt",
        "value": {
            "id": prompt_id,
            "connection": view,
            "timeout_secs": state.args.timeout,
            "domain_scope_available": view["domain"] is not None,
            "pending": 0 if second else 2,
        },
    }
    if second and view["domain"]:
        view["domain"] = "second." + view["domain"]
        view["domain_candidates"] = [view["domain"]]
    return frame


def send_first_prompt(state):
    with state.lock:
        if state.first_prompt_sent or not state.subscribers:
            return
        state.first_prompt_sent = True
        state.first_prompt_at = time.monotonic()
    time.sleep(state.args.prompt_delay)
    with state.lock:
        if not state.subscribers:
            return
    frame = prompt_frame(state, PROMPT_ID)
    broadcast(state, frame, f"PROMPT id={PROMPT_ID} (timeout {state.args.timeout}s)")


def send_second_prompt(state):
    frame = prompt_frame(state, SECOND_ID, second=True)
    broadcast(
        state,
        frame,
        f"PROMPT id={SECOND_ID} (second, {state.args.second_after:g}s after first decision)",
    )


def schedule_second(state):
    """Starts the hide -> show cycle after the first decision; no-op when disabled."""
    args = state.args
    if args.second_after is None or state.second_scheduled:
        return
    with state.lock:
        if state.second_scheduled:
            return
        state.second_scheduled = True

    def later():
        time.sleep(args.second_after)
        if not state.stop.is_set():
            send_second_prompt(state)

    threading.Thread(target=later, daemon=True, name="second-prompt").start()


def handle_frame(state, conn, msg):
    kind = msg.get("kind")
    if kind == "hello":
        log(f"-> hello {json.dumps(msg.get('value'))}")
        send(
            state,
            conn,
            {
                "kind": "hello",
                "value": {
                    "version": 2,
                    "daemon_pid": 999,
                    "mode": "alert",
                    "rule_count": 3,
                },
            },
            "hello",
        )
    elif kind == "subscribe":
        log("-> subscribe")
        with state.lock:
            if conn not in state.subscribers:
                state.subscribers.append(conn)
        if not state.first_prompt_sent:
            threading.Thread(
                target=send_first_prompt, args=(state,), daemon=True, name="first-prompt"
            ).start()
    elif kind == "decide":
        value = msg.get("value") or {}
        with state.lock:
            state.decides.append(value)
            first = len(state.decides) == 1
        log(f"-> DECIDE {json.dumps(value)}")
        # The real daemon answers a decision with prompt_closed; the GUI needs it to hide
        # the alert, so the fake must send it too.
        send(
            state,
            conn,
            {
                "kind": "prompt_closed",
                "value": {
                    "id": value.get("prompt_id"),
                    "resolution": "allowed"
                    if value.get("action") == "allow"
                    else "denied",
                },
            },
            f"PROMPT_CLOSED id={value.get('prompt_id')}",
        )
        if first:
            schedule_second(state)
    else:
        log(f"-> {kind} {json.dumps(msg.get('value'))}")


def serve(state, conn):
    """Reads one client until it closes or the fake daemon stops."""
    buf = b""
    conn.settimeout(0.5)
    try:
        while not state.stop.is_set():
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                log("client closed")
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    log(f"UNPARSED: {line[:200]!r}")
                    continue
                try:
                    handle_frame(state, conn, msg)
                except (KeyError, TypeError) as err:
                    log(f"BAD FRAME {line[:200]!r}: {err}")
    finally:
        with state.lock:
            if conn in state.subscribers:
                state.subscribers.remove(conn)
        try:
            conn.close()
        except OSError:
            pass


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Pretend to be netshieldd over a unix socket: no root, no nftables, no "
            "filtering.  Every frame received is printed as '-> ...' and every frame "
            "sent as '<- ...'."
        ),
        epilog=(
            "example: dev/fake-daemon.py --socket target/dev/fake.sock --app curl "
            "--domain example.com --prompt-delay 3 --second-after 6"
        ),
    )
    parser.add_argument("--socket", required=True, metavar="PATH",
                        help="unix socket to listen on (required)")
    parser.add_argument("--duration", type=float, default=60.0, metavar="SECS",
                        help="how long to keep listening, in seconds (default 60)")
    parser.add_argument("--prompt-delay", type=float, default=0.3, metavar="SECS",
                        help="delay after the first subscribe before the first prompt "
                             "(default 0.3)")
    parser.add_argument("--timeout", type=int, default=180, metavar="SECS",
                        help="timeout_secs advertised in each prompt (default 180); the "
                             "protocol field is an integer")
    parser.add_argument("--app", default="curl", metavar="NAME",
                        help="app_name and /usr/bin/<name> executable (default curl); "
                             "'unknown' produces the unattributed shape")
    parser.add_argument("--domain", default="example.com", metavar="NAME",
                        help="learned domain shown by the alert (default example.com); "
                             "an empty string means no name")
    parser.add_argument("--second-after", type=float, default=None, metavar="SECS",
                        help="send a second prompt SECS after the first decision, to "
                             "prove the hide->show cycle (default off)")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.duration <= 0:
        print("fake-daemon: --duration must be positive", file=sys.stderr)
        return 2
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    state = State(args)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(args.socket)
    srv.listen(8)
    os.chmod(args.socket, 0o666)
    srv.settimeout(0.5)
    log(f"fake daemon listening on {args.socket}")

    try:
        while not state.deadline_passed():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with state.lock:
                state.clients += 1
            threading.Thread(
                target=serve, args=(state, conn), daemon=True, name="client"
            ).start()
    except KeyboardInterrupt:
        log("interrupted")
    finally:
        state.stop.set()
        srv.close()
        try:
            os.unlink(args.socket)
        except OSError:
            pass

    if state.clients == 0:
        log("NO CLIENT CONNECTED")
        return 1
    log(
        f"=== {len(state.decides)} decide frame(s) received in "
        f"{args.duration:g}s ==="
    )
    for decide in state.decides:
        log(f"    {json.dumps(decide)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
