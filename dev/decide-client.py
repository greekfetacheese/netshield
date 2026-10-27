#!/usr/bin/env python3
"""Subscribe to a real netshieldd control socket, answer the first prompt, print what it saw.

The handshake is `hello` then `subscribe`: a client that sends only `hello` receives no
prompts at all, and a client that subscribes after the prompt was raised never receives
the prompt either, because the daemon does not replay an already-open prompt on subscribe.
Subscribe first, then create traffic.

No root is needed when the socket is owned by `allowed_uid`; under `dev/netns-run.sh` the
daemon runs as root inside a network namespace and the socket is mode 0660.
"""
import argparse
import json
import socket
import sys
import time


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Answer the first NetShield prompt on a control socket.",
        epilog=(
            "example: dev/decide-client.py --socket target/dev/netns/control.sock "
            "--action allow --duration once"
        ),
    )
    parser.add_argument("--socket", required=True, metavar="PATH",
                        help="the daemon control socket (required)")
    parser.add_argument("--action", choices=("allow", "deny"), default="allow",
                        help="the answer (default allow)")
    parser.add_argument("--duration", choices=("once", "session", "forever"),
                        default="session",
                        help="how long the answer lasts: once (this flow), session "
                             "(until the daemon restarts), forever (persisted); "
                             "default session")
    parser.add_argument("--scope", choices=("any", "domain", "address"), default="any",
                        help="what the answer covers: any connection by the app, only "
                             "the learned domain, or only the remote address (default any)")
    parser.add_argument("--timeout", type=float, default=15.0, metavar="SECS",
                        help="how long to wait for a prompt, in seconds (default 15)")
    return parser.parse_args(argv)


def scope_choice(scope, prompt, conn):
    """Maps --scope onto the wire's ScopeChoice, refusing a scope the prompt cannot offer."""
    if scope == "any":
        return {"kind": "any_connection"}
    if scope == "address":
        return {"kind": "address"}
    domain = conn.get("domain")
    if not domain:
        print("REFUSING: the prompt has no learned domain; use --scope address or any",
              file=sys.stderr)
        return None
    if not prompt.get("domain_scope_available", False):
        print("REFUSING: the prompt disables domain scope; use --scope address or any",
              file=sys.stderr)
        return None
    return {"kind": "domain", "value": {"host": domain, "subdomains": False}}


def main(argv):
    args = parse_args(argv)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect(args.socket)
    except OSError as err:
        print(f"CONNECT FAILED {args.socket}: {err}", file=sys.stderr)
        return 1

    def send(obj):
        sock.sendall((json.dumps(obj) + "\n").encode())

    send({"kind": "hello", "value": {"version": 1, "client": "gui"}})
    send({"kind": "subscribe"})
    print(f"SUBSCRIBED {args.socket}", flush=True)

    deadline = time.time() + args.timeout
    buf = b""
    prompt = None
    while time.time() < deadline and prompt is None:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            print("DAEMON CLOSED THE SOCKET", file=sys.stderr)
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                print(f"UNPARSED: {line[:200]!r}", file=sys.stderr)
                continue
            if msg.get("kind") == "prompt":
                prompt = msg["value"]
                break
            print(f"<- {msg.get('kind')}", flush=True)

    if prompt is None:
        print(f"NO PROMPT within {args.timeout:g}s", file=sys.stderr)
        return 1

    conn = prompt["connection"]
    scope = scope_choice(args.scope, prompt, conn)
    if scope is None:
        return 1

    print(
        f"PROMPT id={prompt['id']} app={conn.get('app_name')} "
        f"domain={conn.get('domain')} dest={conn.get('remote_ip')}:{conn.get('remote_port')}",
        flush=True,
    )
    send({
        "kind": "decide",
        "value": {
            "prompt_id": prompt["id"],
            "action": args.action,
            "duration": args.duration,
            "scope": scope,
        },
    })
    print(
        f"SENT DECIDE prompt_id={prompt['id']} action={args.action} "
        f"duration={args.duration} scope={args.scope}",
        flush=True,
    )

    # Read until the daemon confirms, so the caller can rely on the decision having been
    # applied before it inspects the log.
    confirmation = time.time() + 3
    sock.settimeout(0.5)
    while time.time() < confirmation:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("kind") == "prompt_closed":
                print(f"PROMPT CLOSED {json.dumps(msg.get('value'))}", flush=True)
                return 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
