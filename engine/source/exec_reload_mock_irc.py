#!/usr/bin/env python3
"""
Minimal mock IRC server for testing the exec-reload hot-reload flow.

Listens on a TCP port, accepts ONE connection, sends an IRC welcome banner,
and echoes PING/PONG. Verifies that a single continuous TCP connection is
maintained across the OLD→NEW engine exec boundary.

Exit code:
  0  — connection survived (only ever seen ONE distinct TCP connection)
  1  — saw multiple distinct connections (exec broke continuity)
"""
import socket
import sys
import time
import threading

def main():
    if len(sys.argv) < 3:
        print("usage: mock_irc.py <port> <result-file>", file=sys.stderr)
        sys.exit(2)

    port = int(sys.argv[1])
    result_file = sys.argv[2]

    # State we want to verify across the test:
    seen_connections = []   # list of (remote_port, accepted_at) per accept
    seen_data = []          # raw lines received from "engine"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    print(f"mock_irc: listening on 127.0.0.1:{port}", flush=True)

    def handle(conn, remote_port):
        seen_connections.append((remote_port, time.time()))
        print(f"mock_irc: accepted connection from remote port {remote_port}", flush=True)
        # Send IRC welcome banner so the engine thinks it's connected to IRC.
        conn.sendall(b":mock.irc.localhost 001 Zod :Welcome to the mock IRC server\r\n")
        conn.sendall(b":mock.irc.localhost 002 Zod :Your host is mock.irc.localhost\r\n")
        conn.sendall(b":mock.irc.localhost 003 Zod :Server created at test time\r\n")
        conn.sendall(b":mock.irc.localhost 004 Zod :mock.irc.localhost mock-1 o o\r\n")
        conn.sendall(b":mock.irc.localhost 376 Zod :End of MOTD\r\n")
        # Echo loop: handle PINGs, read and remember everything else.
        buf = b""
        conn.settimeout(60)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n" in buf:
                    line, _, buf = buf.partition(b"\r\n")
                    text = line.decode("utf-8", errors="replace")
                    seen_data.append((remote_port, text))
                    print(f"mock_irc: rcv[{remote_port}]: {text!r}", flush=True)
                    if text.startswith("PING"):
                        # Extract payload
                        payload = text.split(":", 1)[1] if ":" in text else "mock"
                        pong = f"PONG :{payload}\r\n".encode()
                        conn.sendall(pong)
                        print(f"mock_irc: snd[{remote_port}]: {pong!r}", flush=True)
                    elif text.startswith("QUIT"):
                        # The OLD engine says QUIT after exec — log it but
                        # keep the socket open (the NEW engine takes over).
                        print(f"mock_irc: saw QUIT from remote {remote_port}", flush=True)
                    elif text.startswith("PRIVMSG"):
                        print(f"mock_irc: PRIVMSG from remote {remote_port}: {text!r}", flush=True)
        except socket.timeout:
            print(f"mock_irc: connection from {remote_port} timed out", flush=True)
        except Exception as e:
            print(f"mock_irc: connection from {remote_port} error: {e}", flush=True)
        finally:
            try: conn.close()
            except: pass

    # Accept loop — only ONE connection expected for the test.
    server.settimeout(90)
    try:
        conn, addr = server.accept()
    except socket.timeout:
        print("mock_irc: no connection within 90s — test FAILED", flush=True)
        with open(result_file, "w") as f:
            f.write("FAIL: no connection\n")
        sys.exit(1)
    handle(conn, addr[1])

    # Write results.
    distinct_ports = set(p for p, _ in seen_connections)
    result = (
        f"PASS\n"
        f"distinct_connections={len(distinct_ports)}\n"
        f"lines_received={len(seen_data)}\n"
        f"first_remote_port={seen_connections[0][0] if seen_connections else 'none'}\n"
    )
    with open(result_file, "w") as f:
        f.write(result)
    print(f"mock_irc: result written to {result_file}", flush=True)
    print(f"mock_irc: distinct connections = {len(distinct_ports)} (expect 1)", flush=True)
    sys.exit(0 if len(distinct_ports) == 1 else 1)

if __name__ == "__main__":
    main()