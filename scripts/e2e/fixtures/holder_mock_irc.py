#!/usr/bin/env python3
"""
Mock IRC server for the engine hot-swap proof (scripts/e2e/hot_swap.sh).

Accepts connections on PORT and records the inode of every accepted socket:
the result file says how many distinct server-side sockets it ever saw. A
hot swap must leave that at 1 — the holder keeps the socket while the engine
is replaced; a reconnect would show a second one.

Behaviour (just enough IRC for the engine to register and for the proof):
  * `CAP LS`           -> `CAP * LS :` (no caps), so registration proceeds
  * NICK + USER seen   -> 001 / 002 / 376 welcome burst
  * `PING :x`          -> `PONG :x`
  * `JOIN #chan`       -> echo JOIN + 353 / 366
  * `NAMES #chan`      -> 353 / 366
  * `QUIT`             -> logged (and visible in LINES_FILE)
  * every received line is appended to LINES_FILE (one per line, CRLF
    stripped) so the shell proof can grep for JOIN / NAMES / QUIT.
  * INJECT_FILE: when it appears, its contents are written verbatim to the
    live connection and the file is removed — the proof uses this to send
    `PING :x` while the engine is down and expect the holder's auto-PONG.

The result file (RESULT_FILE) is rewritten after every accept and on exit:
    PASS|FAIL
    accepted=[(remote_port, inode), ...]
    distinct=<number of distinct accepted sockets>
"""
import os
import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 16668
RESULT_FILE = sys.argv[2] if len(sys.argv) > 2 else "/tmp/holder-mock-irc.result"
LINES_FILE = os.environ.get("MOCK_IRC_LINES", "/tmp/mock-irc.lines")
INJECT_FILE = os.environ.get("MOCK_IRC_INJECT", "/tmp/mock-irc.inject")
SERVER = "mock.irc"

accepted = []  # (remote_port, inode)
lock = threading.Lock()


def write_result():
    distinct = len(set(accepted))
    verdict = "PASS" if distinct <= 1 else "FAIL"
    text = f"{verdict}\naccepted={accepted}\ndistinct={distinct}\n"
    tmp = RESULT_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, RESULT_FILE)
    return text


def record_line(text):
    with lock:
        with open(LINES_FILE, "a") as f:
            f.write(text + "\n")


def send(conn, line):
    print(f"mock_irc: snd: {line!r}", flush=True)
    conn.sendall((line + "\r\n").encode())


def welcome(conn, nick):
    send(conn, f":{SERVER} 001 {nick} :Welcome to the holder mock IRC {nick}!u@mock")
    send(conn, f":{SERVER} 002 {nick} :Your host is {SERVER}, running version mock-1")
    send(conn, f":{SERVER} 376 {nick} :End of MOTD")


def names(conn, nick, chan):
    send(conn, f":{SERVER} 353 {nick} = {chan} :@{nick}")
    send(conn, f":{SERVER} 366 {nick} {chan} :End of /NAMES list")


def inject_loop(conn, stop):
    """Write INJECT_FILE's contents to the connection whenever it appears."""
    while not stop.is_set():
        if os.path.exists(INJECT_FILE):
            try:
                with open(INJECT_FILE, "rb") as f:
                    data = f.read()
                os.remove(INJECT_FILE)
                if data:
                    print(f"mock_irc: inject: {data!r}", flush=True)
                    conn.sendall(data)
            except OSError as e:
                print(f"mock_irc: inject error: {e}", flush=True)
        time.sleep(0.2)


def handle(conn, addr, ino):
    print(f"mock_irc: accepted {addr} inode={ino}", flush=True)
    accepted.append((addr[1], ino))
    print(f"mock_irc: result: {write_result().strip()}", flush=True)
    stop = threading.Event()
    threading.Thread(target=inject_loop, args=(conn, stop), daemon=True).start()
    nick = None
    user_seen = False
    welcomed = False
    buf = b""
    try:
        conn.settimeout(None)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                text = line.rstrip(b"\r").decode("utf-8", errors="replace")
                print(f"mock_irc: rcv: {text!r}", flush=True)
                record_line(text)
                parts = text.split(" ")
                cmd = parts[0].upper() if parts else ""
                if cmd == "CAP" and len(parts) > 1 and parts[1].upper() == "LS":
                    send(conn, "CAP * LS :")
                elif cmd == "NICK" and len(parts) > 1:
                    nick = parts[1].lstrip(":")
                elif cmd == "USER":
                    user_seen = True
                elif cmd == "PING":
                    payload = text.split(":", 1)[1] if ":" in text else (parts[1] if len(parts) > 1 else "mock")
                    send(conn, f"PONG :{payload}")
                elif cmd == "JOIN" and len(parts) > 1 and nick:
                    for chan in parts[1].split(","):
                        send(conn, f":{nick}!u@mock JOIN {chan}")
                        names(conn, nick, chan)
                elif cmd == "NAMES" and len(parts) > 1 and nick:
                    for chan in parts[1].split(","):
                        names(conn, nick, chan)
                elif cmd == "QUIT":
                    print(f"mock_irc: saw QUIT from {addr}", flush=True)
                if not welcomed and nick and user_seen:
                    welcomed = True
                    welcome(conn, nick)
    except (socket.timeout, OSError) as e:
        print(f"mock_irc: connection {addr} ended: {e}", flush=True)
    finally:
        stop.set()
        try:
            conn.close()
        except OSError:
            pass
        print(f"mock_irc: closed {addr}", flush=True)


def main():
    for path in (LINES_FILE, INJECT_FILE):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(4)
    print(f"mock_irc: listening on 0.0.0.0:{PORT}", flush=True)
    write_result()
    try:
        while True:
            conn, addr = server.accept()
            fd_path = f"/proc/{os.getpid()}/fd/{conn.fileno()}"
            ino = os.stat(fd_path).st_ino if os.path.exists(fd_path) else 0
            threading.Thread(target=handle, args=(conn, addr, ino), daemon=True).start()
    finally:
        print(f"mock_irc: result: {write_result().strip()}", flush=True)


if __name__ == "__main__":
    main()
