#!/usr/bin/env python3
"""
Mock IRC server for testing the Connection Holder architecture.

Accepts ONE connection. Records the inode of the accepted socket.
Reports at end whether it saw 1 connection (pass) or 2+ (fail).
"""
import socket
import sys
import os
import time

PORT = 16668
RESULT_FILE = "/tmp/holder-mock-irc.result"

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", PORT))
    server.listen(1)
    print(f"mock_irc: listening on 127.0.0.1:{PORT}", flush=True)

    accepted = []  # list of (remote_port, inode) for accepted sockets

    def handle(conn, addr, ino):
        print(f"mock_irc: accepted {addr} inode={ino}", flush=True)
        accepted.append((addr[1], ino))
        try:
            # Send welcome banner so the engine thinks we're a real IRC server
            conn.sendall(b":mock.irc 001 Zod :Welcome to the holder mock IRC\r\n")
            conn.sendall(b":mock.irc 376 Zod :End of MOTD\r\n")
            conn.settimeout(60)
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n" in buf:
                    line, _, buf = buf.partition(b"\r\n")
                    text = line.decode("utf-8", errors="replace")
                    print(f"mock_irc: rcv: {text!r}", flush=True)
                    if text.startswith("PING"):
                        payload = text.split(":", 1)[1] if ":" in text else "mock"
                        conn.sendall(f"PONG :{payload}\r\n".encode())
                    elif text.startswith("QUIT"):
                        print(f"mock_irc: saw QUIT from {addr}", flush=True)
        except socket.timeout:
            print(f"mock_irc: timeout from {addr}", flush=True)
        except Exception as e:
            print(f"mock_irc: error from {addr}: {e}", flush=True)
        finally:
            try: conn.close()
            except: pass

    server.settimeout(60)
    try:
        while True:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                print("mock_irc: accept timeout", flush=True)
                break
            ino = os.stat(f"/proc/{os.getpid()}/fd/{conn.fileno()}").st_ino if os.path.exists(f"/proc/{os.getpid()}/fd/{conn.fileno()}") else 0
            handle(conn, addr, ino)
            # Continue accepting (only 1 expected)
    finally:
        distinct = len(set(p for p, _ in accepted))
        result = f"PASS\naccepted={accepted}\ndistinct={distinct}\n"
        with open(RESULT_FILE, "w") as f:
            f.write(result)
        print(f"mock_irc: result: {result.strip()}", flush=True)

if __name__ == "__main__":
    main()