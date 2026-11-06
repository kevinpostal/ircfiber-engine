#!/usr/bin/env python3
"""Test-only RFC 1928/1929 exit. SIGUSR1 kills live tunnels and rejects CONNECT."""
import select
import signal
import socket
import socketserver
import threading

TARGETS = {"alpha.example.org", "beta.example.net"}
active = set()
lock = threading.Lock()
failed = threading.Event()


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("peer closed during SOCKS handshake")
        data.extend(chunk)
    return bytes(data)


def drop_tunnels(_signal, _frame):
    failed.set()
    with lock:
        sockets = tuple(active)
    for sock in sockets:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
    print(f"SIGUSR1 dropped {len(sockets)} sockets; refusing future CONNECT", flush=True)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        upstream = None
        try:
            client.settimeout(10)
            ver, count = recv_exact(client, 2)
            methods = recv_exact(client, count)
            if ver != 5 or 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            ver, user_len = recv_exact(client, 2)
            username = recv_exact(client, user_len)
            password = recv_exact(client, recv_exact(client, 1)[0])
            auth_ok = ver == 1 and username == b"test" and password == b"test"
            client.sendall(b"\x01\x00" if auth_ok else b"\x01\x01")
            if not auth_ok:
                return
            ver, cmd, reserved, atyp = recv_exact(client, 4)
            if atyp == 3:
                host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii", "replace").lower()
            elif atyp == 1:
                host = socket.inet_ntop(socket.AF_INET, recv_exact(client, 4))
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                return
            port = int.from_bytes(recv_exact(client, 2), "big")
            if ver != 5 or cmd != 1 or reserved != 0 or host not in TARGETS or port != 16668:
                client.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if failed.is_set():
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            upstream = socket.create_connection(("mock-irc", 16668), 10)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            print(f"CONNECT {host}:{port}", flush=True)
            with lock:
                active.update((client, upstream))
            client.settimeout(None)
            upstream.settimeout(None)
            while not failed.is_set():
                readable, _, _ = select.select((client, upstream), (), (), 1)
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    (upstream if source is client else client).sendall(chunk)
        except (OSError, ValueError, ConnectionError):
            pass
        finally:
            with lock:
                active.discard(client)
                if upstream is not None:
                    active.discard(upstream)
            if upstream is not None:
                upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    signal.signal(signal.SIGUSR1, drop_tunnels)
    with Server(("0.0.0.0", 1080), Handler) as server:
        print("SOCKS exit listening on 1080", flush=True)
        server.serve_forever()
