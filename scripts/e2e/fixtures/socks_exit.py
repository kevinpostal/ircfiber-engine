#!/usr/bin/env python3
"""Test-only RFC 1928/1929 exit. SIGUSR1 kills live tunnels and rejects CONNECT.
SIGUSR2 toggles blackhole mode: live tunnels stay open and keep reading both
directions, but forwarded bytes are dropped (a silently dead path)."""
import http.server
import json
import os
import ssl
import time
import select
import signal
import socket
import socketserver
import threading

TARGETS = {"alpha.example.org", "beta.example.net"}
active = set()
lock = threading.Lock()
failed = threading.Event()
blackhole = threading.Event()
capacity_fixture = os.environ.get("NORD_CAPACITY_FIXTURE") == "1"
mullvad_fixture = capacity_fixture and os.environ.get("NORD_CAPACITY_MULLVAD") == "1"
https_gate = threading.Event()
https_gate.set()
auth_gate = threading.Event()
auth_gate.set()
measurement = {"current": 0, "peak": 0, "started": 0, "closed": 0, "events": []}
sessions = set()
reject_auth = threading.Event()
bad_tls = threading.Event()


def measure(event, client):
    """Count one client from authentication negotiation through physical close."""
    with lock:
        if event == "begin":
            sessions.add(client)
            measurement["current"] += 1
            measurement["started"] += 1
            measurement["peak"] = max(measurement["peak"], measurement["current"])
        else:
            sessions.discard(client)
            measurement["current"] -= 1
            measurement["closed"] += 1
        if len(measurement["events"]) >= 10000:
            raise RuntimeError("fixture measurement bound exceeded")
        measurement["events"].append({"event": event, "at": time.monotonic(),
                                      "current": measurement["current"]})


class Metrics(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        with lock:
            body = json.dumps(measurement).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/block":
            https_gate.clear()
        elif self.path == "/unblock":
            https_gate.set()
            auth_gate.set()
        elif self.path == "/fail-auth":
            reject_auth.set()
        elif self.path == "/allow-auth":
            reject_auth.clear()
        elif self.path == "/bad-tls":
            bad_tls.set()
        elif self.path == "/allow-tls":
            bad_tls.clear()
        elif self.path == "/stall-auth":
            auth_gate.clear()
        elif self.path == "/close":
            with lock:
                clients = tuple(sessions)
            for client in clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):
        pass


def https_reply(client):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/fixture-certs/nord-server.crt", "/fixture-certs/nord-server.key")
    with context.wrap_socket(client, server_side=True) as tls:
        request = bytearray()
        while b"\r\n\r\n" not in request:
            chunk = tls.recv(4096)
            if not chunk or len(request) > 32768:
                return
            request.extend(chunk)
        deadline = time.monotonic() + 30
        while not https_gate.wait(.05):
            if time.monotonic() >= deadline:
                return
            if select.select((tls,), (), (), 0)[0] and not tls.recv(1):
                return
        if b"/image" in request.split(b"\r\n", 1)[0]:
            body = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082")
            content_type = b"image/png"
        else:
            body = b'{"ip":"198.51.100.7","org":"AS64512 Fixture","country":"ZZ","city":"Local","mullvad_exit_ip":true}'
            content_type = b"application/json"
        tls.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: " + content_type +
                    b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


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
        measured = False
        try:
            client.settimeout(10)
            ver, count = recv_exact(client, 2)
            methods = recv_exact(client, count)
            method = 2 if 2 in methods else 0 if mullvad_fixture and 0 in methods else 255
            if ver != 5 or method == 255:
                client.sendall(b"\x05\xff")
                return
            if capacity_fixture:
                measure("begin", client)
                measured = True
            client.sendall(bytes((5, method)))
            if method == 2:
                ver, user_len = recv_exact(client, 2)
                username = recv_exact(client, user_len)
                password = recv_exact(client, recv_exact(client, 1)[0])
                deadline = time.monotonic() + 30
                while not auth_gate.wait(.05):
                    if time.monotonic() >= deadline:
                        return
                    if select.select((client,), (), (), 0)[0] and not client.recv(1, socket.MSG_PEEK):
                        return
                auth_ok = not reject_auth.is_set() and ver == 1 and username in (b"test", b"second") and password == b"test"
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
            https = capacity_fixture and port == 443 and host in {
                "am.i.mullvad.net", "ipinfo.io", "image.regression.test", "93.184.216.34"}
            irc = host in TARGETS and port in ((16668, 16669) if capacity_fixture else (16668,))
            if ver != 5 or cmd != 1 or reserved != 0 or not (https or irc):
                client.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if failed.is_set():
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if capacity_fixture and port == 16669 and bad_tls.is_set():
                client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00not a TLS record\r\n")
                return
            if https:
                client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                https_reply(client)
                return
            upstream = socket.create_connection(("mock-irc", port), 10)
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
                    if blackhole.is_set():
                        continue
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
            client.close()
            if measured:
                measure("close", client)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def toggle_blackhole(_signal, _frame):
    if blackhole.is_set():
        blackhole.clear()
    else:
        blackhole.set()
    print(f"SIGUSR2 blackhole {'on' if blackhole.is_set() else 'off'}", flush=True)


if __name__ == "__main__":
    signal.signal(signal.SIGUSR1, drop_tunnels)
    signal.signal(signal.SIGUSR2, toggle_blackhole)
    if capacity_fixture:
        metrics = http.server.ThreadingHTTPServer(("0.0.0.0", 1081), Metrics)
        threading.Thread(target=metrics.serve_forever, daemon=True).start()
    with Server(("0.0.0.0", 1080), Handler) as server:
        print("SOCKS exit listening on 1080", flush=True)
        server.serve_forever()
