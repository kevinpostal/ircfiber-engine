#!/usr/bin/env python3
"""Disposable namespace endpoints; counters come exclusively from socket I/O."""
import ipaddress
import json
import os
import select
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PREFIX = "2001:db8:1234:5678::/64"
SERVER6 = "2001:db8:20::10"
SERVER4 = "203.0.113.10"
NATIVE6 = "2001:db8:20::20"
HOSTS = {"dual.routed.test", "aonly.routed.test", "default.routed.test"}
lock = threading.RLock()
state = {"accepts": [], "connects": [], "diagnostics": [], "nativeMode": "healthy",
         "sni": [], "moveWitness": None, "maxRegistered": {}, "nativeDelaySeconds": 8}
active = {}


def exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise ConnectionError("short socket read")
        data += part
    return data

def move_proof():
    """Read the real coordinator's proof at the instant an upstream accepts."""
    with lock:
        witness = state["moveWitness"]
    if not witness:
        return None
    key = "irc:routing:move-status:" + witness["moveId"]
    args = ["HMGET", key, "sourceClosed", "ackServerId", "state"]
    wire = ("*%d\r\n" % len(args)).encode()
    for arg in args:
        data = arg.encode()
        wire += ("$%d\r\n" % len(data)).encode() + data + b"\r\n"
    try:
        with socket.create_connection(("203.0.113.2", 6379), timeout=2) as redis:
            redis.sendall(wire)
            stream = redis.makefile("rb")
            assert stream.readline() == b"*3\r\n"
            values = []
            for _ in range(3):
                line = stream.readline()
                assert line.startswith(b"$")
                size = int(line[1:])
                values.append(None if size < 0 else stream.read(size + 2)[:-2].decode())
        return dict(witness, sourceClosed=values[0] == "1",
                    ackServerId=values[1], state=values[2])
    except (OSError, ValueError, AssertionError) as error:
        return dict(witness, error=str(error))



def command(*args):
    subprocess.run(args, check=True)


def certificates():
    if not os.path.exists("/certs/ca.pem"):
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=dual.routed.test", "-addext",
                "subjectAltName=DNS:dual.routed.test,DNS:aonly.routed.test,DNS:default.routed.test",
                "-keyout", "/certs/key.pem", "-out", "/certs/ca.pem")
    shutil.copyfile("/certs/ca.pem", "/certs/ca-certificates.crt")


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCP6(TCP):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()


def send(sock, text):
    sock.sendall((text + "\r\n").encode())


class IRC(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        peer = self.client_address[0]
        proof = move_proof()
        with lock:
            index = len(state["accepts"])
            rec = {"id": index, "peer": peer, "port": self.server.server_address[1],
                   "registered": False, "pongs": 0, "open": True, "clientPings": [],
                   "acceptedAt": time.monotonic(), "moveProof": proof}
            state["accepts"].append(rec)
            mode = state["nativeMode"]
        try:
            if self.server.server_address[1] == 16669:
                if ":" in peer and mode != "healthy":
                    if mode == "hold-close":
                        time.sleep(state["nativeDelaySeconds"])
                    return
                sock.settimeout(12)
                sock = self.server.tls.wrap_socket(sock, server_side=True)
            with lock:
                active[index] = sock
            sock.settimeout(1)
            nick = None
            user = False
            buf = b""
            last_ping = 0
            while True:
                if rec["registered"] and time.monotonic() - last_ping > 2:
                    send(sock, "PING :fixture-%d" % index)
                    last_ping = time.monotonic()
                try:
                    chunk = sock.recv(16384)
                except socket.timeout:
                    continue
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, _, buf = buf.partition(b"\n")
                    text = line.rstrip(b"\r").decode(errors="replace")
                    words = text.split()
                    if not words:
                        continue
                    cmd = words[0].upper()
                    if cmd == "CAP" and "LS" in words:
                        send(sock, "CAP * LS :")
                    elif cmd == "NICK":
                        nick = words[1].lstrip(":")
                    elif cmd == "USER":
                        user = True
                    elif cmd == "PING":
                        with lock:
                            rec["clientPings"].append(text)
                        send(sock, "PONG :" + text.split(":", 1)[-1])
                    elif cmd == "PONG":
                        with lock:
                            rec["pongs"] += 1
                    elif cmd == "QUIT":
                        return
                    elif cmd == "JOIN" and nick:
                        for channel in words[1].split(","):
                            send(sock, f":{nick}!u@fixture JOIN {channel}")
                            send(sock, f":fixture 353 {nick} = {channel} :{nick}")
                            send(sock, f":fixture 366 {nick} {channel} :End of NAMES")
                    if nick and user and not rec["registered"]:
                        send(sock, f":fixture 001 {nick} :Welcome")
                        send(sock, f":fixture 376 {nick} :End of MOTD")
                        with lock:
                            rec["registered"] = True
                            rec["nick"] = nick
                            rec["registeredAt"] = time.monotonic()
                            count = sum(row["open"] and row["registered"]
                                        and row.get("nick") == nick for row in state["accepts"])
                            state["maxRegistered"][nick] = max(
                                state["maxRegistered"].get(nick, 0), count)
        except (OSError, ValueError):
            pass
        finally:
            with lock:
                rec["open"] = False
                rec["closedAt"] = time.monotonic()
                active.pop(index, None)
            sock.close()


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        try:
            offset = 12
            labels = []
            while packet[offset]:
                size = packet[offset]
                offset += 1
                labels.append(packet[offset:offset + size].decode("ascii"))
                offset += size
            offset += 1
            qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
            end = offset + 4
            host = ".".join(labels).lower()
            address = None
            if host in HOSTS and qclass == 1:
                if qtype == 1:
                    address = socket.inet_pton(socket.AF_INET, SERVER4)
                elif qtype == 28 and host != "aonly.routed.test":
                    address = socket.inet_pton(socket.AF_INET6, SERVER6)
            answer = b""
            if address:
                answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 1, len(address)) + address
            response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0)
            sock.sendto(response + packet[12:end] + answer, self.client_address)
        except (IndexError, UnicodeError, struct.error):
            return


class SOCKS(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        upstream = None
        try:
            client.settimeout(10)
            version, count = exact(client, 2)
            methods = exact(client, count)
            if version != 5:
                return
            method = 2 if 2 in methods else 0 if 0 in methods else 255
            client.sendall(bytes([5, method]))
            if method == 255:
                return
            if method == 2:
                version, length = exact(client, 2)
                user = exact(client, length)
                password = exact(client, exact(client, 1)[0])
                if version != 1 or user != b"test" or password != b"test":
                    client.sendall(b"\x01\x01")
                    return
                client.sendall(b"\x01\x00")
            version, cmd, reserved, atyp = exact(client, 4)
            if atyp == 3:
                host = exact(client, exact(client, 1)[0]).decode("ascii").lower()
            elif atyp in (1, 4):
                host = socket.inet_ntop(socket.AF_INET if atyp == 1 else socket.AF_INET6,
                                        exact(client, 4 if atyp == 1 else 16))
            else:
                return
            port = int.from_bytes(exact(client, 2), "big")
            # Include rejected IRC CONNECT attempts. Provider IP-info/transport
            # diagnostics are separately observable, never mistaken for IRC.
            with lock:
                key = "connects" if host in HOSTS else "diagnostics"
                state[key].append({"provider": os.environ["PROVIDER"], "host": host, "port": port})
            if version != 5 or cmd != 1 or reserved or host not in HOSTS or port not in (16668, 16669):
                client.sendall(b"\x05\x02\x00\x01" + bytes(6))
                return
            upstream = socket.create_connection((SERVER4, port), 10)
            client.sendall(b"\x05\x00\x00\x01" + bytes(6))
            client.settimeout(None)
            upstream.settimeout(None)
            while True:
                readable, _, _ = select.select((client, upstream), (), (), 20)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            if upstream:
                upstream.close()


class Control(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        with lock:
            data = json.dumps(state).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        with lock:
            if "nativeMode" in body:
                assert body["nativeMode"] in ("healthy", "close", "hold-close")
                state["nativeMode"] = body["nativeMode"]
            if "moveWitness" in body:
                witness = body["moveWitness"]
                assert witness is None or (isinstance(witness["moveId"], str)
                                           and isinstance(witness["fromServerId"], str))
                state["moveWitness"] = witness
            if "nativeDelaySeconds" in body:
                assert 1 <= body["nativeDelaySeconds"] <= 30
                state["nativeDelaySeconds"] = body["nativeDelaySeconds"]
            if "drop" in body:
                for index, sock in list(active.items()):
                    rec = state["accepts"][index]
                    if body["drop"] == "all" or rec["peer"] == body["drop"]:
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
        self.do_GET()


def main():
    mode = sys.argv[1]
    if mode == "namespace":
        assert os.environ.get("ROUTED_FIXTURE") == "1"
        # IPv6 exists solely on this container's eth0/lo, never Docker's
        # host bridge. The bridge carries layer-2 frames only.
        command("ip", "-6", "addr", "replace", NATIVE6 + "/64", "dev", "eth0", "nodad")
        command("ip", "-6", "route", "replace", "local", PREFIX, "dev", "lo")
        open("/tmp/namespace-ready", "w").close()
        while True:
            time.sleep(3600)
    elif mode == "server":
        assert os.environ.get("ROUTED_FIXTURE") == "1"
        command("ip", "-6", "addr", "replace", SERVER6 + "/64", "dev", "eth0", "nodad")
        command("ip", "-6", "route", "replace", PREFIX, "via", NATIVE6)
        certificates()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain("/certs/ca.pem", "/certs/key.pem")
        def sni(_sock, name, _context):
            with lock:
                state["sni"].append(name)
        tls.set_servername_callback(sni)
        for family in (TCP, TCP6):
            for port in (16668, 16669):
                server = family(("0.0.0.0" if family is TCP else "::", port), IRC)
                server.tls = tls
                serve(server)
        serve(socketserver.ThreadingUDPServer(("0.0.0.0", 53), DNS))
    elif mode == "socks":
        assert os.environ["PROVIDER"] in ("mullvad", "nordvpn")
        serve(TCP(("0.0.0.0", 1080), SOCKS))
    elif mode == "proof":
        # Performed before enabling the engine's routing-verification flag.
        context = ssl.create_default_context(cafile="/certs/ca.pem")
        for iid in ("a516:4466:5544:123", "a516:4466:5544:124"):
            source = "2001:db8:1234:5678:" + iid
            sock = socket.socket(socket.AF_INET6)
            sock.settimeout(10)
            sock.bind((source, 0))
            sock.connect((SERVER6, 16669))
            with context.wrap_socket(sock, server_hostname="dual.routed.test") as tls:
                assert ipaddress.ip_address(tls.getsockname()[0]) == ipaddress.ip_address(source)
        return
    else:
        raise ValueError(mode)
    ThreadingHTTPServer(("0.0.0.0", 8080), Control).serve_forever()


if __name__ == "__main__":
    main()
