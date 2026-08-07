#!/usr/bin/env python3
"""
Mock TLS IRC server for testing the Connection Holder TLS path.
Self-signed cert, single connection.
"""
import socket, ssl, sys, os, time

PORT = 16669
RESULT_FILE = "/tmp/holder-mock-irc-tls.result"
CERT = "/tmp/holder-mock-cert.pem"
KEY = "/tmp/holder-mock-key.pem"

def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    os.system(f"openssl req -x509 -newkey rsa:2048 -keyout {KEY} -out {CERT} "
              f"-days 365 -nodes -subj '/CN=mock.irc' 2>/dev/null")

def main():
    ensure_cert()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", PORT))
    server.listen(1)
    print(f"mock_irc_tls: listening TLS on 127.0.0.1:{PORT}", flush=True)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)

    server.settimeout(30)
    accepted = []
    try:
        while True:
            try:
                raw, addr = server.accept()
            except socket.timeout:
                break
            try:
                conn = ctx.wrap_socket(raw, server_side=True)
                print(f"mock_irc_tls: TLS accepted from {addr}", flush=True)
                accepted.append(addr[1])
                try:
                    conn.sendall(b":mock.irc 001 Zod :Welcome to holder mock TLS\r\n")
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
                            print(f"mock_irc_tls: rcv: {line!r}", flush=True)
                            if line.startswith(b"QUIT"):
                                print(f"mock_irc_tls: saw QUIT from {addr}", flush=True)
                except socket.timeout:
                    print(f"mock_irc_tls: timeout from {addr}", flush=True)
                finally:
                    try: conn.close()
                    except: pass
            except Exception as e:
                print(f"mock_irc_tls: TLS error: {e}", flush=True)
    finally:
        result = f"tls_distinct={len(set(accepted))}\n"
        with open(RESULT_FILE, "w") as f:
            f.write(result)
        print(f"mock_irc_tls: result: {result.strip()}", flush=True)

if __name__ == "__main__":
    main()