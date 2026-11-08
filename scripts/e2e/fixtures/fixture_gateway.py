#!/usr/bin/env python3
"""Run a fixture command behind an ownership-checked loopback gateway relay."""
from contextlib import contextmanager
import json
import os
import select
import socket
import socketserver
import subprocess
import sys
import threading


@contextmanager
def gateway_access(context, project, compose, service, address, port, external=False):
    docker = ["docker", "--context", context]

    def verify_target():
        container = subprocess.check_output(
            [*docker, "compose", "--project-name", project, "-f", compose, "ps", "-q", service],
            text=True).strip()
        if not container or "\n" in container:
            raise RuntimeError("fixture gateway is not running")
        template = '{"labels":{{json .Config.Labels}},"networks":{{json .NetworkSettings.Networks}}}'
        target = json.loads(subprocess.check_output(
            [*docker, "inspect", "--format", template, container], text=True))
        if (target["labels"].get("ircfiber.fixture.run") != project
                or not any(net.get("IPAddress") == address for net in target["networks"].values())):
            raise RuntimeError("refusing an unowned gateway relay target")

    if external:
        verify_target()
        yield
        return
    if not sys.platform.startswith("linux"):
        raise RuntimeError("VM context requires the printed operator-owned private SSH forward")

    class Relay(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = False

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            sockets = {self.request}
            with relay.lock:
                relay.connections.update(sockets)
            try:
                verify_target()
                with socket.create_connection((address, 8090), timeout=3) as upstream:
                    sockets.add(upstream)
                    with relay.lock:
                        relay.connections.add(upstream)
                    upstream.settimeout(3)
                    self.request.settimeout(3)
                    while not relay.stopping.is_set():
                        ready, _, _ = select.select((self.request, upstream), (), (), 1)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.request else self.request).sendall(data)
            except (OSError, subprocess.CalledProcessError, RuntimeError):
                return
            finally:
                with relay.lock:
                    relay.connections.difference_update(sockets)

    relay = Relay(("127.0.0.1", port), Handler)
    relay.stopping = threading.Event()
    relay.lock = threading.Lock()
    relay.connections = set()
    thread = threading.Thread(target=relay.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        relay.stopping.set()
        relay.shutdown()
        with relay.lock:
            for stream in relay.connections:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                stream.close()
        relay.server_close()
        thread.join()


def main():
    if len(sys.argv) < 9 or sys.argv[7] != "--":
        raise ValueError("usage: fixture_gateway.py CONTEXT PROJECT COMPOSE SERVICE ADDRESS PORT -- COMMAND...")
    context, project, compose, service, address, port = sys.argv[1:7]
    with gateway_access(context, project, compose, service, address, int(port),
                        os.environ.get("ROUTING_REGRESSION_EXTERNAL_FORWARD") == "1"):
        return subprocess.run(sys.argv[8:]).returncode


if __name__ == "__main__":
    sys.exit(main())
