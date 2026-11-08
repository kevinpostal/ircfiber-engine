#!/usr/bin/env python3
"""Bounded test client for real holder IPC; never used outside fixture volume."""
import json
import socket
import sys

mode, path, server, body = sys.argv[1:]
body = json.loads(body)
with socket.socket(socket.AF_UNIX) as sock:
    sock.settimeout(40)
    sock.connect(path)
    stream = sock.makefile("rwb", buffering=0)

    def send(verb, payload):
        stream.write((verb + " " + json.dumps(payload, separators=(",", ":")) + "\n").encode())

    def receive():
        line = stream.readline(16 << 20).decode().strip()
        if not line:
            raise RuntimeError("holder closed before reply")
        verb, _, payload = line.partition(" ")
        return verb, json.loads(payload)

    if mode == "dial":
        send("DIAL", body)
        events = []
        while True:
            verb, payload = receive()
            if verb != "EVENT":
                print(json.dumps({"verb": verb, "payload": payload, "events": events}))
                break
            events.append(payload)
    else:
        send("HELLO", {"proto": 1, "serverId": server, "engine": "disposable-fixture"})
        verb, payload = receive()
        assert verb == "OK", (verb, payload)
        if mode == "legacy-meta":
            send("INFO", {"id": body["id"]})
            verb, payload = receive()
            assert verb == "OK", (verb, payload)
            meta = payload["meta"]
            assert isinstance(meta, dict) and meta.get("schemaTag") == "IRCFv1", meta
            meta.pop("activeRoute", None)
            send("META", {"id": body["id"], "meta": meta})
        elif mode == "close":
            send("CLOSE", {"id": body["id"], "quit": "fixture complete"})
        else:
            raise ValueError(mode)
        verb, payload = receive()
        assert verb == "OK", (verb, payload)
        print(json.dumps(payload))
