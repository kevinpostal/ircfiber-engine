#!/usr/bin/env python3
"""Real HTTP -> Mongo/Redis -> two engines/holders -> TLS/SOCKS socket proof.

No mocks of routing, ownership, allocation, probes or holder traffic. Compose is
private to one shell-guarded invocation. Step 5 enables ROUTED_REQUIRE_MOVES=1;
without it the native-capable node intentionally has the higher priority.
"""
import copy
from http.client import HTTPException
import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from fixture_gateway import gateway_access as fixture_gateway_access
from fixture_http import LoopbackFixtureCookies

PROJECT = os.environ["ROUTED_RUN"]
DOCKER = ["docker", "--context", os.environ["ROUTED_DOCKER_CONTEXT"]]
BASE = os.environ["GATEWAY_URL"]
COMPOSE = sys.argv[1]
POOL = ipaddress.ip_network("2001:db8:1234:5678::/64")
POLICY_KEY = "irc:config:egressRoutingPolicy"
assert BASE == "http://127.0.0.1:" + os.environ["ROUTED_PORT"], "fixture gateway must be this run's loopback listener"


jar = LoopbackFixtureCookies(BASE)
http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
ids = []


def dc(*args, capture=True):
    result = subprocess.run([*DOCKER, "compose", "--project-name", PROJECT, "-f", COMPOSE, *args],
                            check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ""


def ex(service, *args):
    return dc("exec", "-T", service, *args)


def redis(*args):
    return ex("redis", "redis-cli", "--raw", *args)


def mongo(script):
    return ex("mongo", "mongosh", "--quiet", "ircfiber_routed_fixture", "--eval", script)


def gateway_access():
    return fixture_gateway_access(
        os.environ["ROUTED_DOCKER_CONTEXT"], PROJECT, COMPOSE, "gateway",
        "203.0.113.4", int(os.environ["ROUTED_PORT"]),
        os.environ.get("ROUTED_EXTERNAL_FORWARD", "0") == "1")


def wait(label, predicate, seconds=120):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (subprocess.CalledProcessError, urllib.error.URLError, HTTPException,
                ConnectionError, TimeoutError, ValueError, KeyError) as error:
            last = error
        time.sleep(1)
    raise AssertionError(f"timeout: {label}; last error: {last}")


def api(method, path, body=None, expect=(200, 201, 202)):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
    try:
        with http.open(request, timeout=40) as response:
            status, payload = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, payload = error.code, error.read()
    assert status in expect, (method, path, status, payload.decode())
    value = json.loads(payload) if payload else {}
    return value.get("data", value) if isinstance(value, dict) else value


def login(path):
    data = urllib.parse.urlencode({"username": "routedfixture", "email": "routed@local.test",
                                  "password": "RoutedFixture123!"}).encode()
    with http.open(urllib.request.Request(BASE + path, data=data), timeout=30) as response:
        response.read()


def endpoint(service="endpoint", body=None):
    # Control never leaves this labelled fixture's network namespace.
    code = ("import urllib.request,json; b=" + repr(body) + "; "
            "r=urllib.request.Request('http://127.0.0.1:8080/',"
            "data=None if b is None else json.dumps(b).encode(),"
            "headers={'Content-Type':'application/json'}); "
            "print(urllib.request.urlopen(r,timeout=12).read().decode())")
    return json.loads(ex(service, "python3", "-c", code))


def counts():
    return (len(endpoint()["accepts"]), len(endpoint("nord")["connects"]),
            len(endpoint("mull")["connects"]))


def no_new_sockets(before, seconds=8):
    time.sleep(seconds)
    assert counts() == before, ("unexpected physical socket attempt", before, counts())


def policy(order=None, blocked=None, hosts=None):
    current = api("GET", "/api/admin/config/routing-policy")["policy"]
    new = copy.deepcopy(current)
    new["global"] = {"order": order or ["ipv6", "nordvpn", "mullvad", "direct"],
                     "blockedRoutes": blocked or []}
    new["hosts"] = hosts or []
    return api("POST", "/api/admin/config/routing-policy",
               {"expectedRevision": current["revision"], "policy": new})["policy"]


def create(order, nick, host="dual.routed.test", port=16669, preferred=""):
    result = api("POST", "/api/networks", {"name": nick, "host": host, "port": port,
                 "tls": "enabled" if port == 16669 else "disabled", "nick": nick,
                 "realName": "Disposable routing fixture", "autoJoinChannels": [],
                 "routing": {"order": order, "preferredExit": preferred}})
    ident = result.get("id", result.get("networkId"))
    assert ident, result
    ids.append(ident)
    return ident, result


def update(ident, order, preferred=""):
    old = {(service, row["id"]) for service, row in held(ident)}
    saved = next(row for row in api("GET", "/api/networks") if row["id"] == ident)
    routing = {"order": order, "preferredExit": preferred}
    result = api("PUT", "/api/networks/" + ident, {"routing": routing})
    if old and saved["routing"] != routing:
        wait("routing edit closes old physical socket",
             lambda: not old.intersection((service, row["id"]) for service, row in held(ident)))
    return result


def reconnect(ident, expect=(200, 202)):
    old = {(service, row["id"]) for service, row in held(ident)}
    result = api("POST", f"/api/networks/{ident}/reconnect", {}, expect=expect)
    if old and "error" not in result:
        try:
            wait("reconnect closes old physical socket",
                 lambda: not old.intersection((service, row["id"]) for service, row in held(ident)))
        except AssertionError:
            print("Reconnect failure:", ident, result, "owner=", redis("hget", "irc:assignments", ident),
                  "held=", [(service, row["id"]) for service, row in held(ident)], file=sys.stderr)
            logs = dc("logs", "--no-color", "--since", "5m", "native-engine", "old-engine")
            for line in logs.splitlines():
                if ident in line or "reconnect_dedup" in line or "Failed to parse control" in line:
                    print(line, file=sys.stderr)
            raise
    return result


def remove(ident, nick):
    api("DELETE", "/api/networks/" + ident, expect=(200, 204))
    wait("deleted connection closes at holder and IRC endpoint",
         lambda: not held(ident) and not physical_registered(nick))


def snapshot(ident):
    owner = redis("hget", "irc:assignments", ident)
    raw = redis("hget", f"irc:state:{owner}:{ident}", "data")
    return json.loads(raw) if raw else {}


def connected(ident, route):
    state = snapshot(ident)
    return state if state.get("connected") and state.get("activeRoute") == route else None


def iid(ident):
    result = mongo("print(db.networks.findOne({id:" + json.dumps(ident) + "},{_id:0,ipv6Iid:1}).ipv6Iid)")
    assert len(result) == 16 and all(c in "0123456789abcdef" for c in result), result
    return result


def source_for(identity):
    return str(ipaddress.ip_address(int(POOL.network_address) | int(identity, 16)))


def held(ident):
    result = []
    for service in ("native-holder", "old-holder"):
        rows = json.loads(ex(service, "/app/irc-fiber-holder", "--list"))["connections"]
        result.extend((service, row) for row in rows
                      if row.get("tag", {}).get("networkId") == ident and row["state"] == "open")
    return result


def physical_registered(nick, peer=None):
    return [row for row in endpoint()["accepts"] if row.get("registered") and row.get("open")
            and row.get("nick") == nick and (peer is None or ipaddress.ip_address(row["peer"]) == ipaddress.ip_address(peer))]


def priority(server, value):
    api("POST", f"/api/admin/servers/{server}/config",
        {"priority": value, "maxConnections": 0, "fallbackOnly": False})
    wait("published engine priority", lambda:
         json.loads(redis("hget", f"irc:server:{server}", "data"))["priority"] == value)


def native(ident, nick, identity):
    state = wait("native registration", lambda: connected(ident, "ipv6"))
    actual = source_for(identity)
    assert ipaddress.ip_address(state["localIp"]) == ipaddress.ip_address(actual), state
    wait("independently observed native source", lambda: physical_registered(nick, actual))
    entries = held(ident)
    assert len(entries) == 1 and entries[0][0] == "native-holder", entries
    assert ipaddress.ip_address(entries[0][1]["localIp"]) == ipaddress.ip_address(actual)
    return state


def ipc(mode, body, old=False):
    path = "/run/oldholder/holder.sock" if old else "/run/ircfiber/holder.sock"
    server = "fixture-old" if old else "fixture-native"
    return json.loads(ex("native-net", "python3", "/fixture/routed_holder_client.py",
                         mode, path, server, json.dumps(body)))


def transport_edges():
    request = {"host": "dual.routed.test", "port": 16669, "tls": "implicit",
               "sni": "dual.routed.test", "addressFamily": "ipv6",
               "bindIp6": "2001:db8:1234:5678:a516:4466:5544:125",
               "tag": {"networkId": "fixture-ipc-only"}, "tlsTimeoutMs": 3000}
    variants = [
        (dict(request, addressFamily="bogus"), False),
        (dict(request, bindIp6=""), False),
        (dict(request, bindIp6="2001:db8:9999::12345"), False),
        (dict(request, bindIp6="2001:db8:9999::1234"), False),
        (dict(request, proxy={"host": "203.0.113.30", "port": 1080}), False),
        (request, True),  # old/shared holder has no authorized source pool
    ]
    before = counts()
    for variant, old in variants:
        reply = ipc("dial", variant, old)
        assert reply["verb"] in ("ERR", "FAILED"), reply
        assert counts() == before, ("IPC boundary leaked a socket", variant, counts())
    reply = ipc("dial", dict(request, host="aonly.routed.test"))
    assert reply["verb"] == "FAILED" and reply["payload"]["phase"] == "no_ipv6_destination", reply
    assert counts() == before
    endpoint(body={"nativeMode": "close"})
    reply = ipc("dial", request)
    assert reply["verb"] == "FAILED", reply
    new = endpoint()["accepts"][before[0]:]
    assert new and all(":" in row["peer"] for row in new), new
    before = counts()
    shared = dict(request, addressFamily="any", bindIp6="")
    reply = ipc("dial", shared)
    assert reply["verb"] == "CONNECTED", reply
    assert ":" not in reply["payload"]["peerIp"], reply
    ipc("close", {"id": reply["payload"]["id"]})
    assert counts()[1:] == before[1:]
    endpoint(body={"nativeMode": "healthy"})


def run():
    dc("up", "-d", "--no-build", "redis", "mongo", "native-net", "endpoint", "nord", "mull", capture=False)
    wait("Redis", lambda: redis("ping") == "PONG")
    wait("Mongo", lambda: mongo("print(db.runCommand({ping:1}).ok)") == "1")
    wait("endpoint and certificate", lambda: endpoint())
    redis("set", "irc:config:fiberEnabled", "0")
    redis("set", "irc:config:routingSchemaVersion", "1")
    initial = {"schema": 1, "revision": 0,
               "global": {"order": ["ipv6", "nordvpn", "mullvad", "direct"], "blockedRoutes": []}, "hosts": []}
    redis("set", POLICY_KEY, json.dumps(initial))
    # Two arbitrary pool sources must physically return over the route installed
    # ONLY in endpoint/native-net. No ip/sysctl command executes on the host.
    wait("native namespace local pool route", lambda: dc("exec", "-T", "native-net", "test", "-f", "/tmp/namespace-ready") == "")
    ex("native-net", "python3", "/fixture/routed_fixture.py", "proof")
    peers = {ipaddress.ip_address(row["peer"]) for row in endpoint()["accepts"]}
    assert {ipaddress.ip_address("2001:db8:1234:5678:a516:4466:5544:123"),
            ipaddress.ip_address("2001:db8:1234:5678:a516:4466:5544:124")} <= peers
    assert "dual.routed.test" in endpoint()["sni"]
    os.environ["ROUTED_VERIFIED"] = "1"
    dc("up", "-d", "--no-build", "native-holder", "old-holder", capture=False)
    for holder in ("native-holder", "old-holder"):
        wait(holder, lambda holder=holder: json.loads(ex(holder, "/app/irc-fiber-holder", "--status")))
    transport_edges()
    dc("up", "-d", "--no-build", "gateway", "native-engine", "old-engine", capture=False)
    wait("gateway", lambda: urllib.request.urlopen(BASE + "/health", timeout=2).status == 200)
    login("/register")
    mongo('db.users.updateOne({username:"routedfixture"},{$addToSet:{roles:"admin"}})')
    login("/login")
    wait("admin authentication", lambda: api("GET", "/api/admin/me")["isAdmin"])
    wait("both isolated engines", lambda: all(redis("sismember", "irc:servers", name) == "1"
                                             for name in ("fixture-native", "fixture-old")))
    priority("fixture-native", 100)
    priority("fixture-old", 10)

    # IPv6-only does not escape to an available A/TLS listener on failure.
    endpoint(body={"nativeMode": "close"})
    start = counts()
    only, _ = create(["ipv6"], "sixonly")
    wait("real failed IPv6 TLS attempt", lambda: counts()[0] > start[0])
    time.sleep(4)
    new = endpoint()["accepts"][start[0]:]
    assert new and all(":" in row["peer"] for row in new), new
    assert counts()[1:] == start[1:]
    remove(only, "sixonly")
    start = counts()
    aonly, _ = create(["ipv6"], "aonly", "aonly.routed.test")
    no_new_sockets(start)
    remove(aonly, "aonly")
    # Shared direct keeps dual-stack fallback and is never pool-bound.
    direct, _ = create(["direct"], "shared")
    shared = wait("shared IPv4 fallback", lambda: connected(direct, "direct"))
    assert ipaddress.ip_address(shared["localIp"]) not in POOL
    wait("physical A listener fallback", lambda: any(":" not in row["peer"] for row in physical_registered("shared")))
    remove(direct, "shared")
    endpoint(body={"nativeMode": "healthy"})

    # Seed real remembered Nord success, then prove tier order outranks memory.
    main, _ = create(["nordvpn"], "routedmain", preferred="fixture-nord")
    wait("initial Nord registration", lambda: connected(main, "nordvpn"))
    identity = iid(main)
    # Remove only the additive route field from real IRCFv1 META to emulate a
    # retained pre-upgrade VPN entry, not a stale image or invented snapshot.
    wait("Nord META ready", lambda: held(main)[0][1].get("meta"))
    old_holder, old_held = held(main)[0]
    old_entry = old_held["id"]
    old_engine = "native-engine" if old_holder == "native-holder" else "old-engine"
    old_row = physical_registered("routedmain")[0]
    old_accepts = counts()[0]
    dc("stop", old_engine, capture=False)
    ipc("legacy-meta", {"id": old_entry}, old=old_holder == "old-holder")
    wait("detached holder auto-PONG", lambda: physical_registered("routedmain")[0]["pongs"] > old_row["pongs"])
    dc("start", old_engine, capture=False)
    wait("old VPN META provider restored", lambda: connected(main, "nordvpn"))
    assert held(main)[0][1]["id"] == old_entry and counts()[0] == old_accepts
    before = counts()
    update(main, ["ipv6", "nordvpn"])
    native(main, "routedmain", identity)
    assert counts()[1:] == before[1:], (before, counts())
    clone, _ = create(["ipv6", "nordvpn"], "routedclone")
    clone_iid = iid(clone)
    assert clone_iid != identity
    native(clone, "routedclone", clone_iid)
    remove(clone, "routedclone")

    # Native transport failure advances only to permitted Nord, not Mull/direct.
    endpoint(body={"nativeMode": "close"})
    before = counts()
    reconnect(main)
    fallback = wait("Nord fallback", lambda: connected(main, "nordvpn"))
    assert counts()[1] > before[1] and counts()[2] == before[2]
    assert ipaddress.ip_address(fallback["localIp"]) not in POOL, fallback
    assert iid(main) == identity
    endpoint(body={"nativeMode": "healthy"})
    reconnect(main)
    native(main, "routedmain", identity)
    assert iid(main) == identity

    # Existing physical session, holder ID and PONGs survive policy save and
    # engine hot-swap; META must restore observed source, not recompute it.
    entry = held(main)[0][1]["id"]
    old = physical_registered("routedmain", source_for(identity))[0]
    accepts = counts()[0]
    policy(blocked=["nordvpn", "mullvad", "direct"])
    dc("restart", "native-engine", capture=False)
    native(main, "routedmain", identity)
    assert held(main)[0][1]["id"] == entry and counts()[0] == accepts
    wait("PONG on original held socket", lambda: any(row["id"] == old["id"] and row["pongs"] > old["pongs"]
                                                     for row in physical_registered("routedmain")))

    # An already saved preferred VPN, route memory and manual retry never
    # resurrect an administratively excluded provider.
    policy()
    update(main, ["nordvpn", "mullvad"], "fixture-nord")
    wait("remembered pinned Nord", lambda: connected(main, "nordvpn"))
    policy(blocked=["nordvpn", "mullvad"])
    entry = held(main)[0][1]["id"]
    before = counts()
    time.sleep(4)
    assert held(main)[0][1]["id"] == entry
    # Eligible expired recovery records must not bypass the provider block.
    recovery = {"v": 1, "endpoint": "203.0.113.30:1080", "draining": False,
                "drainReason": "", "open": True, "retryAtMs": int(time.time() * 1000) - 1000,
                "failures": 1, "circuitReason": "fixture recovery", "trialToken": "",
                "trialUntilMs": 0, "trialRegisteredAtMs": 0, "gen": 1,
                "updatedAtMs": int(time.time() * 1000)}
    redis("set", "irc:egress:admission:fixture-nord", json.dumps(recovery))
    reconnect(main)
    wait("blocked socket closed", lambda: not held(main))
    no_new_sockets(before, seconds=35)
    assert json.loads(redis("get", "irc:egress:admission:fixture-nord")) == recovery
    redis("del", "irc:egress:admission:fixture-nord")
    # Unrelated edit is accepted; newly adding a blocked route is not.
    api("PUT", "/api/networks/" + main, {"realName": "Unrelated retained preference"})
    update(main, [])
    api("PUT", "/api/networks/" + main,
        {"routing": {"order": ["nordvpn"], "preferredExit": "fixture-nord"}}, expect=(422,))
    assert iid(main) == identity
    policy()
    update(main, ["mullvad", "nordvpn"], "fixture-mull")
    wait("remembered pinned Mullvad", lambda: connected(main, "mullvad"))
    policy(blocked=["mullvad", "nordvpn"])
    recovery = dict(recovery, endpoint="203.0.113.31:1080",
                    retryAtMs=int(time.time() * 1000) - 1000,
                    updatedAtMs=int(time.time() * 1000))
    redis("set", "irc:egress:admission:fixture-mull", json.dumps(recovery))
    before = counts()
    reconnect(main)
    no_new_sockets(before, seconds=35)
    assert json.loads(redis("get", "irc:egress:admission:fixture-mull")) == recovery
    redis("del", "irc:egress:admission:fixture-mull")
    update(main, [])
    policy()

    # A late administrative save while the planned first native candidate is
    # physically stalled must filter Nord again before the next holder DIAL.
    endpoint(body={"nativeMode": "hold-close"})
    before = counts()
    update(main, ["ipv6", "nordvpn"])
    wait("first tier in-flight before policy save", lambda: counts()[0] > before[0])
    policy(blocked=["nordvpn", "mullvad", "direct"])
    time.sleep(15)
    assert counts()[1:] == before[1:], (before, counts())
    update(main, [])
    endpoint(body={"nativeMode": "healthy"})
    wait("empty plan parked", lambda: not held(main))
    before = counts()
    empty, response = create([], "emptyroute")
    assert response.get("routingBlocked") is True, response
    assert not redis("hget", "irc:assignments", empty)
    assert next(row for row in api("GET", "/api/networks") if row["id"] == empty)["routing"]["order"] == []
    reconnect(main)
    no_new_sockets(before)

    # Missing/corrupt durable policy blocks new upstream work while a held
    # session continues answering actual server PINGs.
    policy()
    stable, _ = create(["nordvpn"], "heldpolicy")
    wait("retained policy session", lambda: connected(stable, "nordvpn"))
    stable_row = physical_registered("heldpolicy")[0]
    saved = redis("get", POLICY_KEY)
    for bad in (None, "{broken", '{"schema":1,"revision":0,"global":{"order":["unknown"],"blockedRoutes":[]},"hosts":[]}'):
        if bad is None:
            redis("del", POLICY_KEY)
        else:
            redis("set", POLICY_KEY, bad)
        before = counts()
        reconnect(main, expect=(200, 202, 503))
        no_new_sockets(before)
        assert physical_registered("heldpolicy")[0]["id"] == stable_row["id"]
    wait("held PONGs while policy unavailable", lambda: physical_registered("heldpolicy")[0]["pongs"] > stable_row["pongs"])
    redis("set", POLICY_KEY, saved)

    # A storage read error is not an unrestricted/default cache hit. Pause a
    # real first-tier handshake, then deny GET on this disposable Redis only.
    endpoint(body={"nativeMode": "hold-close"})
    before = counts()
    update(main, ["ipv6", "nordvpn"])
    wait("native in flight before Redis read denial", lambda: counts()[0] > before[0])
    unreadable_counts = counts()
    redis("ACL", "SETUSER", "default", "-get")
    try:
        no_new_sockets(unreadable_counts, seconds=15)
        assert physical_registered("heldpolicy")[0]["id"] == stable_row["id"]
        assert physical_registered("heldpolicy")[0]["pongs"] > stable_row["pongs"]
    finally:
        redis("ACL", "SETUSER", "default", "+get")
    update(main, [])
    endpoint(body={"nativeMode": "healthy"})

    # Public admin IRC probe uses explicit PoolEntry.provider, not slot label
    # spelling. Allowed probe must CONNECT/register; each block means zero
    # physical CONNECT attempts and a structured policy_blocked response.
    for provider, service, label in (("nordvpn", "nord", "fixture-nord"), ("mullvad", "mull", "fixture-mull")):
        policy()
        before = len(endpoint(service)["connects"])
        result = api("POST", f"/api/admin/mullvad/{label}/irc-test", {"host": "dual.routed.test", "port": 16668})
        assert result["registered"] and len(endpoint(service)["connects"]) > before, result
        policy(blocked=[provider])
        before = len(endpoint(service)["connects"])
        result = api("POST", f"/api/admin/mullvad/{label}/irc-test", {"host": "dual.routed.test", "port": 16668})
        assert result["policyBlocked"] and result["error"] == "policy_blocked", result
        assert len(endpoint(service)["connects"]) == before
    policy()
    # First-party locking is an intersection, never permission to rewrite a
    # user's explicit VPN-only preference into a new shared-direct connection.
    before = counts()
    first_party = api("POST", "/api/networks",
                      {"name": "First-party VPN-only", "host": "default.routed.test",
                       "port": 16668, "tls": "disabled", "nick": "lockedvpn",
                       "realName": "Disposable routing fixture", "autoJoinChannels": [],
                       "routing": {"order": ["nordvpn"], "preferredExit": ""}},
                      expect=(200, 201, 422))
    first_id = first_party.get("id", first_party.get("networkId"))
    if first_id:
        ids.append(first_id)
        assert first_party.get("routingBlocked") is True, first_party
        stored = next(row for row in api("GET", "/api/networks") if row["id"] == first_id)
        assert stored["routing"]["order"] == ["nordvpn"], stored
        assert not owner(first_id), "blocked first-party create must remain unassigned"
    else:
        assert first_party.get("error"), first_party
    no_new_sockets(before)
    if first_id:
        remove(first_id, "lockedvpn")

    # The largest exact JSON revision is readable for an explicit reconnect,
    # but not incrementable by save. Use an already parked row: zero dials.
    saved_policy = redis("get", POLICY_KEY)
    boundary = json.loads(saved_policy)
    boundary["revision"] = 9007199254740991
    redis("set", POLICY_KEY, json.dumps(boundary))
    before = counts()
    try:
        api("POST", "/api/admin/config/routing-policy/reconnect",
            {"expectedRevision": boundary["revision"], "networkIds": [main]}, expect=(202,))
        api("POST", "/api/admin/config/routing-policy",
            {"expectedRevision": boundary["revision"], "policy": boundary}, expect=(400,))
        assert json.loads(redis("get", POLICY_KEY)) == boundary
        no_new_sockets(before)
    finally:
        redis("set", POLICY_KEY, saved_policy)
    if os.environ.get("ROUTED_REQUIRE_MOVES") == "1":
        movement(main, identity)
    print("PASS: physical IPv6/no-A, pool return path/SNI, tier order, stable IID, fallback, exclusion, late block, empty/missing/corrupt fail-closed, held PONGs/hot-swap and admin probes")
    if os.environ.get("ROUTED_REQUIRE_MOVES") != "1":
        print("Step 5 acceptance not exercised: rerun with ROUTED_REQUIRE_MOVES=1 after tier placement and fenced coordinator land")


def owner(ident):
    return redis("hget", "irc:assignments", ident)


def operation(move_id):
    raw = redis("hgetall", "irc:routing:move-status:" + move_id).splitlines()
    return dict(zip(raw[::2], raw[1::2]))


def single_upstream(ident, nick):
    evidence = endpoint()
    rows = [row for row in evidence["accepts"]
            if row["open"] and row["registered"] and row.get("nick") == nick]
    assert len(rows) <= 1 and evidence["maxRegistered"].get(nick, 0) <= 1, (
        "multiple real registered upstream sockets", nick, evidence)
    return rows


def control(server, action, ident, config=None):
    body = {"action": action, "networkId": ident,
            "userId": "00000000-0000-4000-8000-000000000099",
            "timestampMs": int(time.time() * 1000)}
    if config is not None:
        body["config"] = config
    redis("lpush", "irc:control:" + server, json.dumps(body))

def backlog_ping(request, ident, nick):
    token = "PING :" + request["_queuedPing"]
    def received():
        rows = single_upstream(ident, nick)
        return rows[0] if rows and token in rows[0]["clientPings"] else None
    current = wait("fenced backlog reaches the canonical command consumer", received)
    records = [row for row in endpoint()["accepts"] if token in row["clientPings"]]
    assert len(records) == 1 and records[0]["id"] == current["id"], records



def command_ping(ident, nick):
    token = "routing-move-" + str(time.monotonic_ns())
    before = single_upstream(ident, nick)
    assert len(before) == 1, before
    server = owner(ident)
    command = {"cmd": "raw", "text": "PING :" + token,
               "timestampMs": int(time.time() * 1000)}
    redis("rpush", f"irc:cmd:{server}:{ident}", json.dumps(command))
    wait("destination consumer sends harmless server PING", lambda: any(
        "PING :" + token in row["clientPings"] for row in single_upstream(ident, nick)))
    records = endpoint()["accepts"]
    received = [row for row in records if "PING :" + token in row["clientPings"]]
    assert len(received) == 1 and received[0]["id"] == before[0]["id"], received


def paused_move(ident, target):
    """A real paused source makes duplicate/failure windows deterministic."""
    source = owner(ident)
    source_service = "native-engine" if source == "fixture-native" else "old-engine"
    dc("pause", source_service)
    try:
        request = api("POST", f"/api/admin/networks/{ident}/move",
                      {"serverId": target}, expect=(202,))
        wait("real worker begins source-close operation", lambda:
             operation(request["moveId"]).get("state") == "processing")
        # An outstanding BLPOP can consume into the paused engine's TCP buffer.
        # Queue contents are not delivery/closure evidence; actual source ack
        # and independently observed upstream sockets below prove the handoff.
        duplicate = api("POST", f"/api/admin/networks/{ident}/move",
                        {"serverId": target}, expect=(202,))
        assert duplicate["moveId"] == request["moveId"], (request, duplicate)
        endpoint(body={"moveWitness": {"moveId": request["moveId"], "fromServerId": source}})
        queued_ping = "fenced-backlog-" + str(time.monotonic_ns())
        redis("rpush", f"irc:cmd:{source}:{ident}", json.dumps(
            {"cmd": "raw", "text": "PING :" + queued_ping, "timestampMs": int(time.time() * 1000)}))
        request["_queuedPing"] = queued_ping
        return request, source_service
    except BaseException:
        dc("unpause", source_service)
        raise


def finish_move(request, ident, nick, completed=True):
    def terminal():
        single_upstream(ident, nick)
        result = api("GET", "/api/admin/routing-moves/" + request["moveId"])
        return result if result["state"] in ("completed", "failed", "expired") else None
    try:
        result = wait("controlled move terminal state", terminal, seconds=100)
    except AssertionError:
        print("MOVE FAILURE", json.dumps({
            "operation": operation(request["moveId"]),
            "owner": owner(ident),
            "fence": redis("get", "irc:routing:move:" + ident),
        }), flush=True)
        for service in ("gateway", "old-engine", "native-engine"):
            container = dc("ps", "-a", "-q", service)
            if container:
                state = subprocess.check_output(
                    [*DOCKER, "inspect", "--format", "{{json .State}}", container], text=True)
                print(service, "STATE", state, flush=True)
        logs = dc("logs", "--no-color", "gateway", "old-engine", "native-engine")
        for line in logs.splitlines():
            if any(word in line.lower() for word in ("routing", "migrat", "exception", "error", "pool:", "quiescen")):
                print(line, flush=True)
        raise
    if completed:
        assert result["state"] == "completed", result
        assert result.get("sourceClosed") is True and result["ackServerId"] == request["fromServerId"], result
        assert owner(ident) == request["targetServerId"], result
        wait("destination physical registration", lambda: single_upstream(ident, nick))
        row = single_upstream(ident, nick)[0]
        proof = row["moveProof"]
        assert proof and proof["moveId"] == request["moveId"] and proof["sourceClosed"], row
        assert proof["ackServerId"] == request["fromServerId"], row
        entries = held(ident)
        assert len(entries) == 1, entries
        command_ping(ident, nick)
        if request.get("_queuedPing"):
            backlog_ping(request, ident, nick)
    else:
        assert result["state"] in ("failed", "expired"), result
        assert owner(ident) == request["fromServerId"], result
        assert not redis("lrange", "irc:control:" + request["targetServerId"], "0", "-1"), result
    endpoint(body={"moveWitness": None})
    return result


def movement(_parked_ident, _parked_identity):
    policy(order=["nordvpn", "ipv6", "direct"])
    priority("fixture-old", 200)
    priority("fixture-native", 10)
    ident, _ = create(None, "movematrix")
    identity = iid(ident)
    wait("high-priority old engine owns inherited VPN connection",
         lambda: owner(ident) == "fixture-old" and connected(ident, "nordvpn"))
    original = single_upstream(ident, "movematrix")[0]
    original_entry = held(ident)[0][1]["id"]

    # Saving a new default and registering native capability never mass-moves.
    policy(order=["ipv6", "nordvpn", "direct"])
    dc("restart", "native-engine", capture=False)
    wait("native engine re-registration", lambda:
         "ipv6" in json.loads(redis("hget", "irc:server:fixture-native", "data"))["supportedRoutes"])
    no_new_sockets(counts(), seconds=15)
    assert owner(ident) == "fixture-old" and held(ident)[0][1]["id"] == original_entry
    assert single_upstream(ident, "movematrix")[0]["id"] == original["id"]

    # Legitimate reconnect crosses owners through the real coordinator.
    dc("pause", "old-engine")
    try:
        api("POST", f"/api/networks/{ident}/reconnect", {})
        move_id = wait("explicit reconnect creates a fence", lambda:
                       redis("get", "irc:routing:move:" + ident))
        request = api("GET", "/api/admin/routing-moves/" + move_id)
        endpoint(body={"moveWitness": {"moveId": move_id, "fromServerId": "fixture-old"}})
    finally:
        dc("unpause", "old-engine")
    finish_move(request, ident, "movematrix")
    native(ident, "movematrix", identity)

    # Remote-owner bootstrap, stale controls and an obsolete reverse mirror must
    # never instantiate the canonical native connection on the old engine.
    before = counts()
    redis("hset", "irc:server-assignments:fixture-old", ident, "fixture-old")
    dc("restart", "old-engine", capture=False)
    stale = {"id": ident, "host": "aonly.routed.test", "nick": "staleowner",
             "routing": {"order": ["direct"], "preferredExit": ""}}
    for action in ("addNetwork", "updateNetwork", "reconnectNetwork"):
        control("fixture-old", action, ident, stale)
    no_new_sockets(before, seconds=15)
    assert owner(ident) == "fixture-native"
    assert single_upstream(ident, "movematrix")[0]["moveProof"]["sourceClosed"]
    wait("assigned-away reverse mirror cleared", lambda:
         not redis("hget", "irc:server-assignments:fixture-old", ident))

    # Wiped canonical state can recover only its uniquely evidenced live owner.
    before = counts()
    redis("hdel", "irc:assignments", ident)
    wait("wiped canonical owner repaired without a second socket",
         lambda: owner(ident) == "fixture-native")
    no_new_sockets(before)
    command_ping(ident, "movematrix")

    # Remove a local client without deleting/disabling its canonical Mongo row.
    # Heartbeat reconciliation, not an add/reconnect message, must restore it.
    previous = single_upstream(ident, "movematrix")[0]["id"]
    control("fixture-native", "disconnectNetwork", ident)
    wait("missing canonical client is reconstructed", lambda:
         any(row["id"] != previous for row in single_upstream(ident, "movematrix")))
    native(ident, "movematrix", identity)
    command_ping(ident, "movematrix")

    request, source_service = paused_move(ident, "fixture-old")
    dc("unpause", source_service)
    finish_move(request, ident, "movematrix")
    stale_move = request
    request, source_service = paused_move(ident, "fixture-native")
    dc("unpause", source_service)
    finish_move(request, ident, "movematrix")
    assert iid(ident) == identity
    before = counts()
    control("fixture-native", "migrateNetwork", ident, stale_move)
    no_new_sockets(before)
    command_ping(ident, "movematrix")

    # A policy change or target drain during source quiescence must refuse
    # commit, leave canonical source untouched, and reconcile its stopped client.
    for change in ("policy", "priority", "target"):
        request, source_service = paused_move(ident, "fixture-old")
        before = counts()
        try:
            if change == "policy":
                policy(order=["ipv6", "nordvpn"], blocked=["nordvpn", "direct"])
            elif change == "priority":
                priority("fixture-old", 201)
            else:
                dc("pause", "old-engine")
                redis("set", "irc:draining:fixture-old", "1", "EX", "110")
                redis("hset", "irc:server:fixture-old", "draining", "true")
            dc("unpause", source_service)
            finish_move(request, ident, "movematrix", completed=False)
            # No VPN/direct target route may even attempt a CONNECT.
            assert counts()[1:] == before[1:], (change, before, counts())
            assert all(":" in row["peer"] for row in endpoint()["accepts"][before[0]:]), (
                "destination accepted without a committed move", change)
        finally:
            if change == "target":
                redis("del", "irc:draining:fixture-old")
                redis("hdel", "irc:server:fixture-old", "draining")
                dc("unpause", "old-engine")
            elif change == "priority":
                priority("fixture-old", 200)
            policy()
        wait("source recovers after refused move", lambda:
             owner(ident) == "fixture-native" and connected(ident, "ipv6")
             and single_upstream(ident, "movematrix"))
        command_ping(ident, "movematrix")
        backlog_ping(request, ident, "movematrix")

    # A holder that cannot answer LIST/CLOSE is not closure proof, even when
    # the source's manager has stopped. Its real socket remains at the endpoint.
    dc("pause", "native-holder")
    request = None
    try:
        request, source_service = paused_move(ident, "fixture-old")
        before = counts()
        dc("unpause", source_service)
        result = finish_move(request, ident, "movematrix", completed=False)
        assert not result.get("sourceClosed", False), result
        assert counts()[1:] == before[1:], (before, counts())
        assert all(":" in row["peer"] for row in endpoint()["accepts"][before[0]:])
    finally:
        dc("unpause", "native-holder")
    wait("source recovers after holder becomes reachable", lambda:
         connected(ident, "ipv6") and single_upstream(ident, "movematrix"))
    backlog_ping(request, ident, "movematrix")
    command_ping(ident, "movematrix")

    # Kill the actual worker process after dequeue, not a simulated exception.
    # Let the original 120-second Redis fence expire; no fabricated ack or TTL
    # reset authorizes another owner. Source heartbeat must recover by itself.
    request, source_service = paused_move(ident, "fixture-old")
    before = counts()
    dc("kill", "-s", "SIGKILL", "gateway", capture=False)
    try:
        dc("unpause", source_service)
        wait("source supplies real close proof to crashed operation", lambda:
             operation(request["moveId"]).get("sourceClosed") == "1", seconds=85)
        assert owner(ident) == "fixture-native"
        wait("abandoned worker fence expires naturally", lambda:
             not redis("exists", "irc:routing:move:" + ident) == "1", seconds=135)
        wait("source heartbeat recovers after abandoned fence", lambda:
             connected(ident, "ipv6") and single_upstream(ident, "movematrix"))
        assert owner(ident) == "fixture-native" and counts()[1:] == before[1:]
        assert all(":" in row["peer"] for row in endpoint()["accepts"][before[0]:])
    finally:
        dc("start", "gateway", capture=False)
    wait("gateway returns after worker crash", lambda:
         urllib.request.urlopen(BASE + "/health", timeout=2).status == 200)
    finish_move(request, ident, "movematrix", completed=False)
    command_ping(ident, "movematrix")
    backlog_ping(request, ident, "movematrix")
    remove(ident, "movematrix")

    # A physical TLS DIAL is still in flight when movement begins. The holder's
    # delayed endpoint closes without registration; only actual quiescence and
    # LIST closure may release an old-node VPN registration.
    endpoint(body={"nativeMode": "hold-close", "nativeDelaySeconds": 30})
    before = counts()
    inflight, _ = create(["ipv6", "nordvpn"], "moveinflight")
    inflight_iid = iid(inflight)
    wait("real native TLS DIAL is in flight", lambda:
         any(row["open"] and not row["registered"] and ":" in row["peer"]
             for row in endpoint()["accepts"][before[0]:]))
    request, source_service = paused_move(inflight, "fixture-old")
    dc("unpause", source_service)
    finish_move(request, inflight, "moveinflight")
    assert connected(inflight, "nordvpn") and iid(inflight) == inflight_iid
    endpoint(body={"nativeMode": "healthy", "nativeDelaySeconds": 8})
    remove(inflight, "moveinflight")
    print("PASS: two-node tier placement/no mass move, remote bootstrap, mirror recovery, missing-client reconciliation, stale controls, duplicate moves, positive source-close proof, destination command PING, changed policy/target refusal, unreachable holder, worker crash/expiry/source recovery and in-flight DIAL")


if __name__ == "__main__":
    with gateway_access():
        run()
