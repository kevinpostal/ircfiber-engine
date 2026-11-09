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
import datetime
import hashlib
import json

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 16668
RESULT_FILE = sys.argv[2] if len(sys.argv) > 2 else "/tmp/holder-mock-irc.result"
LINES_FILE = os.environ.get("MOCK_IRC_LINES", "/tmp/mock-irc.lines")
INJECT_FILE = os.environ.get("MOCK_IRC_INJECT", "/tmp/mock-irc.inject")
SERVER = "mock.irc"

# Entirely opt-in: the original no-CAP transport below stays unchanged.
# Control records use the existing INJECT_FILE, alongside verbatim IRC lines:
#   !history {"op":"configure","short_pages":1,"nested":true}
# See site/scripts/e2e/history_fixture.py for the producer and full contract.
HISTORY_ENABLED = os.environ.get("MOCK_IRC_HISTORY", "") == "1"
HISTORY_CONTROL_PREFIX = "!history "


def history_time(timestamp_ms):
    return datetime.datetime.fromtimestamp(
        timestamp_ms / 1000, datetime.timezone.utc
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def history_timestamp(selector):
    if not selector.startswith("timestamp="):
        raise ValueError("expected timestamp selector")
    value = datetime.datetime.fromisoformat(selector[10:].replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return int(value.timestamp() * 1000)


def history_tag(line, tag):
    return "@" + tag + ";" + line[1:] if line.startswith("@") else "@" + tag + " " + line


class HistoryFixture:
    """DM-retaining scripted upstream, not evidence about the owned IRCd.

    The manifest is a saved oracle, not an alternate history transport. Clients
    receive rows only through normal IRC CHATHISTORY/BATCH responses.
    """

    def __init__(self):
        self.labels = os.environ.get("MOCK_IRC_HISTORY_LABELS", "nested")
        if self.labels not in ("none", "direct", "nested"):
            raise ValueError("MOCK_IRC_HISTORY_LABELS must be none, direct or nested")
        self.expected_path = os.environ.get(
            "MOCK_IRC_HISTORY_EXPECTED", "/tmp/mock-irc.history.expected.json")
        self.events_path = os.environ.get(
            "MOCK_IRC_HISTORY_EVENTS", "/tmp/mock-irc.history.events.jsonl")
        self.mutex = threading.RLock()
        self.base_ms = int(os.environ.get(
            "MOCK_IRC_HISTORY_NOW_MS", str(int(time.time() * 1000)))) - 600_000
        self.options = {
            "short_pages": 0, "short_limit": 7, "context": False,
            "end_markers": True, "nested": False, "multiline": False,
            "live": False, "timestamp_only": False, "clipped_boundary": False,
            "reject_msgids": 0, "reject_code": "INVALID_MSGID",
            "timeout": "none", "malformed": "none", "empty_pages": 0,
            "invalid_target": "", "pause_after": 0,
            "visible_count": int(os.environ.get("MOCK_IRC_HISTORY_INITIAL_ROWS", "2503")),
            "offline_visible": os.environ.get("MOCK_IRC_HISTORY_OFFLINE", "1") == "1",
        }
        if not 0 <= self.options["visible_count"] <= 2503:
            raise ValueError("MOCK_IRC_HISTORY_INITIAL_ROWS must be between 0 and 2503")
        self.available = True
        self.native_cap = ""
        self.sequence = 0
        self.live_sequence = 0
        self.rows = {}
        # The permutation-like hash IDs deliberately do not sort in wire order.
        # Seven rows share each timestamp; page size twenty crosses those ties.
        for target, count in (("history-peer", 2503), ("offline-discovery", 3),
                              ("offline-boundary", 3), ("empty-peer", 0)):
            self.rows[target] = [{
                "target": target, "msgid": hashlib.sha256(
                    f"holder-history-v1/{target}/{index}".encode()).hexdigest()[:24],
                "timestampMs": self.base_ms + (index // 7) * 1000,
                "text": f"retained {target} {index:04d}", "index": index,
            } for index in range(count)]
        self.live_rows = []
        with open(self.events_path, "w"):
            pass
        self.save_expected()

    def caps(self):
        caps = ["batch", "message-tags", "server-time", "draft/multiline=max-bytes=65536,max-lines=100"]
        if self.available:
            caps += ["draft/chathistory", "draft/event-playback"]
        if self.labels != "none":
            caps.append("labeled-response")
        if self.native_cap:
            caps.append("draft/account-registration=" + self.native_cap)
        return caps

    def effective_row(self, row):
        value = dict(row)
        if self.options["clipped_boundary"]:
            value["timestampMs"] = self.base_ms
        if self.options["timestamp_only"]:
            value["msgid"] = ""
        value["time"] = history_time(value["timestampMs"])
        return value

    def visible_rows(self, target):
        rows = self.rows[target]
        if target == "history-peer":
            rows = rows[:self.options["visible_count"]] + self.live_rows
        elif target.startswith("offline-") and not self.options["offline_visible"]:
            rows = []
        return [self.effective_row(row) for row in rows]

    def save_expected(self):
        with self.mutex:
            expected = {
                "version": 1, "fixtureOnly": True, "limit": 20,
                "primaryTarget": "history-peer", "primaryCount": 2503,
                "discoveryOnlyTarget": "offline-discovery",
                "labels": self.labels, "options": dict(self.options),
                "nativeRegistrationCapability": self.native_cap,
                "targets": {target: [self.effective_row(row) for row in rows]
                            for target, rows in self.rows.items()},
                "visible": {target: [row["msgid"] for row in self.visible_rows(target)]
                            for target in self.rows},
                "visibleIndices": {target: [row["index"] for row in self.visible_rows(target)]
                                   for target in self.rows},
                "live": [self.effective_row(row) for row in self.live_rows],
            }
            temporary = self.expected_path + ".tmp"
            with open(temporary, "w") as output:
                json.dump(expected, output, separators=(",", ":"))
                output.write("\n")
            os.replace(temporary, self.expected_path)

    def record(self, event):
        with self.mutex:
            with open(self.events_path, "a") as output:
                output.write(json.dumps(event, separators=(",", ":")) + "\n")

    def next_ref(self, prefix):
        with self.mutex:
            self.sequence += 1
            return f"fixture-{prefix}-{self.sequence}"


class HistorySession:
    def __init__(self, fixture, conn):
        self.fixture = fixture
        self.conn = conn
        self.nick = "*"
        self.enabled = set()
        self.send_lock = threading.RLock()
        self.pending = []
        self.registration_ready = False

    def send(self, line):
        with self.send_lock:
            send(self.conn, line)

    def raw_inject(self, data):
        # One injection can configure the next response and contain real IRC
        # lines. No controls are ever emitted to, or accepted from, the client.
        with self.send_lock:
            for line in data.decode("utf-8").splitlines():
                if line.startswith(HISTORY_CONTROL_PREFIX):
                    self.control(json.loads(line[len(HISTORY_CONTROL_PREFIX):]))
                elif line:
                    self.send(line)

    def control(self, control):
        if not isinstance(control, dict):
            raise ValueError("history control must be an object")
        op = control.get("op")
        fixture = self.fixture
        if op == "configure":
            updates = {key: value for key, value in control.items() if key != "op"}
            if set(updates) - set(fixture.options):
                raise ValueError("unknown history option")
            for key, value in updates.items():
                original = fixture.options[key]
                if type(value) is not type(original):
                    raise ValueError(f"invalid type for {key}")
                if isinstance(value, str) and any(ord(c) < 32 for c in value):
                    raise ValueError("control strings cannot contain controls")
            if "visible_count" in updates and not 0 <= updates["visible_count"] <= 2503:
                raise ValueError("visible_count must be between 0 and 2503")
            for key in ("short_pages", "reject_msgids", "empty_pages", "pause_after"):
                if key in updates and updates[key] < 0:
                    raise ValueError(f"{key} must be nonnegative")
            if "short_limit" in updates and not 1 <= updates["short_limit"] < 20:
                raise ValueError("short_limit must be between 1 and 19")
            if updates.get("timeout", "none") not in ("none", "silent", "open"):
                raise ValueError("invalid timeout mode")
            if updates.get("malformed", "none") not in (
                    "none", "duplicate", "missing_parent", "cycle",
                    "premature_close", "unclosed_child"):
                raise ValueError("invalid malformed mode")
            if updates.get("reject_code", "INVALID_MSGID") not in (
                    "INVALID_MSGID", "MSGID_EXPIRED"):
                raise ValueError("invalid msgid rejection code")
            with fixture.mutex:
                if updates.get("offline_visible") and not fixture.options["offline_visible"]:
                    # These are newly received offline DMs, not archive rows
                    # hidden from an earlier TARGETS discovery watermark.
                    activated_at = int(time.time() * 1000)
                    for target, rows in fixture.rows.items():
                        if target.startswith("offline-"):
                            for row in rows:
                                row["timestampMs"] = activated_at + row["index"] // 7
                fixture.options.update(updates)
                fixture.save_expected()
        elif op == "caps":
            available = control.get("available")
            if type(available) is not bool:
                raise ValueError("caps needs boolean available")
            fixture.available = available
            verb = "NEW" if available else "DEL"
            self.send(f":{SERVER} CAP {self.nick} {verb} :draft/chathistory draft/event-playback")
            if not available:
                self.enabled -= {"draft/chathistory", "draft/event-playback"}
            # NEW is followed by a real REQ/ACK, never an unsolicited ACK.
        elif op == "native-cap":
            value = control.get("value")
            if not isinstance(value, str) or any(
                    character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=,-"
                    for character in value):
                raise ValueError("native-cap value must be a CAP token value")
            with fixture.mutex:
                fixture.native_cap = value
                fixture.save_expected()
            if value:
                self.send(f":{SERVER} CAP {self.nick} NEW :draft/account-registration={value}")
            else:
                self.enabled.discard("draft/account-registration")
                self.send(f":{SERVER} CAP {self.nick} DEL :draft/account-registration")
            # REGISTER/VERIFY remain wire-recorded and unanswered. The matrix
            # injects actual server verdict lines through the existing file.
        elif op == "resume":
            pending, self.pending = self.pending, []
            for lines in pending:
                for line in lines:
                    self.send(line)
        elif op == "live":
            self.emit_live()
        else:
            raise ValueError("unknown history control operation")
        fixture.record({"control": control})

    def emit_live(self):
        fixture = self.fixture
        with fixture.mutex:
            fixture.live_sequence += 1
            number = fixture.live_sequence
            row = {"target": "history-peer", "msgid": f"fixture-live-{number}",
                   "timestampMs": int(time.time() * 1000),
                   "text": f"live during recovery {number}", "index": 2502 + number}
            fixture.live_rows.append(row)
            fixture.save_expected()
        self.send(f"@time={history_time(row['timestampMs'])};msgid={row['msgid']} "
                  f":history-peer!u@fixture PRIVMSG {self.nick} :{row['text']}")

    def handle(self, text):
        tags = {}
        if text.startswith("@"):
            encoded, _, text = text.partition(" ")
            for item in encoded[1:].split(";"):
                key, _, value = item.partition("=")
                tags[key] = value
        parts = text.split()
        if not parts:
            return True
        command = parts[0].upper()
        if command == "CAP":
            subcommand = parts[1].upper() if len(parts) > 1 else ""
            if subcommand == "LS":
                self.send(f":{SERVER} CAP * LS :{' '.join(self.fixture.caps())}")
            elif subcommand == "REQ":
                requested = text.partition(" :")[2].split()
                advertised = {cap.split("=", 1)[0] for cap in self.fixture.caps()}
                valid = bool(requested) and all(cap.lstrip("-") in advertised for cap in requested)
                self.send(f":{SERVER} CAP {self.nick} {'ACK' if valid else 'NAK'} :{' '.join(requested)}")
                if valid:
                    for cap in requested:
                        if cap.startswith("-"):
                            self.enabled.discard(cap[1:])
                        else:
                            self.enabled.add(cap)
            elif subcommand == "END":
                self.registration_ready = True
            return True
        if command == "CHATHISTORY":
            label = tags.get("label", "") if "labeled-response" in self.enabled else ""
            # Finish each response atomically relative to injection, except
            # explicitly interleaved live rows and intentionally held closes.
            with self.send_lock, self.fixture.mutex:
                self.history(parts[1:], label)
            return True
        return False

    def failure(self, subcommand, code, description, label):
        line = f":{SERVER} FAIL CHATHISTORY {code} {subcommand} :{description}"
        if label:
            line = f"@label={label} " + line
        self.send(line)

    def envelope(self, batch_type, target, label):
        fixture = self.fixture
        root = fixture.next_ref("history")
        opening, closing = [], []
        parent = ""
        if label and fixture.labels == "nested":
            outer = fixture.next_ref("label")
            opening.append(f"@label={label} :{SERVER} BATCH +{outer} labeled-response")
            closing.insert(0, f":{SERVER} BATCH -{outer}")
            parent = outer
        if fixture.options["nested"]:
            wrapper = fixture.next_ref("ancestor")
            tag = f"@batch={parent} " if parent else ""
            opening.append(f"{tag}:{SERVER} BATCH +{wrapper} fixture/ancestor")
            closing.insert(0, f":{SERVER} BATCH -{wrapper}")
            parent = wrapper
        attributes = []
        if parent:
            attributes.append("batch=" + parent)
        if label and fixture.labels == "direct":
            attributes.append("label=" + label)
        tag = "@" + ";".join(attributes) + " " if attributes else ""
        suffix = f" {target}" if target else ""
        opening.append(f"{tag}:{SERVER} BATCH +{root} {batch_type}{suffix}")
        closing.insert(0, f":{SERVER} BATCH -{root}")
        return root, opening, closing

    def row_lines(self, row, batch, context=False, multiline=False):
        tags = [f"batch={batch}", f"time={history_time(row['timestampMs'])}"]
        if row["msgid"]:
            tags.append("msgid=" + row["msgid"])
        if context:
            tags.append("draft/chathistory-context")
        prefix = f":{row['target']}!u@fixture PRIVMSG {self.nick} :"
        if not multiline:
            return ["@" + ";".join(tags) + " " + prefix + row["text"]]
        child = self.fixture.next_ref("multiline")
        start = f"@batch={batch} :{SERVER} BATCH +{child} draft/multiline {self.nick}"
        tags[0] = "batch=" + child
        middle = len(row["text"]) // 2
        first = "@" + ";".join(tags) + " " + prefix + row["text"][:middle]
        second = "@" + ";".join(tags + ["draft/multiline-concat"]) + " " + prefix + row["text"][middle:]
        return [start, first, second, f":{SERVER} BATCH -{child}"]

    def history(self, args, label):
        fixture = self.fixture
        options = fixture.options
        if not fixture.available:
            self.failure("*", "UNAVAILABLE", "History capability is unavailable", label)
            return
        if not {"batch", "message-tags", "server-time", "draft/chathistory"} <= self.enabled:
            self.failure("*", "NEED_CAP", "Required history capabilities are not enabled", label)
            return
        try:
            subcommand = args[0].upper()
            limit = min(20, max(1, int(args[-1])))
            if subcommand == "TARGETS" and len(args) == 4:
                self.targets(args[1], args[2], limit, label)
                return
            if subcommand not in ("LATEST", "BEFORE") or len(args) != 4:
                raise ValueError("unsupported CHATHISTORY syntax")
            target, selector = args[1:3]
            if target == options["invalid_target"] or target not in fixture.rows:
                self.failure(subcommand, "INVALID_TARGET", "Target is unavailable", label)
                return
            rows = fixture.visible_rows(target)
            eligible = rows
            if selector.startswith("msgid="):
                if options["reject_msgids"]:
                    options["reject_msgids"] -= 1
                    self.failure(subcommand, options["reject_code"], "Reference is unavailable", label)
                    return
                index = next((i for i, row in enumerate(rows) if row["msgid"] == selector[6:]), None)
                if index is None:
                    self.failure(subcommand, "INVALID_MSGID", "Reference is unavailable", label)
                    return
                eligible = rows[:index] if subcommand == "BEFORE" else rows[index + 1:]
            elif selector != "*":
                timestamp = history_timestamp(selector)
                eligible = [row for row in rows if
                            ((row["timestampMs"] <= timestamp if options["clipped_boundary"]
                              else row["timestampMs"] < timestamp) if subcommand == "BEFORE"
                             else row["timestampMs"] > timestamp)]
            elif subcommand != "LATEST":
                raise ValueError("only LATEST accepts wildcard")
            short = options["short_pages"] > 0
            if short:
                options["short_pages"] -= 1
                limit = min(limit, options["short_limit"])
            chosen = eligible[-limit:]
            forced_empty = options["empty_pages"] > 0
            if forced_empty:
                options["empty_pages"] -= 1
                chosen = []
            # A clipped timestamp-only boundary is intentionally not a proof of
            # exhaustion: the server cannot represent the remaining tie group.
            end = not forced_empty and not short and len(eligible) <= limit
            if options["clipped_boundary"]:
                end = False
            root, opening, closing = self.envelope("chathistory", target, label)
            content = []
            late_closes = []
            malformed = options["malformed"]
            options["malformed"] = "none"
            if malformed == "duplicate":
                content.append(f":{SERVER} BATCH +{root} chathistory {target}")
            elif malformed == "missing_parent":
                orphan = fixture.next_ref("orphan")
                content.append(f"@batch=fixture-absent :{SERVER} BATCH +{orphan} chathistory {target}")
                root = orphan
                closing.insert(0, f":{SERVER} BATCH -{orphan}")
            elif malformed == "cycle":
                a, b = fixture.next_ref("cycle"), fixture.next_ref("cycle")
                content += [f"@batch={b} :{SERVER} BATCH +{a} chathistory {target}",
                            f"@batch={a} :{SERVER} BATCH +{b} fixture/ancestor"]
                root = b
                closing = [f":{SERVER} BATCH -{b}", f":{SERVER} BATCH -{a}"] + closing
            elif malformed in ("premature_close", "unclosed_child"):
                child = fixture.next_ref("unclosed")
                content.append(f"@batch={root} :{SERVER} BATCH +{child} fixture/ancestor")
                if malformed == "premature_close":
                    content.append(f":{SERVER} BATCH -{root}")
                    closing = [line for line in closing if line != f":{SERVER} BATCH -{root}"]
                root = child
                # The child deliberately remains open until explicit resume.
                late_closes = [f":{SERVER} BATCH -{child}"]
            if options["context"] and chosen:
                position = next(i for i, row in enumerate(rows) if row["index"] == chosen[0]["index"])
                if position:
                    content += self.row_lines(rows[position - 1], root, context=True)
            for index, row in enumerate(chosen):
                content += self.row_lines(row, root, multiline=(
                    options["multiline"] and "draft/multiline" in self.enabled and index == 0))
            if end and options["end_markers"] and malformed == "none":
                opening[-1] = history_tag(opening[-1], "draft/chathistory-end")
            fixture.record({"request": args, "label": label, "batch": root,
                            "msgids": [row["msgid"] for row in chosen],
                            "indices": [row["index"] for row in chosen],
                            "end": end, "short": short, "malformed": malformed,
                            "timeout": options["timeout"], "pauseAfter": options["pause_after"]})
            if options["timeout"] == "silent":
                self.pending.append(opening + content + closing + late_closes)
                return
            for line in opening:
                self.send(line)
            if options["pause_after"]:
                count = options["pause_after"]
                self.pending.append(content[count:] + closing + late_closes)
                content = content[:count]
                closing = []
                late_closes = []
            for index, line in enumerate(content):
                self.send(line)
                if options["live"] and index == 0:
                    self.emit_live()
            if options["timeout"] == "open":
                self.pending.append(closing + late_closes)
            else:
                for line in closing:
                    self.send(line)
                if late_closes:
                    self.pending.append(late_closes)
        except (ValueError, IndexError, OverflowError):
            self.failure(args[0] if args else "*", "INVALID_PARAMS", "Invalid history request", label)

    def targets(self, lower, upper, limit, label):
        start, stop = history_timestamp(lower), history_timestamp(upper)
        reverse = start > stop
        low, high = sorted((start, stop))
        # Filter by each target's actual latest row, not its latest in range.
        entries = [(target, max(row["timestampMs"] for row in rows))
                   for target in self.fixture.rows
                   if (rows := self.fixture.visible_rows(target))]
        entries = [(target, ts) for target, ts in entries if low <= ts <= high]
        entries.sort(key=lambda item: (item[1], item[0]), reverse=reverse)
        chosen = entries[:limit]
        # Include every boundary tie, even if that exceeds the advertised limit.
        if chosen:
            chosen += [item for item in entries[limit:] if item[1] == chosen[-1][1]]
        root, opening, closing = self.envelope("draft/chathistory-targets", "", label)
        end = len(chosen) == len(entries)
        if end and self.fixture.options["end_markers"]:
            opening[-1] = history_tag(opening[-1], "draft/chathistory-end")
        for line in opening:
            self.send(line)
        for target, timestamp in chosen:
            self.send(f"@batch={root} :{SERVER} CHATHISTORY TARGETS {target} {history_time(timestamp)}")
        for line in closing:
            self.send(line)
        self.fixture.record({"request": ["TARGETS", lower, upper, str(limit)],
                             "targets": [name for name, _ in chosen], "end": end})


history_fixture = HistoryFixture() if HISTORY_ENABLED else None

accepted = []  # (remote_port, inode)
lock = threading.Lock()


def write_result():
    # Concurrent connections write the same result file during failover.
    # Serialize the temp-file rename so one thread cannot steal another's.
    with lock:
        distinct = len(set(accepted))
        verdict = "PASS" if distinct <= 1 else "FAIL"
        text = f"{verdict}\naccepted={accepted}\ndistinct={distinct}\n"
        tmp = RESULT_FILE + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, RESULT_FILE)
        return text


def record_line(text, nick=None):
    with lock:
        with open(LINES_FILE, "a") as f:
            f.write(text + "\n")
        if (os.environ.get("MOCK_IRC_TARGET_INJECT") == "1" and nick
                and all(c.isalnum() or c in "_-" for c in nick)):
            with open(LINES_FILE + ".target." + nick, "a") as f:
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


def targeted_inject_loop(conn, stop, current_nick):
    """Opt-in per-nick wire injection; never consume another live socket's file."""
    while not stop.is_set():
        nick = current_nick()
        if nick and all(c.isalnum() or c in "_-" for c in nick):
            path = INJECT_FILE + ".target." + nick
            try:
                with open(path, "rb") as f:
                    data = f.read()
                os.remove(path)
                if data:
                    print(f"mock_irc: target inject {nick}: {data!r}", flush=True)
                    conn.sendall(data)
            except FileNotFoundError:
                pass
            except OSError as e:
                print(f"mock_irc: target inject error {nick}: {e}", flush=True)
        stop.wait(0.2)


def inject_loop(conn, stop, history=None):
    """Write INJECT_FILE's contents to the connection whenever it appears."""
    while not stop.is_set():
        if os.path.exists(INJECT_FILE):
            try:
                with open(INJECT_FILE, "rb") as f:
                    data = f.read()
                if not history:
                    os.remove(INJECT_FILE)
                if data:
                    print(f"mock_irc: inject: {data!r}", flush=True)
                    if history:
                        history.raw_inject(data)
                    else:
                        conn.sendall(data)
                if history:
                    # For controls, disappearance acknowledges application,
                    # not just a read racing the next CHATHISTORY request.
                    os.remove(INJECT_FILE)
            except (OSError, ValueError, TypeError) as e:
                print(f"mock_irc: inject error: {e}", flush=True)
        time.sleep(0.2)


def handle(conn, addr, ino):
    print(f"mock_irc: accepted {addr} inode={ino}", flush=True)
    accepted.append((addr[1], ino))
    print(f"mock_irc: result: {write_result().strip()}", flush=True)
    stop = threading.Event()
    history = HistorySession(history_fixture, conn) if history_fixture else None
    threading.Thread(target=inject_loop, args=(conn, stop, history), daemon=True).start()
    nick = None
    if os.environ.get("MOCK_IRC_TARGET_INJECT") == "1":
        threading.Thread(target=targeted_inject_loop,
                         args=(conn, stop, lambda: nick), daemon=True).start()
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
                record_line(text, nick)
                parts = text.split(" ")
                cmd = parts[0].upper() if parts else ""
                if history and history.handle(text):
                    pass
                elif cmd == "CAP" and len(parts) > 1 and parts[1].upper() == "LS":
                    send(conn, "CAP * LS :")
                elif cmd == "NICK" and len(parts) > 1:
                    nick = parts[1].lstrip(":")
                    if history:
                        history.nick = nick
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
                if not welcomed and nick and user_seen and (not history or history.registration_ready):
                    welcomed = True
                    if history:
                        with history.send_lock:
                            send(conn, f":{SERVER} 001 {nick} :Welcome to the holder mock IRC {nick}!u@mock")
                            send(conn, f":{SERVER} 002 {nick} :Your host is {SERVER}, running version mock-history-1")
                            send(conn, f":{SERVER} 005 {nick} CHATHISTORY=20 MSGREFTYPES=msgid,timestamp CASEMAPPING=rfc1459 CHANTYPES=# MONITOR=100 :are supported by this server")
                            send(conn, f":{SERVER} 376 {nick} :End of MOTD")
                    else:
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
