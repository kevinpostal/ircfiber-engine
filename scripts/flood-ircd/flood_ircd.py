#!/usr/bin/env python3
"""Minimal ircd that reproduces InspIRCd 4's command-penalty flood model.

Our own network runs InspIRCd 4 and gives the engine's connect class

    <connect ... fakelag="no" commandrate="100000" threshold="100">

which is NOT "unlimited", and is not the UnrealIRCd model the engine used to
guess at. The three knobs mean:

  * ``commandrate`` is in **millicommands per second** — 100000 is 100
    commands/second sustained, i.e. the penalty counter drains at
    ``commandrate / 1000`` points per second;
  * ``threshold`` is a burst allowance in **command penalty points**. Every
    command costs 1 point (``OPER`` costs 10), so a client may fire
    ``threshold`` commands back to back and then must stay under the drain
    rate;
  * ``fakelag="no"`` does **not** disable the limit — it disables the
    *delaying*. With fakelag on, InspIRCd holds the client's input until the
    penalty has drained; with fakelag off it KILLS the connection with
    ``Excess Flood`` the moment the penalty passes the threshold. That kill is
    the failure mode the engine's client-side pacer has to make impossible.

So this rig exists to answer one question with numbers: at what send cadence
does the engine survive, and does it survive at all? Every PRIVMSG it receives
is printed with a monotonic offset from the client's first PRIVMSG, so a run
log is directly a throughput measurement:

    [msg] 300 t=3.331 len=44 target=#flood
    [ircd] client done nick=pacer privmsgs=300 span=3.331 rate=90.06/s peak_penalty=13.0

Nothing here is a general-purpose ircd: it answers exactly enough of the
protocol for a real client to register, join a channel and believe it is an op,
and it never disconnects for anything except the flood model.
"""
import argparse
import signal
import socket
import sys
import threading
import time

HOST_NAME = 'flood.test'

# Capability list shaped like our real ircd's: InspIRCd 4 with the modules we
# actually load. `draft/multiline` is deliberately ABSENT — prod does not have
# it, so a client that batches long pastes into multiline must not be able to
# discover it here and pace itself against a capability it will never get.
CAPS = (
    'inspircd.org/poison inspircd.org/stats-tags batch message-tags '
    'server-time echo-message labeled-response multi-prefix away-notify '
    'account-notify extended-join'
)

# Commands that cost more than one point. InspIRCd charges OPER heavily
# because it is the one command worth brute-forcing.
PENALTY = {'OPER': 10}

clients_lock = threading.Lock()
clients = []


class Client:
    """Per-connection flood state plus the PRIVMSG measurement counters."""

    def __init__(self, conn, addr, opts):
        self.conn = conn
        self.addr = addr
        self.opts = opts
        self.nick = '*'
        self.registered = False
        self.penalty = 0.0
        self.peak_penalty = 0.0
        self.last_tick = time.monotonic()
        self.lines = 0
        self.privmsgs = 0
        self.first_line_at = None
        self.first_privmsg_at = None
        self.last_privmsg_at = None
        self.held = False
        self.killed = False
        self.summarised = False

    # -- flood model ------------------------------------------------------

    def drain(self, now):
        """Bleed off the penalty accrued since the last command."""
        elapsed = now - self.last_tick
        self.last_tick = now
        if elapsed > 0:
            self.penalty -= elapsed * (self.opts.commandrate / 1000.0)
            if self.penalty < 0.0:
                self.penalty = 0.0

    def charge(self, cmd):
        """Bill one command. Returns True when the client may be processed.

        False means the connection has been killed (fakelag off) — InspIRCd
        with `fakelag="no"` closes the link instead of throttling.
        """
        now = time.monotonic()
        self.drain(now)
        self.penalty += PENALTY.get(cmd, 1)
        if self.penalty > self.peak_penalty:
            self.peak_penalty = self.penalty
        if self.penalty <= self.opts.threshold:
            return True

        span = now - (self.first_line_at or now)
        if not self.opts.fakelag:
            print('[ircd] EXCESS FLOOD nick=%s after=%d lines t=%.3f'
                  % (self.nick, self.lines, span), flush=True)
            self.send('ERROR :Closing Link: %s[%s] (Excess Flood)' % (self.nick, HOST_NAME))
            self.killed = True
            return False

        # fakelag on: stall the client's input until the penalty has drained
        # back under the threshold. InspIRCd does this by simply not reading
        # the socket, which from the client's side is indistinguishable from
        # a slow server.
        if not self.held:
            self.held = True
            print('[ircd] fakelag hold nick=%s after=%d lines t=%.3f penalty=%.1f'
                  % (self.nick, self.lines, span, self.penalty), flush=True)
        while self.penalty > self.opts.threshold:
            time.sleep(0.005)
            self.drain(time.monotonic())
        return True

    # -- io ---------------------------------------------------------------

    def send(self, line):
        try:
            self.conn.sendall((line + '\r\n').encode())
        except Exception:
            pass

    def numeric(self, num, rest):
        self.send(':%s %s %s %s' % (HOST_NAME, num, self.nick, rest))

    # -- measurement ------------------------------------------------------

    def summary(self):
        if self.summarised:
            return
        self.summarised = True
        if self.first_privmsg_at is not None and self.last_privmsg_at is not None:
            span = self.last_privmsg_at - self.first_privmsg_at
        else:
            span = 0.0
        rate = (self.privmsgs / span) if span > 0 else 0.0
        print('[ircd] client done nick=%s privmsgs=%d span=%.3f rate=%.2f/s peak_penalty=%.1f'
              % (self.nick, self.privmsgs, span, rate, self.peak_penalty), flush=True)


def welcome(c):
    """The registration burst, shaped like InspIRCd 4's."""
    c.registered = True
    c.numeric('001', ':Welcome to the FloodTest IRC Network %s!%s@%s'
              % (c.nick, c.nick, HOST_NAME))
    c.numeric('002', ':Your host is %s, running version InspIRCd-4' % HOST_NAME)
    c.numeric('003', ':This server was created 12:00:00 Jan 01 2026')
    # 004 carries the version and mode letters as leading parameters, with no
    # trailing at all — the same shape prod sends.
    c.send(':%s 004 %s %s InspIRCd-4 iosw biklmnopstv bklov'
           % (HOST_NAME, c.nick, HOST_NAME))
    c.numeric('005', 'NETWORK=FloodTest NICKLEN=32 CHANNELLEN=64 :are supported by this server')
    c.numeric('375', ':%s message of the day' % HOST_NAME)
    c.numeric('372', ':- flood rig: commandrate=%d threshold=%d fakelag=%s'
              % (c.opts.commandrate, c.opts.threshold, 'on' if c.opts.fakelag else 'off'))
    c.numeric('376', ':End of message of the day.')


def handle(c, line):
    parts = line.split(' ')
    cmd = parts[0].upper()
    args = parts[1:]

    if cmd == 'CAP':
        sub = args[0].upper() if args else ''
        if sub == 'LS':
            c.send(':%s CAP * LS :%s' % (HOST_NAME, CAPS))
        elif sub == 'REQ':
            # ACK whatever was asked for: the engine's negotiation must not
            # stall on an unanswered REQ, and what it ends up with is its own
            # business.
            want = line.split(':', 1)[1] if ':' in line else ' '.join(args[1:])
            c.send(':%s CAP %s ACK :%s' % (HOST_NAME, c.nick, want.strip()))
        elif sub == 'END':
            pass
        return

    if cmd == 'NICK':
        c.nick = args[0].lstrip(':') if args else 'x'
        return
    if cmd == 'USER':
        if c.nick != '*' and not c.registered:
            welcome(c)
        return
    if cmd == 'PASS':
        return
    if cmd == 'PING':
        tok = line.split(' ', 1)[1].lstrip(':') if ' ' in line else HOST_NAME
        c.send(':%s PONG :%s' % (HOST_NAME, tok))
        return
    if cmd == 'PONG':
        return
    if cmd == 'QUIT':
        c.killed = True
        return

    if cmd == 'JOIN':
        for chan in (args[0] if args else '').lstrip(':').split(','):
            chan = chan.strip()
            if not chan:
                continue
            c.send(':%s!%s@%s JOIN %s' % (c.nick, c.nick, HOST_NAME, chan))
            # @<nick>: the client is told it is an op so it takes whatever
            # op-only path it has (e.g. skipping +m/+f self-throttling).
            c.numeric('353', '= %s :@%s' % (chan, c.nick))
            c.numeric('366', '%s :End of /NAMES list.' % chan)
            c.numeric('324', '%s +nt' % chan)
            print('[ircd] joined %s nick=%s' % (chan, c.nick), flush=True)
        return

    if cmd == 'MODE':
        target = args[0] if args else c.nick
        if target.startswith('#'):
            c.numeric('324', '%s +nt' % target)
        else:
            c.numeric('221', '+iw')
        return
    if cmd == 'WHO':
        target = args[0] if args else c.nick
        c.numeric('352', '%s %s %s %s %s H@ :0 %s'
                  % (target, c.nick, HOST_NAME, HOST_NAME, c.nick, c.nick))
        c.numeric('315', '%s :End of /WHO list.' % target)
        return
    if cmd == 'WHOIS':
        who = args[0] if args else c.nick
        c.numeric('311', '%s %s %s * :%s' % (who, who, HOST_NAME, who))
        c.numeric('312', '%s %s :FloodTest' % (who, HOST_NAME))
        c.numeric('318', '%s :End of /WHOIS list.' % who)
        return
    if cmd == 'USERHOST':
        who = args[0] if args else c.nick
        c.numeric('302', ':%s=+%s@%s' % (who, who, HOST_NAME))
        return
    if cmd == 'AWAY':
        c.numeric('306' if args else '305', ':You have been marked as being away'
                  if args else ':You are no longer marked as being away')
        return
    if cmd == 'TOPIC':
        chan = args[0] if args else '#chan'
        c.numeric('331', '%s :No topic is set.' % chan)
        return

    if cmd == 'PRIVMSG' or cmd == 'NOTICE':
        target = args[0] if args else '*'
        text = line.split(' :', 1)[1] if ' :' in line else ''
        if cmd == 'NOTICE':
            return
        now = time.monotonic()
        if c.first_privmsg_at is None:
            c.first_privmsg_at = now
        c.last_privmsg_at = now
        c.privmsgs += 1
        print('[msg] %d t=%.3f len=%d target=%s'
              % (c.privmsgs, now - c.first_privmsg_at, len(text), target), flush=True)
        return

    # Anything else is acknowledged as unknown rather than fatal: this rig
    # must only ever kill a client for the flood model.
    c.numeric('421', '%s :Unknown command' % cmd)


def serve_client(conn, addr, opts):
    c = Client(conn, addr, opts)
    with clients_lock:
        clients.append(c)
    print('[ircd] connection from %s' % (addr,), flush=True)
    conn.settimeout(300)
    f = conn.makefile('rb', buffering=0)
    last_ping = time.monotonic()
    try:
        while not c.killed:
            try:
                raw = f.readline()
            except socket.timeout:
                raw = b''
            except Exception:
                break
            if not raw:
                break
            line = raw.decode('utf-8', 'replace').strip()
            if not line:
                continue
            if line.startswith('@'):
                # Strip a message-tag prefix; the flood model bills the command.
                line = line.split(' ', 1)[1] if ' ' in line else ''
                if not line:
                    continue
            c.lines += 1
            if c.first_line_at is None:
                c.first_line_at = time.monotonic()
            cmd = line.split(' ', 1)[0].upper()
            if not c.charge(cmd):
                break
            handle(c, line)
            now = time.monotonic()
            if now - last_ping >= 60.0:
                last_ping = now
                c.send('PING :%d' % int(now))
    except Exception as e:
        import traceback
        print('[ircd] client thread died: %r' % (e,), flush=True)
        traceback.print_exc()
    finally:
        c.summary()
        with clients_lock:
            if c in clients:
                clients.remove(c)
        try:
            conn.close()
        except Exception:
            pass


def on_signal(signum, frame):
    # A run is normally ended by killing the rig, so the summaries have to be
    # reachable from a signal — the parent reads them out of the process log.
    print('[ircd] signal %d, summarising %d client(s)' % (signum, len(clients)), flush=True)
    with clients_lock:
        live = list(clients)
    for c in live:
        c.summary()
    sys.exit(0)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog='flood_ircd.py',
        description='Fake ircd reproducing InspIRCd 4 command-penalty flood limits.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Prod engine class: --commandrate 100000 --threshold 100 --fakelag off',
    )
    p.add_argument('--port', type=int, default=16691,
                   help='TCP port to listen on (default: 16691)')
    p.add_argument('--bind', default='0.0.0.0',
                   help='address to bind; 0.0.0.0 so a container can reach it (default: 0.0.0.0)')
    p.add_argument('--commandrate', type=int, default=100000,
                   help='InspIRCd commandrate in MILLIcommands/second; the penalty '
                        'counter drains at commandrate/1000 points per second '
                        '(default: 100000 = 100 commands/s)')
    p.add_argument('--threshold', type=int, default=100,
                   help='InspIRCd threshold: burst allowance in command penalty '
                        'points, 1 point per command, 10 for OPER (default: 100)')
    p.add_argument('--fakelag', choices=('on', 'off'), default='off',
                   help="InspIRCd fakelag. 'off' KILLS the client with Excess Flood "
                        "on threshold (what prod does); 'on' delays its input "
                        'until the penalty drains (default: off)')
    opts = p.parse_args(argv)
    opts.fakelag = (opts.fakelag == 'on')
    return opts


def main():
    opts = parse_args()
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((opts.bind, opts.port))
    s.listen(8)
    print('[ircd] listening on %s:%d (commandrate=%d millicmd/s -> %.1f cmd/s drain, '
          'threshold=%d points, fakelag=%s)'
          % (opts.bind, opts.port, opts.commandrate, opts.commandrate / 1000.0,
             opts.threshold, 'on' if opts.fakelag else 'off'), flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=serve_client, args=(conn, addr, opts), daemon=True).start()


if __name__ == '__main__':
    main()
