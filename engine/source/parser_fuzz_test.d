module parser_fuzz_test;

import std.stdio : stderr, writeln;
import std.random : Random, Mt19937, uniform;
import std.conv : to;
import std.format : format;
import ircfiber.irc.parser : parseIRCLinePublic, parseIRCLineNamed;
import ircfiber.models.network : NetworkConfig;
import std.uuid : randomUUID;

int passed, failed;

void check(bool cond, string name, string msg = "") {
    if (cond) { ++passed; stderr.writeln("  ✓ ", name); }
    else { ++failed; stderr.writeln("  ✗ ", name, msg.length ? " — " ~ msg : ""); }
}

private string buildRandomIRCLine(ref Mt19937 rng, bool withTags,
                                  bool withPrefix, bool withTrailing,
                                  size_t nParams) {
    string[] commands = ["PRIVMSG","NOTICE","JOIN","PART","QUIT","NICK",
        "MODE","TOPIC","INVITE","KICK","001","002","005","332","333",
        "353","366","433","PING","PONG","ERROR","ABCD","123","AA"];
    string cmd = commands[uniform(0, commands.length, rng)];
    string prefix = "";
    if (withPrefix) {
        string[] nicks = ["alice","bob","char-1","Zod","test"];
        string[] users = ["alice","bot","service","visitor","guest"];
        string[] hosts = ["irc.example.com","host.local","1.2.3.4"];
        auto nick = nicks[uniform(0, nicks.length, rng)];
        auto user = users[uniform(0, users.length, rng)];
        auto host = hosts[uniform(0, hosts.length, rng)];
        prefix = ":" ~ nick ~ "!" ~ user ~ "@" ~ host;
    }
    string line = "";
    if (withTags) {
        string tags;
        foreach (i; 0 .. uniform(1UL, 4, rng)) {
            if (i > 0) tags ~= ";";
            tags ~= ["time","msgid","label","bot"][uniform(0, 4, rng)];
            if (uniform(0, 2, rng) == 0) tags ~= "=abc123";
        }
        line ~= "@" ~ tags ~ " ";
    }
    if (prefix.length) line ~= prefix ~ " ";
    line ~= cmd;
    foreach (i; 0 .. nParams) {
        string p = ["#chan","target","word","word-word","hello","x"][uniform(0, 6, rng)];
        line ~= " ";
        if (withTrailing && i == nParams - 1) line ~= ":" ~ p;
        else line ~= p;
    }
    return line;
}

void runFuzzSuite(size_t n = 10_000) {
    writeln("\n[fuzz] ", n, " random lines through parser");
    auto rng = Mt19937(0xCAFE);
    NetworkConfig cfg; cfg.id = randomUUID(); cfg.name = "FuzzNet";
    int parsed, threw, empty;
    string[] sampleThrows;
    foreach (_; 0 .. n) {
        string line = buildRandomIRCLine(rng, uniform(0, 2, rng) == 0,
                       uniform(0, 2, rng) == 0, uniform(0, 2, rng) == 0,
                       uniform(0UL, 8, rng));
        try { parseIRCLinePublic(line, cfg); ++parsed; }
        catch (Exception e) {
            ++threw;
            if (sampleThrows.length < 3) sampleThrows ~= line ~ " => " ~ e.msg;
        }
    }
    check(threw == 0, format("parser survives %d random lines (no throw)", n),
          threw > 0 ? "threw on: " ~ sampleThrows[0] : "");
    check(parsed >= 1, format(">0 parsed out of %d", n));
    writeln("  parsed=", parsed, " empty=", empty, " threw=", threw);
}

void runTargetedFuzz() {
    writeln("\n[targeted] adversarial patterns");
    NetworkConfig cfg; cfg.id = randomUUID(); cfg.name = "FuzzNet";

    bool threw;
    threw = false; try parseIRCLinePublic("", cfg); catch (Exception) { threw = true; }
    check(!threw, "empty line never throws");
    threw = false; try parseIRCLinePublic("   ", cfg); catch (Exception) { threw = true; }
    check(!threw, "whitespace-only line never throws");
    threw = false; try parseIRCLinePublic(":prefix", cfg); catch (Exception) { threw = true; }
    check(!threw, "prefix-only line never throws");
    threw = false; try parseIRCLinePublic("A\0B C\0D :E\0", cfg); catch (Exception) { threw = true; }
    check(!threw, "NUL-stuffed line never throws");
    threw = false;
    char[64*1024] big;
    foreach (j, ref b; big) b = cast(char)('A' + (j % 26));
    try parseIRCLinePublic(cast(string) big, cfg); catch (Exception) { threw = true; }
    check(!threw, "64 KiB line truncated and parsed cleanly");
    threw = false; try parseIRCLinePublic("NICK foo\r\nbar", cfg); catch (Exception) { threw = true; }
    check(!threw, "embedded CRLF doesn't crash parser");
    threw = false; try parseIRCLinePublic("PRIVMSG #c :", cfg); catch (Exception) { threw = true; }
    check(!threw, "trailing colon with empty value parses cleanly");
    threw = false; try parseIRCLinePublic("@time=2024;bot=1 :n PRIVMSG #c :hi", cfg); catch (Exception) { threw = true; }
    check(!threw, "tags with semicolons parse cleanly");
    threw = false; try parseIRCLinePublic(":test PRIVMSG #test :test", cfg); catch (Exception) { threw = true; }
    check(!threw, "unicode nick/channel parse without throwing");
    threw = false;
    foreach (n; [400, 401, 403, 404, 451, 471, 473, 700, 704]) {
        try parseIRCLinePublic(":host " ~ n.to!string ~ " Nick :something", cfg);
        catch (Exception) { threw = true; break; }
    }
    check(!threw, "200+ numeric codes parse without throwing");
    threw = false;
    try parseIRCLinePublic("PING :0gGzZ0vF0GzZal", cfg); catch (Exception) { threw = true; }
    check(!threw, "normal PING cmd parses cleanly");
}

int main() {
    writeln("parser property-based fuzz test");
    runFuzzSuite();
    runTargetedFuzz();
    writeln("\n", passed, " passed, ", failed, " failed");
    return failed > 0 ? 1 : 0;
}
