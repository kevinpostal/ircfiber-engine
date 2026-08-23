module buffer_dedup_test;

import std.path : dirName, buildPath;
import std.file : readText;
import std.string : indexOf;
import std.stdio : writeln;

string thisDir() {
    return dirName(__FILE__);
}

void main() {
    string bufPath = buildPath(thisDir, "..", "source", "ircfiber", "storage", "buffer.d");
    string connPath = buildPath(thisDir, "..", "..", "engine", "source", "ircfiber", "irc", "connection.d");
    // fallback for when run from project root
    import std.file : exists;
    if (!exists(bufPath)) bufPath = "common/source/ircfiber/storage/buffer.d";
    if (!exists(connPath)) connPath = "engine/source/ircfiber/irc/connection.d";
    string bufSrc = readText(bufPath);
    assert(bufSrc.indexOf("~ event.nick") != -1, "buffer.d must include nick in dedup hash");
    assert(bufSrc.indexOf("~ event.text") != -1, "buffer.d must include text in dedup hash");
    string connSrc = readText(connPath);
    assert(connSrc.indexOf("total!\"msecs\"") != -1, "connection.d must use msecs");
    writeln("buffer dedup regression: PASS (nick+text in hash, msecs in resolveTimestamp)");
}

version(unittest) {
    unittest {
        string bufPath = buildPath(dirName(__FILE__), "..", "source", "ircfiber", "storage", "buffer.d");
        import std.file : exists;
        if (!exists(bufPath)) bufPath = "common/source/ircfiber/storage/buffer.d";
        string bufSrc = readText(bufPath);
        assert(bufSrc.indexOf("~ event.nick") != -1);
        assert(bufSrc.indexOf("~ event.text") != -1);
    }
    unittest {
        string connPath = buildPath(dirName(__FILE__), "..", "..", "engine", "source", "ircfiber", "irc", "connection.d");
        import std.file : exists;
        if (!exists(connPath)) connPath = "engine/source/ircfiber/irc/connection.d";
        string connSrc = readText(connPath);
        assert(connSrc.indexOf("total!\"msecs\"") != -1);
    }
}
