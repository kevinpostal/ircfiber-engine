/**
 * Versioned, locale-aware Anope reply grammar for the actual-user services
 * adapters (unit 3).
 *
 * Anope sends a reply in the target account's language: the English source
 * string (`_("...")`, the catalog msgid) or any non-fuzzy translation the
 * network's services shipped, with plural forms chosen by count. The
 * language can change mid-session and is never ours to change, so a reply is
 * recognised against the UNION of English and every shipped translation of
 * the exact source message, per supported release:
 *
 *  - upstream Anope 2.0.20 (tag commit 12f1ebee), and
 *  - the managed fork 2.1.27-git (commit f6e46425, pinned in
 *    site/deploy/roles/ircd/files/Containerfile.anope).
 *
 * The catalogs are the releases' own `language/anope.*.po`, compiled
 * unmodified with `msgfmt -c` exactly like Anope's build (fuzzy and
 * untranslated entries dropped, every plural form kept) and embedded as data
 * (catalogs/anope, GPL-2, see catalogs/anope/SOURCE.txt). Runtime candidates
 * use these as decoders only; recognized replies and HELP establish compatibility.
 *
 * Matching rules (all fail closed — a false/absent result is never success):
 *  - Text is compared after IRC formatting is removed (`\x1B`, Anope's
 *    no-break marker, becomes a space). Operation code passes the msgid as
 *    written in the Anope source, formatting included.
 *  - Templates are anchored: the whole (joined) reply must match. printf
 *    conversions (`%s %d %u %zu %lu %lld %i %c %x %.2Lf`, widths, `%%`,
 *    positional `%2$s`) and 2.1 flexible-layout `{key}` templates
 *    (`Anope::Template`, `{}` = literal `{`) become captures, returned in the
 *    ENGLISH argument order even when a translation reorders them.
 *  - A translated string shared by a different source message (translators
 *    reuse wording: de "%s wurde nach %s eingeladen." is both "has been
 *    invited" and "has no access") is contested: it never matches.
 *  - Several parses of one reply (`%s is %s` against "a is b is c"), a
 *    translation that omits an argument, or several occurrences that
 *    disagree are ambiguous: `matches` is false (`has` may still be true for
 *    the first two).
 *  - 2.0 splits a reply only on `\n` in the string; 2.1 additionally wraps
 *    at `options:linelength` on spaces (`LineWrapper`), so a 2.1 message may
 *    span consecutive lines joined by one space. Frames only join lines that
 *    share the same reply correlation and NOTICE/PRIVMSG command, and prefer
 *    the fewest lines. A message whose last token is free text (`...: %s`)
 *    therefore captures the shortest reading of that trailing text.
 *  - Anope 2.1's wrapper drops characters in two edge cases (a word longer
 *    than the line length; formatting carried into a line that wraps again).
 *    Such replies do not match and stay unconfirmed.
 *
 * Table grammar (fixed/flexible/monospace list layouts) belongs to each
 * operation; this module supplies translated templates, row keys and the
 * INFO `Key: value` reader.
 */
module ircfiber.irc.services_grammar;

import std.algorithm : canFind;
import std.array : split;
import std.concurrency : initOnce;
import std.exception : enforce;

import ircfiber.irc.services : ServiceFrame, ServiceReplyLine, stripIrcFormatting;

// ── Releases ───────────────────────────────────────────────────────────────

/// Anope releases whose command grammar and catalogs ship with the engine.
enum AnopeRelease : ubyte {
    unknown,
    /// Upstream 2.0.20 (12f1ebee1c03c1a71ecb7f6c3a1d853f97625bea).
    v2_0_20,
    /// Managed fork 2.1.27-git (f6e46425b6747e1b34ff939ca5e8d6028cd4dae3).
    v2_1_pinned
}

/// `Anope::Version()` of the supported releases (`VERSION_EXTRA` included).
enum string ANOPE_20_VERSION = "Anope-2.0.20";
enum string ANOPE_21_VERSION = "Anope-2.1.27-git";
/// `VERSION_GIT` (7 hex) a build from a checked-out branch would append.
enum string ANOPE_20_GIT = "12f1ebe";
enum string ANOPE_21_GIT = "f6e4642";

/**
 * Classifies a pseudoclient's CTCP VERSION text.
 *
 * 2.1 (`bots.cpp`): `Anope-<ver>[ (<git>)] <build string> -- <proto> -- <enc>`.
 * 2.0 (`messages.cpp`): `VERSION Anope-<ver>[ (<git>)] <server> :<proto> - (<enc>) -- <build>`.
 * A leading `VERSION ` is accepted either way. The version token must be
 * exact (a different patch level, suffix or git commit is unknown).
 */
AnopeRelease anopeRelease(string versionText) @safe pure nothrow @nogc {
    string s = trimSpaces(versionText);
    enum head = "VERSION ";
    if (s.length >= head.length && s[0 .. head.length] == head) s = trimSpaces(s[head.length .. $]);
    if (releaseHead(s, ANOPE_21_VERSION, ANOPE_21_GIT)) return AnopeRelease.v2_1_pinned;
    if (releaseHead(s, ANOPE_20_VERSION, ANOPE_20_GIT)) return AnopeRelease.v2_0_20;
    return AnopeRelease.unknown;
}

/// Selects a decoder family, not an exact source identity or capability.
AnopeRelease anopeCandidateRelease(string versionText) @safe pure nothrow @nogc {
    string s = trimVersionWhitespace(versionText);
    enum head = "VERSION ";
    if (startsWithBytes(s, head)) s = trimVersionWhitespace(s[head.length .. $]);
    enum prefix = "Anope-2.";
    if (!startsWithBytes(s, prefix) || s.length <= prefix.length + 2) return AnopeRelease.unknown;
    const minor = s[prefix.length];
    if ((minor != '0' && minor != '1') || s[prefix.length + 1] != '.') return AnopeRelease.unknown;
    size_t i = prefix.length + 2;
    const patchStart = i;
    while (i < s.length && s[i] >= '0' && s[i] <= '9') ++i;
    if (i == patchStart) return AnopeRelease.unknown;
    if (i < s.length && s[i] == '-') {
        const suffixStart = ++i;
        while (i < s.length) {
            const c = s[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '+' || c == '-')) break;
            ++i;
        }
        if (i == suffixStart) return AnopeRelease.unknown;
    }
    if (i != s.length && s[i] != ' ') return AnopeRelease.unknown;
    return minor == '0' ? AnopeRelease.v2_0_20 : AnopeRelease.v2_1_pinned;
}

/// Constructs the advertised family's decoder without inventing a VERSION.
AnopeGrammar candidateAnopeGrammar(string versionText) {
    return new AnopeGrammar(anopeCandidateRelease(versionText));
}

private string trimVersionWhitespace(string s) @safe pure nothrow @nogc {
    bool whitespace(char c) @safe pure nothrow @nogc {
        return c == ' ' || (c >= '\t' && c <= '\r');
    }
    size_t start, end = s.length;
    while (start < end && whitespace(s[start])) ++start;
    while (end > start && whitespace(s[end - 1])) --end;
    return s[start .. end];
}

private bool releaseHead(string s, string version_, string git) @safe pure nothrow @nogc {
    if (s.length < version_.length || s[0 .. version_.length] != version_) return false;
    const rest = s[version_.length .. $];
    if (!rest.length) return true;
    if (rest[0] != ' ') return false;
    if (rest.length >= 2 && rest[1] == '(') {
        // ` (<git>)` must name the pinned commit.
        return rest.length >= git.length + 3 && rest[2 .. 2 + git.length] == git && rest[2 + git.length] == ')';
    }
    return true;
}

// ── Text helpers ───────────────────────────────────────────────────────────

/// Formatting-free text; returns `s` itself when there is nothing to strip.
string normalizeServiceText(string s) @safe pure nothrow {
    foreach (char c; s) {
        switch (c) {
            case '\x02': case '\x03': case '\x04': case '\x0F': case '\x11': case '\x16':
            case '\x1B': case '\x1D': case '\x1E': case '\x1F':
                return stripIrcFormatting(s);
            default:
                break;
        }
    }
    return s;
}

/// ASCII-space trimming (never decodes: service text may be invalid UTF-8).
private string trimSpaces(string s) @safe pure nothrow @nogc { return trimRight(trimLeft(s)); }

private string trimLeft(string s) @safe pure nothrow @nogc {
    size_t i;
    while (i < s.length && s[i] == ' ') ++i;
    return s[i .. $];
}

private string trimRight(string s) @safe pure nothrow @nogc {
    size_t e = s.length;
    while (e > 0 && s[e - 1] == ' ') --e;
    return s[0 .. e];
}

private bool startsWithBytes(string s, string prefix) @safe pure nothrow @nogc {
    return s.length >= prefix.length && s[0 .. prefix.length] == prefix;
}

private bool endsWithBytes(string s, string suffix) @safe pure nothrow @nogc {
    return s.length >= suffix.length && s[$ - suffix.length .. $] == suffix;
}

/// Byte offset of `needle` in `hay` at or after `from`, or -1.
private ptrdiff_t findBytes(string hay, string needle, size_t from) @safe pure nothrow @nogc {
    if (needle.length == 0) return from <= hay.length ? cast(ptrdiff_t) from : -1;
    if (hay.length < needle.length) return -1;
    for (size_t i = from; i + needle.length <= hay.length; ++i)
        if (hay[i] == needle[0] && hay[i .. i + needle.length] == needle) return cast(ptrdiff_t) i;
    return -1;
}

/// Code points as Anope's `utf8length()` counts them (non-continuation bytes).
private size_t utf8Width(string s) @safe pure nothrow @nogc {
    size_t n;
    foreach (char c; s) if ((c & 0xC0) != 0x80) ++n;
    return n;
}

/// One PO string token (`"..."`) with its C escapes resolved.
private string poString(string token, string name) {
    token = trimSpaces(token);
    enforce(token.length >= 2 && token[0] == '"' && token[$ - 1] == '"', "Anope catalog " ~ name ~ " is malformed");
    const body_ = token[1 .. $ - 1];
    char[] o;
    o.reserve(body_.length);
    for (size_t i = 0; i < body_.length; ++i) {
        const c = body_[i];
        if (c != '\\') {
            o ~= c;
            continue;
        }
        enforce(i + 1 < body_.length, "Anope catalog " ~ name ~ " is malformed");
        const e = body_[++i];
        switch (e) {
            case 'n': o ~= '\n'; break;
            case 't': o ~= '\t'; break;
            case 'r': o ~= '\r'; break;
            case 'a': o ~= '\a'; break;
            case 'b': o ~= '\b'; break;
            case 'f': o ~= '\f'; break;
            case 'v': o ~= '\v'; break;
            case '\\': case '"': case '\'': case '?': o ~= e; break;
            case 'x': {
                uint v;
                size_t n;
                while (n < 2 && i + 1 < body_.length && hexDigit(body_[i + 1]) >= 0) {
                    v = v * 16 + cast(uint) hexDigit(body_[++i]);
                    ++n;
                }
                enforce(n > 0, "Anope catalog " ~ name ~ " is malformed");
                o ~= cast(char) v;
                break;
            }
            case '0': .. case '7': {
                uint v = e - '0';
                size_t n = 1;
                while (n < 3 && i + 1 < body_.length && body_[i + 1] >= '0' && body_[i + 1] <= '7') {
                    v = v * 8 + (body_[++i] - '0');
                    ++n;
                }
                o ~= cast(char) v;
                break;
            }
            default:
                enforce(false, "Anope catalog " ~ name ~ " is malformed");
        }
    }
    return o.idup;
}

private int hexDigit(char c) @safe pure nothrow @nogc {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// ── Embedded catalogs ──────────────────────────────────────────────────────

/// Shipped `language/anope.<locale>.po` of each release (Anope installs all).
private enum string[] LOCALES_21 = ["de_DE", "el_GR", "en_US", "es_ES", "fr_FR", "it_IT", "nl_NL",
    "pl_PL", "pt_PT", "ro_RO", "tr_TR"];
private enum string[] LOCALES_20 = ["ca_ES", "de_DE", "el_GR", "en_US", "es_ES", "fr_FR", "hu_HU",
    "it_IT", "nl_NL", "pl_PL", "pt_PT", "ru_RU", "tr_TR"];

/// One release's message union. Built once, read-only afterwards.
private final class AnopeCatalog {
    /// Formatting-free English msgid (singular and plural) → message group.
    size_t[string] groupOf;
    /// Group → formatting-free variants, English singular first.
    string[][] groupVariants;
    /// Variant → every group that can produce it (contest detection).
    size_t[][string] variantGroups;
    /// Short single-line strings (INFO row keys and the like).
    bool[string] rowKeys;
    size_t catalogs;
    size_t entries;

    /// Reads one GNU MO file. Throws on any structural inconsistency.
    void load(string data, string name) {
        const b = cast(const(ubyte)[]) data;
        enforce(b.length >= 28, "Anope catalog " ~ name ~ " is truncated");
        bool little = true;
        uint word(ulong off) {
            enforce(off + 4 <= b.length, "Anope catalog " ~ name ~ " is malformed");
            const o = cast(size_t) off;
            return little
                ? (cast(uint) b[o] | (cast(uint) b[o + 1] << 8) | (cast(uint) b[o + 2] << 16) | (cast(uint) b[o + 3] << 24))
                : ((cast(uint) b[o] << 24) | (cast(uint) b[o + 1] << 16) | (cast(uint) b[o + 2] << 8) | cast(uint) b[o + 3]);
        }
        const magic = word(0);
        if (magic == 0xde120495) little = false;
        else enforce(magic == 0x950412de, "Anope catalog " ~ name ~ " is not a MO file");
        enforce((word(4) >> 16) <= 1, "Anope catalog " ~ name ~ " has an unsupported revision");
        const count = word(8);
        const origins = word(12);
        const translations = word(16);
        string text(ulong table, ulong i) {
            const len = word(table + 8 * i);
            const off = word(table + 8 * i + 4);
            // MO strings are NUL-terminated after `len` bytes.
            enforce(cast(ulong) off + len < b.length, "Anope catalog " ~ name ~ " is malformed");
            return data[off .. off + len];
        }
        foreach (ulong i; 0 .. count) {
            string id = text(origins, i);
            if (!id.length) continue; // header entry
            foreach (k, char c; id)
                if (c == '\x04') { id = id[k + 1 .. $]; break; } // msgctxt
            string singular = id, plural;
            foreach (k, char c; id)
                if (c == '\0') { singular = id[0 .. k]; plural = id[k + 1 .. $]; break; }
            add(singular, plural, text(translations, i).split('\0'));
        }
        ++catalogs;
    }

    /**
     * English source messages from the release's `anope.en_US.po` template:
     * every msgid and msgid_plural, translated anywhere or not (a MO holds
     * translated entries only, so an untranslated plural's English form
     * would otherwise be unknown). Only msgid/msgid_plural are read.
     */
    void loadTemplate(string po, string name) {
        string id, plural;
        int field; // 0 none, 1 msgid, 2 msgid_plural, 3 other
        size_t sources;
        void flush() {
            if (id.length) {
                add(id, plural, null);
                ++sources;
            }
            id = null;
            plural = null;
            field = 0;
        }
        size_t start;
        while (start < po.length) {
            size_t end = start;
            while (end < po.length && po[end] != '\n') ++end;
            string line = po[start .. end];
            start = end + 1;
            if (line.length && line[$ - 1] == '\r') line = line[0 .. $ - 1];
            line = trimSpaces(line);
            if (!line.length || line[0] == '#') continue;
            if (startsWithBytes(line, "msgctxt ")) {
                flush();
                field = 3;
            } else if (startsWithBytes(line, "msgid_plural ")) {
                field = 2;
                plural = poString(line["msgid_plural ".length .. $], name);
            } else if (startsWithBytes(line, "msgid ")) {
                flush();
                field = 1;
                id = poString(line["msgid ".length .. $], name);
            } else if (startsWithBytes(line, "msgstr")) {
                field = 3;
            } else if (line[0] == '"') {
                const s = poString(line, name);
                if (field == 1) id ~= s;
                else if (field == 2) plural ~= s;
            } else {
                enforce(false, "Anope catalog " ~ name ~ " is malformed");
            }
        }
        flush();
        enforce(sources > 0, "Anope catalog " ~ name ~ " has no messages");
    }

    private void add(string singular, string plural, string[] forms) {
        string s = normalizeServiceText(singular);
        if (!s.length) return;
        string p = plural.length ? normalizeServiceText(plural) : null;
        const g = groupFor(s, p);
        addVariant(g, s);
        if (p.length) addVariant(g, p);
        foreach (f; forms) addVariant(g, normalizeServiceText(f));
        ++entries;
    }

    private size_t groupFor(string s, string p) {
        if (auto found = s in groupOf) {
            if (p.length && (p in groupOf) is null) groupOf[p] = *found;
            return *found;
        }
        if (p.length) {
            if (auto found = p in groupOf) {
                groupOf[s] = *found;
                return *found;
            }
        }
        const g = groupVariants.length;
        groupVariants ~= cast(string[]) null;
        groupOf[s] = g;
        if (p.length) groupOf[p] = g;
        return g;
    }

    private void addVariant(size_t g, string v) {
        if (!v.length) return;
        foreach (x; groupVariants[g]) if (x == v) return;
        groupVariants[g] ~= v;
        if (auto gs = v in variantGroups) {
            if (!(*gs).canFind(g)) *gs ~= g;
        } else variantGroups[v] = [g];
        if (rowKeyCandidate(v)) rowKeys[v] = true;
    }
}

private bool rowKeyCandidate(string v) @safe pure nothrow @nogc {
    if (v.length == 0 || v.length > 64 || v[0] == ' ' || v[$ - 1] == ' ') return false;
    foreach (char c; v) if (c == '%' || c == '{' || c == '\n' || c == ':') return false;
    return true;
}

private __gshared AnopeCatalog gCatalog21;
private __gshared AnopeCatalog gCatalog20;

private AnopeCatalog buildCatalog21() {
    auto c = new AnopeCatalog;
    c.loadTemplate(import("anope/2.1/source/anope.en_US.po"), "2.1/en_US.po");
    static foreach (loc; LOCALES_21) c.load(import("anope/2.1/anope." ~ loc ~ ".mo"), "2.1/" ~ loc);
    enforce(c.catalogs == LOCALES_21.length && c.entries > 0, "Anope 2.1 catalogs are incomplete");
    return c;
}

private AnopeCatalog buildCatalog20() {
    auto c = new AnopeCatalog;
    c.loadTemplate(import("anope/2.0.20/source/anope.en_US.po"), "2.0.20/en_US.po");
    static foreach (loc; LOCALES_20) c.load(import("anope/2.0.20/anope." ~ loc ~ ".mo"), "2.0.20/" ~ loc);
    enforce(c.catalogs == LOCALES_20.length && c.entries > 0, "Anope 2.0.20 catalogs are incomplete");
    return c;
}

/// Builds both releases' message unions now (startup), so the first
/// service reply is not parsed while ~25 catalogs load, and a damaged
/// embedded catalog fails the process loudly instead of every request
/// quietly answering unsupported. Throws on a malformed catalog.
void preloadAnopeCatalogs() {
    catalogFor(AnopeRelease.v2_1_pinned);
    catalogFor(AnopeRelease.v2_0_20);
}

private AnopeCatalog catalogFor(AnopeRelease r) {
    final switch (r) {
        case AnopeRelease.unknown: return null;
        case AnopeRelease.v2_1_pinned: return initOnce!gCatalog21(buildCatalog21());
        case AnopeRelease.v2_0_20: return initOnce!gCatalog20(buildCatalog20());
    }
}

// ── Templates ──────────────────────────────────────────────────────────────

private enum Part : ubyte { literal, text, signed, unsigned, decimal, hex, character, wildcard }

private struct Token {
    Part part;
    string literal;
    size_t arg;
    size_t width;
    bool left;
}

private struct Template {
    Token[] tokens;
    /// Highest argument index referenced + 1.
    size_t slots;
    bool[] referenced;
    bool valid;
}

/// `{name}` placeholders and no printf conversion: a 2.1 flexible row.
private bool braceTemplate(string english) @safe pure nothrow {
    bool named;
    for (size_t i = 0; i < english.length; ++i) {
        const c = english[i];
        if (c == '%') {
            if (i + 1 < english.length && english[i + 1] == '%') { ++i; continue; }
            return false;
        }
        if (c != '{') continue;
        size_t e = i + 1;
        while (e < english.length && english[e] != '}') ++e;
        if (e >= english.length) continue;
        const name = trimSpaces(english[i + 1 .. e]);
        if (identifier(name)) named = true;
        i = e;
    }
    return named;
}

private bool identifier(string s) @safe pure nothrow @nogc {
    if (!s.length) return false;
    foreach (k, char c; s) {
        const alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
        if (!alpha && !(k && c >= '0' && c <= '9')) return false;
    }
    return true;
}

private void addToken(ref Template t, Token tok) @safe pure nothrow {
    if (tok.part == Part.literal) {
        if (!tok.literal.length) return;
        if (t.tokens.length && t.tokens[$ - 1].part == Part.literal) {
            t.tokens[$ - 1].literal ~= tok.literal;
            return;
        }
    } else if (tok.part != Part.wildcard) {
        if (tok.arg + 1 > t.slots) t.slots = tok.arg + 1;
        if (t.referenced.length < t.slots) t.referenced.length = t.slots;
        t.referenced[tok.arg] = true;
    }
    t.tokens ~= tok;
}

/// printf template (Anope's `_()` + `vsnprintf`).
private Template compilePrintf(string s) @safe pure nothrow {
    Template t;
    size_t sequential;
    size_t litStart;
    for (size_t i = 0; i < s.length; ++i) {
        if (s[i] != '%') continue;
        addToken(t, Token(Part.literal, s[litStart .. i]));
        if (i + 1 < s.length && s[i + 1] == '%') {
            addToken(t, Token(Part.literal, "%"));
            ++i;
            litStart = i + 1;
            continue;
        }
        size_t j = i + 1;
        // %N$ positional argument
        size_t position;
        {
            size_t k = j;
            size_t n;
            while (k < s.length && s[k] >= '0' && s[k] <= '9' && n < 100) { n = n * 10 + (s[k] - '0'); ++k; }
            if (k > j && k < s.length && s[k] == '$' && n > 0) { position = n; j = k + 1; }
        }
        bool left;
        while (j < s.length && (s[j] == '-' || s[j] == '+' || s[j] == ' ' || s[j] == '#' || s[j] == '0')) {
            if (s[j] == '-') left = true;
            ++j;
        }
        size_t width;
        while (j < s.length && s[j] >= '0' && s[j] <= '9') { width = width * 10 + (s[j] - '0'); ++j; }
        if (j < s.length && s[j] == '*') return Template.init;
        if (j < s.length && s[j] == '.') {
            ++j;
            if (j < s.length && s[j] == '*') return Template.init;
            while (j < s.length && s[j] >= '0' && s[j] <= '9') ++j;
        }
        while (j < s.length && (s[j] == 'h' || s[j] == 'l' || s[j] == 'z' || s[j] == 'j' || s[j] == 't'
                || s[j] == 'L' || s[j] == 'q'))
            ++j;
        if (j >= s.length) return Template.init;
        Part part;
        switch (s[j]) {
            case 's': part = Part.text; break;
            case 'd': case 'i': part = Part.signed; break;
            case 'u': part = Part.unsigned; break;
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': part = Part.decimal; break;
            case 'x': case 'X': case 'p': part = Part.hex; break;
            case 'c': part = Part.character; break;
            default: return Template.init;
        }
        const arg = position ? position - 1 : sequential++;
        addToken(t, Token(part, null, arg, width, left));
        i = j;
        litStart = j + 1;
    }
    addToken(t, Token(Part.literal, s[litStart .. $]));
    t.valid = true;
    return t;
}

/// `Anope::Template` row; `names` holds the English key order (filled
/// when `english`), unknown keys in a translation match any text.
private Template compileBrace(string s, ref string[] names, bool english) @safe pure nothrow {
    Template t;
    size_t litStart;
    for (size_t i = 0; i < s.length; ++i) {
        if (s[i] != '{') continue;
        addToken(t, Token(Part.literal, s[litStart .. i]));
        size_t e = i + 1;
        while (e < s.length && s[e] != '}') ++e;
        if (e >= s.length) {
            // No closing brace: Anope drops the '{' and copies the rest.
            litStart = i + 1;
            continue;
        }
        if (e == i + 1) {
            addToken(t, Token(Part.literal, "{"));
        } else {
            const name = trimSpaces(s[i + 1 .. e]);
            ptrdiff_t index = -1;
            foreach (k, n; names) if (n == name) { index = cast(ptrdiff_t) k; break; }
            if (index < 0 && english) {
                names ~= name;
                index = cast(ptrdiff_t) names.length - 1;
            }
            if (index < 0) addToken(t, Token(Part.wildcard));
            else addToken(t, Token(Part.text, null, cast(size_t) index));
        }
        i = e;
        litStart = e + 1;
    }
    addToken(t, Token(Part.literal, s[litStart .. $]));
    t.valid = true;
    return t;
}

private Template compileTemplate(string s, bool brace, ref string[] names, bool english) @safe pure nothrow {
    return brace ? compileBrace(s, names, english) : compilePrintf(s);
}

// ── Matcher ────────────────────────────────────────────────────────────────

/// Backtracking steps one template may spend on one text.
private enum size_t MATCH_STEP_BUDGET = 100_000;
/// Lines one 2.1 message segment may wrap over.
private enum size_t MAX_WRAP_LINES = 16;
/// Line partitions one start position may try for one variant.
private enum size_t MAX_PARTITIONS = 4096;

private struct Matcher {
    const(Token)[] tokens;
    string text;
    /// Captures returned (English argument count).
    size_t returned;
    string[] caps;
    bool[] bound;
    string[][] found;
    size_t steps;
    bool exhausted;

    void run(size_t slots) {
        const n = slots > returned ? slots : returned;
        caps = new string[n];
        bound = new bool[n];
        step(0, 0);
    }

    private bool done() const { return found.length >= 2 || exhausted; }

    private void step(size_t ti, size_t pos) {
        if (done()) return;
        if (++steps > MATCH_STEP_BUDGET) {
            exhausted = true;
            return;
        }
        if (ti == tokens.length) {
            if (pos == text.length) record();
            return;
        }
        const t = tokens[ti];
        final switch (t.part) {
            case Part.literal:
                if (text.length - pos >= t.literal.length && text[pos .. pos + t.literal.length] == t.literal)
                    step(ti + 1, pos + t.literal.length);
                return;
            case Part.text:
            case Part.wildcard:
                if (ti + 1 == tokens.length) {
                    take(ti, pos, text.length);
                    return;
                }
                if (tokens[ti + 1].part == Part.literal) {
                    const lit = tokens[ti + 1].literal;
                    size_t from = pos;
                    while (!done()) {
                        const hit = findBytes(text, lit, from);
                        if (hit < 0) break;
                        take(ti, pos, cast(size_t) hit);
                        from = cast(size_t) hit + 1;
                    }
                    return;
                }
                foreach (end; pos .. text.length + 1) {
                    if (done()) return;
                    take(ti, pos, end);
                }
                return;
            case Part.character:
                if (pos < text.length) take(ti, pos, pos + 1);
                return;
            case Part.signed:
            case Part.unsigned:
            case Part.decimal:
            case Part.hex:
                numeric(ti, t, pos);
                return;
        }
    }

    private void numeric(size_t ti, const Token t, size_t pos) {
        size_t q = pos;
        if (t.width) while (q < text.length && text[q] == ' ') ++q;
        if ((t.part == Part.signed || t.part == Part.decimal) && q < text.length && text[q] == '-') ++q;
        if (t.part == Part.hex && q + 1 < text.length && text[q] == '0' && (text[q + 1] == 'x' || text[q + 1] == 'X'))
            q += 2;
        size_t e = q;
        while (e < text.length && digit(t.part, text[e])) ++e;
        if (e == q) return;
        size_t[] ends;
        foreach (k; q + 1 .. e + 1) ends ~= k;
        if (t.part == Part.decimal && e + 1 < text.length && text[e] == '.') {
            size_t f = e + 1;
            while (f < text.length && text[f] >= '0' && text[f] <= '9') {
                ++f;
                ends ~= f;
            }
        }
        if (t.width && t.left) {
            const base = ends.dup;
            foreach (b; base) {
                size_t k = b;
                while (k < text.length && text[k] == ' ') ends ~= ++k;
            }
        }
        foreach (end; ends) {
            if (done()) return;
            take(ti, pos, end);
        }
    }

    private static bool digit(Part part, char c) @safe pure nothrow @nogc {
        if (c >= '0' && c <= '9') return true;
        return part == Part.hex && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }

    private void take(size_t ti, size_t pos, size_t end) {
        const t = tokens[ti];
        if (t.part == Part.wildcard) {
            step(ti + 1, end);
            return;
        }
        string value = text[pos .. end];
        if (t.part != Part.text) value = trimSpaces(value);
        else if (t.width) value = t.left ? trimRight(value) : trimLeft(value);
        if (bound[t.arg]) {
            if (caps[t.arg] == value) step(ti + 1, end);
            return;
        }
        bound[t.arg] = true;
        caps[t.arg] = value;
        step(ti + 1, end);
        bound[t.arg] = false;
        caps[t.arg] = null;
    }

    private void record() {
        auto c = caps[0 .. returned].dup;
        foreach (f; found) if (f == c) return;
        found ~= c;
    }
}

// ── Prepared variants ──────────────────────────────────────────────────────

private struct Segment {
    Template tpl;
    bool empty;
    string prefix;
    string suffix;
}

private struct Prepared {
    /// Index of the requested English msgid this variant belongs to.
    size_t which;
    string variant;
    Template whole;
    Segment[] segments;
    size_t returned;
    /// Every English argument appears (captures are complete).
    bool complete;
    /// Another source message produces the same text.
    bool contested;
}

/// One line as the matcher sees it.
private struct LineView {
    string plain;
    string raw;
    string replyTo;
    string command;
}

/// Verdict over one text / one start line.
private struct Verdict {
    /// An uncontested variant matched.
    bool matched;
    /// A contested variant matched.
    bool contested;
    /// More than one reading, incomplete captures or an exhausted search.
    bool ambiguous;
    bool haveCaps;
    string[] caps;
    size_t which;
    /// Lines consumed (frames).
    size_t length;

    void merge(string[] c, size_t w) {
        if (!haveCaps) {
            haveCaps = true;
            caps = c;
            which = w;
        } else if (caps != c) ambiguous = true;
        else if (w < which) which = w;
    }

    @property bool unique() const { return matched && !contested && !ambiguous && haveCaps; }
    @property bool present() const { return matched && !contested; }
}

/// A recognised message in a frame (`AnopeGrammar.occurrences`).
struct ServiceMatch {
    /// First line index in the frame.
    size_t line;
    /// Lines the (2.1-wrapped) message spans.
    size_t lines;
    /// Captures in English argument order.
    string[] captures;
    /// Index of the matched msgid when several were offered.
    size_t which;
}

// ── Grammar ────────────────────────────────────────────────────────────────

/**
 * Reply grammar from an exact release or explicitly selected decoder baseline.
 * Candidate construction does not assert compatibility; every reply still
 * requires the adapter's complete, target-bound recognition.
 */
final class AnopeGrammar {
    private AnopeRelease release_;
    private AnopeCatalog cat;

    this(string versionText) {
        this(anopeRelease(versionText));
    }

    this(AnopeRelease baseline) {
        if (baseline == AnopeRelease.unknown) return;
        AnopeCatalog c;
        try c = catalogFor(baseline);
        catch (Exception) c = null;
        if (c is null) return;
        cat = c;
        release_ = baseline;
    }

    /// Selected decoder baseline with its catalogs loaded.
    @property bool supported() const { return release_ != AnopeRelease.unknown; }
    /// The 2.1 decoder baseline (else 2.0.20 when supported).
    @property bool v21() const { return release_ == AnopeRelease.v2_1_pinned; }
    @property AnopeRelease release() const { return release_; }

    /// The msgid is a message of this release's catalogs (source-exact up
    /// to formatting). Strings Anope never wraps in `_()` are not.
    bool knows(string englishMsgid) const {
        return supported && (normalizeServiceText(englishMsgid) in cat.groupOf) !is null;
    }

    /// English (singular and plural) + every shipped non-fuzzy translation
    /// and plural form, formatting removed, printf/`{key}` left intact.
    /// English only when the release's catalogs do not contain the msgid.
    string[] variants(string englishMsgid) {
        if (!supported) return null;
        string key = normalizeServiceText(englishMsgid);
        if (auto g = key in cat.groupOf) return cat.groupVariants[*g].dup;
        return [key];
    }

    /// `variant` is also produced by a different source message.
    bool contested(string englishMsgid, string variant) {
        if (!supported) return true;
        return isContested(normalizeServiceText(variant), groupsOf([englishMsgid]));
    }

    /// `plainText` is exactly one uncontested variant (no placeholders).
    bool isVariant(string englishMsgid, string plainText) {
        if (!supported) return false;
        const text = normalizeServiceText(plainText);
        const groups = groupsOf([englishMsgid]);
        foreach (v; variants(englishMsgid))
            if (v == text) return !isContested(v, groups);
        return false;
    }

    /// One line, anchored, no wrapping. False when absent, contested,
    /// ambiguous or a translation lacks an argument.
    bool matches(string englishMsgid, string plainLine, out string[] captures) {
        size_t which;
        return matchesAny([englishMsgid], plainLine, captures, which);
    }

    /// `matches` over several outcome-equivalent source messages (e.g. the
    /// by-name and by-number forms of one deletion ack, whose translations
    /// coincide): they do not contest each other. `which` = lowest index.
    bool matchesAny(const string[] englishMsgids, string plainLine, out string[] captures, out size_t which) {
        if (!supported) return false;
        const ps = prepare(englishMsgids);
        auto v = evalText(ps, normalizeServiceText(plainLine));
        if (!v.unique) return false;
        captures = v.caps;
        which = v.which;
        return true;
    }

    /// The message (2.0 `\n` parts / 2.1 wrapped lines, contiguous) occurs in
    /// the frame, and every occurrence reads the same captures.
    bool matches(string englishMsgid, const ref ServiceFrame frame, out string[] captures) {
        size_t which;
        return matchesAny([englishMsgid], frame, captures, which);
    }

    /// Frame form of `matchesAny`.
    bool matchesAny(const string[] englishMsgids, const ref ServiceFrame frame, out string[] captures,
            out size_t which) {
        bool ambiguous;
        auto all = scan(englishMsgids, frameLines(frame), true, ambiguous);
        if (ambiguous || !all.length) return false;
        foreach (m; all[1 .. $]) if (m.captures != all[0].captures) return false;
        captures = all[0].captures;
        which = all[0].which;
        foreach (m; all[1 .. $]) if (m.which < which) which = m.which;
        return true;
    }

    /// Any uncontested occurrence (even one whose captures are ambiguous).
    bool has(string englishMsgid, const ref ServiceFrame frame) {
        return hasAny([englishMsgid], frame);
    }

    /// `has` over several outcome-equivalent messages.
    bool hasAny(const string[] englishMsgids, const ref ServiceFrame frame) {
        if (!supported) return false;
        const ps = prepare(englishMsgids);
        auto lines = frameLines(frame);
        foreach (i; 0 .. lines.length)
            if (evalAt(ps, lines, i, true).present) return true;
        return false;
    }

    /// One line form of `has`.
    bool has(string englishMsgid, string plainLine) {
        if (!supported) return false;
        return evalText(prepare([englishMsgid]), normalizeServiceText(plainLine)).present;
    }

    /// Every non-overlapping occurrence in line order. Null when there is
    /// none, or when any occurrence is contested or ambiguous (see the
    /// `ambiguous` overload to tell those apart).
    string[][] matchAll(string englishMsgid, const ref ServiceFrame frame) {
        bool ambiguous;
        auto r = matchAll(englishMsgid, frame, ambiguous);
        return ambiguous ? null : r;
    }

    /// Every unambiguous occurrence; `ambiguous` reports skipped ones.
    string[][] matchAll(string englishMsgid, const ref ServiceFrame frame, out bool ambiguous) {
        string[][] r;
        foreach (m; scan([englishMsgid], frameLines(frame), true, ambiguous)) r ~= m.captures;
        return r;
    }

    /// `matchAll` over plain lines (no reply/command metadata to separate
    /// bodies: pass one body's lines).
    string[][] matchAllLines(string englishMsgid, const string[] plainLines) {
        bool ambiguous;
        auto r = matchAllLines(englishMsgid, plainLines, ambiguous);
        return ambiguous ? null : r;
    }

    /// ditto, reporting ambiguity.
    string[][] matchAllLines(string englishMsgid, const string[] plainLines, out bool ambiguous) {
        string[][] r;
        foreach (m; scan([englishMsgid], plainViews(plainLines), false, ambiguous)) r ~= m.captures;
        return r;
    }

    /// Occurrences with positions, over several outcome-equivalent msgids.
    ServiceMatch[] occurrences(const string[] englishMsgids, const ref ServiceFrame frame, out bool ambiguous) {
        return scan(englishMsgids, frameLines(frame), true, ambiguous);
    }

    /// ditto, plain lines.
    ServiceMatch[] occurrencesIn(const string[] englishMsgids, const string[] plainLines, out bool ambiguous) {
        return scan(englishMsgids, plainViews(plainLines), false, ambiguous);
    }

    /**
     * `InfoFormatter` row value: translated key exactly, then `:`. 2.0 pads
     * keys on the left (`   Key: value`), 2.1 pads values (`Key:   value`,
     * flexible `\x02Key\x02: value`). A 2.1 value wrapped by `LineWrapper`
     * continues on following lines that are not rows themselves (a known
     * row key, flexible bold key, or the fixed layout's value column);
     * they are joined by one space. Absent, duplicated or contested keys
     * give `found = false`. One INFO block per frame: for a frame carrying
     * several bodies use `infoValueIn` on one block's lines.
     */
    string infoValue(string englishKey, const ref ServiceFrame frame, out bool found) {
        return info(englishKey, frameLines(frame), true, found);
    }

    /// `infoValue` over one block's plain lines.
    string infoValueIn(string englishKey, const string[] plainLines, out bool found) {
        return info(englishKey, plainViews(plainLines), false, found);
    }

    // ── internals ─────────────────────────────────────────────────────

    private size_t[] groupsOf(const string[] englishMsgids) const {
        size_t[] groups;
        foreach (e; englishMsgids)
            if (auto g = normalizeServiceText(e) in cat.groupOf)
                if (!groups.canFind(*g)) groups ~= *g;
        return groups;
    }

    private bool isContested(string variant, const size_t[] groups) const {
        if (auto gs = variant in cat.variantGroups)
            foreach (g; *gs) if (!groups.canFind(g)) return true;
        return false;
    }

    private Prepared[] prepare(const string[] englishMsgids) {
        Prepared[] result;
        if (!supported) return result;
        const groups = groupsOf(englishMsgids);
        foreach (w, e; englishMsgids) {
            string key = normalizeServiceText(e);
            if (!key.length) continue;
            const brace = braceTemplate(key);
            string[] names;
            const english = compileTemplate(key, brace, names, true);
            if (!english.valid) continue;
            const returned = brace ? names.length : english.slots;
            string[] list;
            if (auto g = key in cat.groupOf) list = cat.groupVariants[*g];
            else list = [key];
            foreach (v; list) {
                Prepared p;
                p.which = w;
                p.variant = v;
                p.returned = returned;
                p.whole = compileTemplate(v, brace, names, false);
                if (!p.whole.valid) continue;
                bool anyText;
                foreach (part; split(v, '\n')) {
                    Segment s;
                    s.empty = trimSpaces(part).length == 0;
                    s.tpl = compileTemplate(part, brace, names, false);
                    if (!s.tpl.valid) { anyText = false; break; }
                    if (s.tpl.tokens.length && s.tpl.tokens[0].part == Part.literal) s.prefix = s.tpl.tokens[0].literal;
                    if (s.tpl.tokens.length && s.tpl.tokens[$ - 1].part == Part.literal)
                        s.suffix = s.tpl.tokens[$ - 1].literal;
                    if (!s.empty) anyText = true;
                    p.segments ~= s;
                }
                if (!anyText) continue;
                p.complete = true;
                foreach (a; 0 .. returned)
                    if (a >= p.whole.referenced.length || !p.whole.referenced[a]) p.complete = false;
                p.contested = isContested(v, groups);
                result ~= p;
            }
        }
        return result;
    }

    private static Verdict evalText(const Prepared[] ps, string text) {
        Verdict r;
        foreach (ref p; ps) {
            if (p.segments.length != 1) continue;
            auto m = Matcher(p.whole.tokens, text, p.returned);
            m.run(p.whole.slots);
            if (m.exhausted) { r.ambiguous = true; continue; }
            if (!m.found.length) continue;
            if (p.contested) { r.contested = true; continue; }
            r.matched = true;
            r.length = 1;
            if (m.found.length > 1 || !p.complete) { r.ambiguous = true; continue; }
            r.merge(m.found[0], p.which);
        }
        return r;
    }

    /// Best (fewest-lines) reading of every variant starting at line `i`.
    private Verdict evalAt(const Prepared[] ps, const LineView[] lines, size_t i, bool meta) {
        Verdict r;
        size_t length;
        foreach (ref p; ps) {
            size_t used;
            bool exhausted;
            auto found = matchAt(p, lines, i, meta, used, exhausted);
            if (exhausted) r.ambiguous = true;
            if (!found.length) continue;
            if (p.contested) {
                r.contested = true;
                if (!length || used < length) length = used;
                continue;
            }
            if (r.matched && used != r.length) r.ambiguous = true;
            if (!r.matched || used < r.length) r.length = used;
            r.matched = true;
            if (!length || used < length) length = used;
            if (found.length > 1 || !p.complete) { r.ambiguous = true; continue; }
            r.merge(found[0], p.which);
        }
        if (!r.matched) r.length = length;
        return r;
    }

    private string[][] matchAt(ref const Prepared p, const LineView[] lines, size_t start, bool meta,
            out size_t used, out bool exhausted) {
        const k = p.segments.length;
        const avail = lines.length - start;
        const wrap = v21 ? MAX_WRAP_LINES : 1;
        bool[ulong] memo;
        size_t[] counts = new size_t[k];
        size_t partitions;
        string[][] best;
        size_t bestTotal = size_t.max;

        bool feasible(size_t j, size_t at, size_t m) {
            const key = (cast(ulong) j << 40) | (cast(ulong) at << 20) | m;
            if (auto hit = key in memo) return *hit;
            bool ok = segmentFeasible(p.segments[j], lines, at, m, exhausted);
            memo[key] = ok;
            return ok;
        }

        void evaluate(size_t total) {
            if (meta) {
                foreach (x; start + 1 .. start + total)
                    if (lines[x].replyTo != lines[start].replyTo || lines[x].command != lines[start].command) return;
            }
            string text;
            size_t at = start;
            foreach (j; 0 .. k) {
                if (j) text ~= '\n';
                // A blank part of the message stands for itself whether
                // the IRCd delivered the empty line or not.
                text ~= p.segments[j].empty ? blankText(p.segments[j]) : joined(lines, at, counts[j]);
                at += counts[j];
            }
            auto m = Matcher(p.whole.tokens, text, p.returned);
            m.run(p.whole.slots);
            if (m.exhausted) exhausted = true;
            if (!m.found.length || total > bestTotal) return;
            if (total < bestTotal) {
                bestTotal = total;
                best = null;
            }
            foreach (f; m.found) if (!best.canFind(f)) best ~= f;
        }

        void dfs(size_t j, size_t at, size_t total) {
            if (exhausted) return;
            if (j == k) {
                if (total == 0) return;
                if (++partitions > MAX_PARTITIONS) {
                    exhausted = true;
                    return;
                }
                evaluate(total);
                return;
            }
            const size_t lo = p.segments[j].empty ? 0 : 1;
            const size_t hi = p.segments[j].empty ? 1 : wrap;
            foreach (m; lo .. hi + 1) {
                if (at + m > start + avail) break;
                if (total + m > bestTotal) break;
                if (!feasible(j, at, m)) continue;
                counts[j] = m;
                dfs(j + 1, at + m, total + m);
            }
        }

        dfs(0, start, 0);
        used = best.length ? bestTotal : 0;
        return best;
    }

    private static bool segmentFeasible(const Segment s, const LineView[] lines, size_t at, size_t m,
            ref bool exhausted) {
        if (s.empty) return m == 0 || (m == 1 && trimSpaces(lines[at].plain).length == 0);
        if (m == 0) return false;
        const wrapped = m > 1;
        if (s.prefix.length) {
            const first = lines[at].plain;
            const ok = startsWithBytes(first, s.prefix) || (wrapped && s.prefix.length > first.length
                && s.prefix[0 .. first.length] == first && s.prefix[first.length] == ' ');
            if (!ok) return false;
        }
        if (s.suffix.length) {
            const last = lines[at + m - 1].plain;
            const ok = endsWithBytes(last, s.suffix) || (wrapped && s.suffix.length > last.length
                && s.suffix[$ - last.length .. $] == last && s.suffix[$ - last.length - 1] == ' ');
            if (!ok) return false;
        }
        auto matcher = Matcher(s.tpl.tokens, joined(lines, at, m), 0);
        matcher.run(s.tpl.slots);
        if (matcher.exhausted) {
            exhausted = true;
            return false;
        }
        return matcher.found.length > 0;
    }

    private static string joined(const LineView[] lines, size_t at, size_t m) {
        if (m == 0) return "";
        if (m == 1) return lines[at].plain;
        string s = lines[at].plain;
        foreach (x; at + 1 .. at + m) s ~= " " ~ lines[x].plain;
        return s;
    }

    private static string blankText(const Segment s) {
        return s.tpl.tokens.length && s.tpl.tokens[0].part == Part.literal ? s.tpl.tokens[0].literal : "";
    }

    private ServiceMatch[] scan(const string[] englishMsgids, const LineView[] lines, bool meta, out bool ambiguous) {
        ServiceMatch[] result;
        if (!supported) return result;
        const ps = prepare(englishMsgids);
        if (!ps.length) return result;
        size_t i;
        while (i < lines.length) {
            const v = evalAt(ps, lines, i, meta);
            if (!v.matched && !v.contested) {
                if (v.ambiguous) ambiguous = true;
                ++i;
                continue;
            }
            if (!v.unique) {
                ambiguous = true;
                i += v.length ? v.length : 1;
                continue;
            }
            result ~= ServiceMatch(i, v.length, v.caps.dup, v.which);
            i += v.length ? v.length : 1;
        }
        return result;
    }

    private string info(string englishKey, const LineView[] lines, bool meta, out bool found) {
        if (!supported) return null;
        const groups = groupsOf([englishKey]);
        const keys = variants(englishKey);
        size_t at;
        bool hit;
        string value;
        size_t valueColumn;
        bool fixedColumn;
        foreach (idx, ref l; lines) {
            const s = trimLeft(l.plain);
            foreach (key; keys) {
                if (!startsWithBytes(s, key) || s.length == key.length || s[key.length] != ':') continue;
                const rest = s[key.length + 1 .. $];
                if (rest.length && rest[0] != ' ') continue;
                if (isContested(key, groups) || hit) return null; // contested or duplicate row
                hit = true;
                at = idx;
                const v = trimLeft(rest);
                value = v;
                // 2.1 fixed layout: values start at one column for all rows.
                fixedColumn = l.plain.length && l.plain[0] != ' ' && !flexibleRow(l.raw);
                valueColumn = utf8Width(s[0 .. s.length - v.length]);
                break;
            }
        }
        if (!hit) return null;
        if (v21) {
            foreach (j; at + 1 .. lines.length) {
                const l = lines[j];
                if (!trimSpaces(l.plain).length) break;
                if (meta && (l.replyTo != lines[at].replyTo || l.command != lines[at].command)) break;
                if (infoRow(l, fixedColumn, valueColumn)) break;
                value ~= " " ~ l.plain;
            }
        }
        found = true;
        return trimRight(value);
    }

    private bool infoRow(const LineView l, bool fixedColumn, size_t valueColumn) const {
        if (flexibleRow(l.raw)) return true;
        const s = trimLeft(l.plain);
        const colon = findBytes(s, ":", 0);
        if (colon <= 0) return false;
        const c = cast(size_t) colon;
        if (c + 1 < s.length && s[c + 1] != ' ') return false;
        if ((s[0 .. c] in cat.rowKeys) !is null) return true;
        if (!fixedColumn || l.plain.length != s.length) return false;
        size_t v = c + 1;
        while (v < s.length && s[v] == ' ') ++v;
        return v < s.length && utf8Width(s[0 .. v]) == valueColumn;
    }

    /// 2.1 flexible INFO row: `\x02Key\x02: value` (optionally monospace).
    private static bool flexibleRow(string raw) @safe pure nothrow @nogc {
        size_t i;
        if (i < raw.length && raw[i] == '\x11') ++i;
        if (i >= raw.length || raw[i] != '\x02') return false;
        const close = findBytes(raw, "\x02:", i + 1);
        return close > 0;
    }

    private static LineView[] frameLines(const ref ServiceFrame frame) {
        LineView[] r;
        r.reserve(frame.lines.length);
        foreach (ref l; frame.lines)
            r ~= LineView(l.plain.length || !l.text.length ? l.plain : normalizeServiceText(l.text), l.text,
                l.replyTo, l.command);
        return r;
    }

    private static LineView[] plainViews(const string[] plainLines) {
        LineView[] r;
        r.reserve(plainLines.length);
        foreach (l; plainLines) {
            const p = normalizeServiceText(l);
            r ~= LineView(p, p, null, null);
        }
        return r;
    }
}

// ── Regression checks (services-test) ──────────────────────────────────────

version (ServicesWireHarness) {
    /// Behaviour checks against the embedded catalogs: release gating,
    /// translated/reordered/plural/fuzzy-excluded/contested variants, `%%`,
    /// 2.0 multi-line and 2.1 wrapped replies, `{key}` rows, INFO rows and
    /// ambiguity. `ok(name, cond)` records one named check.
    void servicesGrammarChecks(scope void delegate(string, bool) ok) {
        enum V21 = "Anope-2.1.27-git build #1, compiled Thu Nov 5 2026, flags R -- inspircd -- enc_bcrypt";
        enum V20 = "VERSION Anope-2.0.20 services.test :inspircd3 - (enc_sha256) -- build #1, compiled Nov 5 2026";
        ok("grammar: pinned 2.1 VERSION is supported", anopeRelease(V21) == AnopeRelease.v2_1_pinned);
        ok("grammar: 2.0.20 VERSION is supported", anopeRelease(V20) == AnopeRelease.v2_0_20);
        ok("grammar: 2.1 git build of the pinned commit is supported",
            anopeRelease("Anope-2.1.27-git (f6e4642) build #3 -- inspircd -- enc_bcrypt") == AnopeRelease.v2_1_pinned);
        ok("grammar: other 2.1 commit is unknown",
            anopeRelease("Anope-2.1.27-git (deadbee) build #3 -- inspircd -- enc_bcrypt") == AnopeRelease.unknown);
        ok("grammar: other releases are unknown",
            anopeRelease("Anope-2.0.21 x :y") == AnopeRelease.unknown
            && anopeRelease("Anope-2.0.200 x :y") == AnopeRelease.unknown
            && anopeRelease("Anope-2.1.27 build #1") == AnopeRelease.unknown
            && anopeRelease("") == AnopeRelease.unknown
            && anopeRelease("Atheme 7.2.12") == AnopeRelease.unknown);
        enum NETCRAVE = "Anope-2.1.27-git (1947276) build #1, compiled Mon Sep 28 2026 08:19:33 UTC, flags DG -- InspIRCd 4+ -- enc_sha2";
        ok("candidate: Netcrave selects decoder without exact recognition",
            anopeCandidateRelease(NETCRAVE) == AnopeRelease.v2_1_pinned
            && anopeRelease(NETCRAVE) == AnopeRelease.unknown
            && candidateAnopeGrammar(NETCRAVE).v21);
        ok("candidate: other patches and ASCII build suffixes select families",
            anopeCandidateRelease("\t VERSION Anope-2.0.99-dev.a_1+test-2 (1234567) build #3 \r\n") == AnopeRelease.v2_0_20
            && anopeCandidateRelease("Anope-2.1.28") == AnopeRelease.v2_1_pinned);
        foreach (bad; ["", "Atheme 7.2.12", "server Anope-2.1.27-git", "Anope-2.10.1",
                "Anope-2.2.0", "Anope-3.0.0", "Anope-2.1.", "Anope-2.1.2-", "Anope-2.1.2/evil"])
            ok("candidate: rejects " ~ bad, anopeCandidateRelease(bad) == AnopeRelease.unknown);

        auto g21 = new AnopeGrammar(V21);
        auto g20 = new AnopeGrammar(V20);
        auto none = new AnopeGrammar("Anope-2.2.0 build #1");
        ok("grammar: catalogs load for both releases", g21.supported && g21.v21 && g20.supported && !g20.v21);
        string[] caps;
        ok("grammar: unsupported release has no variants or matches",
            !none.supported && none.variants("Access denied.").length == 0
            && !none.matches("Access denied.", "Access denied.", caps));

        auto denied = g21.variants("Access denied.");
        ok("grammar: variants keep English first and add translations",
            denied.length > 1 && denied[0] == "Access denied." && denied.canFind("Zugriff verweigert.")
            && denied.canFind("Accès refusé."));
        ok("grammar: translated denial matches", g21.matches("Access denied.", "Acceso denegado.", caps));
        ok("grammar: anchored, no substring match",
            !g21.matches("Access denied.", "Access denied. Try again later.", caps)
            && !g21.has("Access denied.", "Note: Access denied."));

        ok("grammar: translated ack captures its argument",
            g21.matches("Memo sent to \x02%s\x02.", "Memo wurde an bob versandt.", caps) && caps == ["bob"]);
        // de_DE marks its "Access for %s on %s:" msgstr fuzzy (a wrong
        // "access level changed" sentence): Anope never sends it.
        enum ACCESS_FOR = "Access for \x02%s\x02 on \x02%s\x02:";
        ok("grammar: fuzzy translations are excluded",
            g21.knows(ACCESS_FOR) && g21.variants(ACCESS_FOR).canFind("Toegang voor %s op %s:")
            && !g21.variants(ACCESS_FOR).canFind("Access-Level für %s in %s wurde auf +%s geändert.")
            && !g21.has(ACCESS_FOR, "Access-Level für bob in #c wurde auf +AO geändert."));
        ok("grammar: formatting in the reply is ignored",
            g21.matches("Memo sent to \x02%s\x02.", "Memo sent to \x02\x0304bob\x03\x02.", caps) && caps == ["bob"]);

        ok("grammar: reordered positional translation returns English argument order",
            g21.matches("%s %s list is empty.", "La liste des SOP de #chan est vide.", caps)
            && caps == ["#chan", "SOP"]);
        ok("grammar: 2.0.20 reordered translation too",
            g20.matches("%s %s list is empty.", "La liste des AOP de #c est vide.", caps) && caps == ["#c", "AOP"]);

        ok("grammar: plural English form matches the singular msgid",
            g21.matches("Deleted %d entry from %s %s list.", "Deleted 2 entries from #c SOP list.", caps)
            && caps == ["2", "#c", "SOP"]);
        ok("grammar: translated plural form matches",
            g21.matches("Deleted %d entry from %s %s list.", "3 entradas removidas da lista #c de SOP.", caps)
            && caps.length == 3 && caps[0] == "3");

        ok("grammar: %% is a literal percent",
            g21.matches("Bot will now kick for \x02caps\x02 (they must constitute at least %d characters and %d%% of the entire message).",
                "Bot will now kick for caps (they must constitute at least 10 characters and 25% of the entire message).", caps)
            && caps == ["10", "25"]);

        ok("grammar: contested translation never matches",
            !g21.matches("\x02%s\x02 has no access on \x02%s\x02.", "bob wurde nach #c eingeladen.", caps)
            && !g21.has("\x02%s\x02 has no access on \x02%s\x02.", "bob wurde nach #c eingeladen.")
            && !g21.matches("\x02%s\x02 has been invited to \x02%s\x02.", "bob wurde nach #c eingeladen.", caps));
        size_t which;
        ok("grammar: equivalent messages do not contest each other",
            g21.matchesAny(["You need to be identified to use this command.",
                "You must be logged into an account to use that command."],
                "Vous devez être identifié(e) pour utiliser cette commande.", caps, which) && which == 0
            && !g21.matches("You need to be identified to use this command.",
                "Vous devez être identifié(e) pour utiliser cette commande.", caps));

        ok("grammar: several readings are ambiguous, not guessed",
            !g20.matches("%s is %s", "a is b is c", caps) && g20.has("%s is %s", "a is b is c")
            && g20.matches("%s is %s", "alice is Alice Liddell", caps) && caps == ["alice", "Alice Liddell"]);

        ok("grammar: flexible {key} row captures in English key order",
            g21.matches("{number}: \x02{mask}\x02 ({reason})", "1: \x02*!*@bad.example\x02 (spam)", caps)
            && caps == ["1", "*!*@bad.example", "spam"]);

        ServiceFrame frame(string[] texts...) {
            ServiceFrame f;
            foreach (t; texts) {
                ServiceReplyLine l;
                l.command = "NOTICE";
                l.text = t;
                l.plain = stripIrcFormatting(t);
                f.lines ~= l;
            }
            return f;
        }

        enum NOBOTS = "There are no bots available at this time.\nAsk a Services Operator to create one!";
        auto twoLine = frame("Es sind derzeit keine Bots verfügbar.", "Bitte einen Services Administrator, einen zu erstellen.");
        ok("grammar: 2.0 multi-line message matches its consecutive lines", g20.has(NOBOTS, twoLine));
        auto firstOnly = frame("Es sind derzeit keine Bots verfügbar.", "Something else.");
        ok("grammar: partial multi-line message does not match", !g20.has(NOBOTS, firstOnly));

        enum AKICK = "\x02%s\x02 added to %s autokick list.";
        auto wrapped = frame("\x02averyveryveryverylongnickname!averyveryverylongident@a.very.long.host.example.net\x02 added to #ircfiber",
            "autokick list.");
        ok("grammar: 2.1 wrapped reply is joined",
            g21.matches(AKICK, wrapped, caps)
            && caps == ["averyveryveryverylongnickname!averyveryverylongident@a.very.long.host.example.net", "#ircfiber"]);
        ok("grammar: 2.0 never joins wrapped lines", !g20.has(AKICK, wrapped));
        auto mixed = wrapped;
        mixed.lines = wrapped.lines.dup;
        mixed.lines[1].command = "PRIVMSG";
        ok("grammar: lines of different reply kinds are not joined", !g21.has(AKICK, mixed));
        auto twice = frame("a!b@c added to #x autokick list.", "d!e@f added to #x autokick list.");
        ok("grammar: disagreeing occurrences make matches() false, matchAll() lists them",
            !g21.matches(AKICK, twice, caps) && g21.matchAll(AKICK, twice).length == 2);

        auto info21 = frame("Information about channel \x02#c\x02:",
            "Founder:     alice",
            "Description: test",
            "Options:     Peace, Persistent, Restricted access, Secure founder, Signed kicks, Topic retention,",
            "Topic lock",
            // A third-party module's row: unknown key, recognised by the
            // fixed layout's value column.
            "Mascot:      ferret");
        bool found;
        ok("grammar: 2.1 INFO value", g21.infoValue("Founder", info21, found) == "alice" && found);
        ok("grammar: 2.1 wrapped INFO value is joined",
            g21.infoValue("Options", info21, found)
                == "Peace, Persistent, Restricted access, Secure founder, Signed kicks, Topic retention, Topic lock"
            && found);
        auto fr21 = frame("Fondateurice: alice", "Options:      Maintien du topic");
        ok("grammar: translated INFO key", g21.infoValue("Founder", fr21, found) == "alice" && found
            && g21.infoValue("Options", fr21, found) == "Maintien du topic" && found);
        auto dup = frame("Founder: alice", "Founder: mallory");
        g21.infoValue("Founder", dup, found);
        ok("grammar: duplicate INFO key is unknown", !found);
        auto info20 = frame("    Founder: alice", "    Options: Peace", "trailing notice");
        ok("grammar: 2.0 right-aligned INFO key, no continuation",
            g20.infoValue("Founder", info20, found) == "alice" && found
            && g20.infoValue("Options", info20, found) == "Peace" && found);
        g21.infoValue("Successor", info21, found);
        ok("grammar: absent INFO key is not found", !found);
    }
}
