module ircfiber.db.upload_category;

import vibe.data.bson : Bson;

// Management classification is deliberately stricter than the upload picker's
// unknown-extension fallback. Keep both execution paths below on these tables.
// Text names cover textFiles.ts and highlightLanguages.ts; video suffixes
// mirror upload.ts. Image suffixes take precedence over textual SVG syntax.
private immutable string[] textMimes = [
    "application/atom+xml", "application/ecmascript", "application/javascript",
    "application/json", "application/rdf+xml", "application/rss+xml",
    "application/xhtml+xml", "application/xml",
];
private immutable string[] genericMimes = ["", "application/octet-stream"];
private immutable string[] videoExtensions = [
    "mp4", "m4v", "webm", "mov", "avi", "mkv", "mpg", "mpeg", "flv", "wmv", "3gp",
];
private immutable string[] imageExtensions = [
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "svg",
    "avif", "heic", "heif",
];
private immutable string[] textExtensions = [
    "txt", "text", "log", "md", "markdown", "mdown", "mkd",
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "py", "pyw", "pyi", "python",
    "rb", "gemspec", "rake", "ruby", "java", "c", "h", "cpp", "cxx", "cc", "hpp", "hh",
    "cs", "csharp", "go", "golang", "rs", "rust", "php", "phtml",
    "sh", "bash", "zsh", "ksh", "fish", "shell", "html", "htm", "xhtml",
    "css", "scss", "sass", "less", "stylus", "json", "json5", "yaml", "yml", "xml", "svg",
    "toml", "sql", "pgsql", "mysql", "graphql", "gql", "graphqls", "graphqlschema",
    "dockerfile", "containerfile", "makefile", "mk", "ini", "conf", "cfg", "properties",
    "lua", "perl", "pl", "pm", "swift", "kotlin", "kt", "kts", "scala", "sc",
    "clj", "cljs", "cljc", "ex", "exs", "eex", "dart", "r", "rmd", "jl", "hs", "lhs",
    "erl", "hrl", "elm", "vue", "svelte", "astro", "tf", "hcl", "nix", "nginx",
    "apache", "htaccess", "bat", "cmd", "ps1", "psm1", "powershell", "tex", "latex",
    "diff", "patch", "csv", "prql", "proto", "protobuf", "zig", "nim", "coffee",
    "pug", "jade", "handlebars", "hbs", "liquid", "twig", "verilog", "vhdl",
];
private immutable string[] textBasenames = [
    "dockerfile", "containerfile", "makefile", "gnumakefile", "gemfile", "rakefile", "podfile",
    "nginx.conf", "package.json", "package-lock.json", "tsconfig.json", "cargo.toml", "pyproject.toml",
    ".bashrc", ".bash_profile", ".zshrc", ".profile", ".gitignore", ".env", ".editorconfig",
    "readme", "license",
];
private enum mimeWhitespace = " \t\r\n";
private enum managedUrlPattern = `\A(?:https?://[^/?#]+)?/uploads/([0-9a-f]{32}(?:\.[^/?#\\\x00-\x20]+)?)(?:[?#][\s\S]*)?\z`;

private char asciiLower(char c) @safe pure nothrow @nogc {
    return c >= 'A' && c <= 'Z' ? cast(char)(c + ('a' - 'A')) : c;
}
private bool equalsAscii(string a, string b) @safe pure nothrow @nogc {
    if (a.length != b.length) return false;
    foreach (i, c; a) if (asciiLower(c) != b[i]) return false;
    return true;
}
private bool prefixAscii(string value, string prefix) @safe pure nothrow @nogc {
    return value.length >= prefix.length && equalsAscii(value[0 .. prefix.length], prefix);
}
private bool inTable(string value, const(string)[] table) @safe pure nothrow @nogc {
    foreach (item; table) if (equalsAscii(value, item)) return true;
    return false;
}
private string trimMime(string value) @safe pure nothrow @nogc {
    bool whitespace(char c) @safe pure nothrow @nogc {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }
    while (value.length && whitespace(value[0])) value = value[1 .. $];
    while (value.length && whitespace(value[$ - 1])) value = value[0 .. $ - 1];
    return value;
}
private string basename(string value) @safe pure nothrow @nogc {
    foreach_reverse (i, c; value) if (c == '/' || c == '\\') return value[i + 1 .. $];
    return value;
}
private string suffix(string value) @safe pure nothrow @nogc {
    foreach_reverse (i, c; value) if (c == '.') return value[i + 1 .. $];
    return "";
}

// This recognizes only a storage pathname, not its origin or local existence.
// Never use it to authorize filesystem access or to fetch remote URLs.
private string managedBasename(string url) @safe pure nothrow @nogc {
    foreach (i, c; url) if (c == '?' || c == '#') { url = url[0 .. i]; break; }
    if (prefixAscii(url, "https://") || prefixAscii(url, "http://")) {
        const start = prefixAscii(url, "https://") ? 8 : 7;
        size_t slash = start;
        while (slash < url.length && url[slash] != '/') ++slash;
        if (slash == start || slash == url.length) return "";
        url = url[slash .. $];
    }
    if (!prefixAscii(url, "/uploads/")) return "";
    auto name = url[9 .. $];
    if (name.length < 32) return "";
    foreach (c; name[0 .. 32]) {
        const lower = asciiLower(c);
        if (!((lower >= '0' && lower <= '9') || (lower >= 'a' && lower <= 'f'))) return "";
    }
    if (name.length == 32) return name;
    if (name[32] != '.' || name.length == 33) return "";
    foreach (c; name[33 .. $]) if (c <= ' ' || c == '/' || c == '\\') return "";
    return name;
}

/// Stable original name for classification and display. A rename must freeze
/// the final legacy display-name fallback into originalFilename before changing it.
string uploadOriginalName(string originalFilename, string directUrl = "", string filename = "")
    @safe pure nothrow @nogc {
    if (originalFilename.length) return originalFilename;
    const stored = managedBasename(directUrl);
    return stored.length ? stored : filename;
}

/// Category shared by library aggregation and server-side text eligibility.
/// No allocation, permissive unknown-MIME picker fallback, or content sniffing.
string uploadCategory(string mimeType, string originalFilename, string directUrl = "", string filename = "")
    @safe pure nothrow @nogc {
    foreach (i, c; mimeType) if (c == ';') { mimeType = mimeType[0 .. i]; break; }
    const mime = trimMime(mimeType);
    if (prefixAscii(mime, "image/")) return "image";
    if (prefixAscii(mime, "video/")) return "video";
    if (prefixAscii(mime, "text/") || inTable(mime, textMimes)) return "text";
    if (!inTable(mime, genericMimes)) return "other";
    const name = basename(uploadOriginalName(originalFilename, directUrl, filename));
    const ext = suffix(name);
    if (inTable(ext, videoExtensions)) return "video";
    if (inTable(ext, imageExtensions)) return "image";
    if (inTable(ext, textExtensions) || inTable(name, textBasenames)) return "text";
    return "other";
}

private Bson stringField(string path) {
    return Bson(["$cond": Bson([
        Bson(["$eq": Bson([Bson(["$type": Bson(path)]), Bson("string")])]), Bson(path), Bson("")])]);
}
private Bson nonempty(Bson value, Bson fallback) {
    return Bson(["$let": Bson([
        "vars": Bson(["candidate": value]),
        "in": Bson(["$cond": Bson([
            Bson(["$ne": Bson([Bson("$$candidate"), Bson("")])]), Bson("$$candidate"), fallback])]),
    ])]);
}
private Bson member(Bson value, const(string)[] table) {
    auto items = new Bson[table.length];
    foreach (i, item; table) items[i] = Bson(item);
    return Bson(["$in": Bson([value, Bson(items)])]);
}
private Bson regexMatch(string value, string pattern) {
    return Bson(["$regexMatch": Bson(["input": Bson(value), "regex": Bson(pattern)])]);
}

/// Aggregation expression over the stored upload document (before projection).
Bson uploadOriginalNameExpression() {
    auto stored = Bson(["$let": Bson([
        "vars": Bson(["matched": Bson(["$regexFind": Bson([
            "input": stringField("$directUrl"), "regex": Bson(managedUrlPattern), "options": Bson("i")])])]),
        "in": Bson(["$cond": Bson([
            Bson(["$eq": Bson([Bson("$$matched"), Bson(null)])]), Bson(""),
            Bson(["$arrayElemAt": Bson([Bson("$$matched.captures"), Bson(0)])])])]),
    ])]);
    return nonempty(stringField("$originalFilename"), nonempty(stored, stringField("$filename")));
}

/// Explicit managed-upload provenance only. Legacy filesystem verification is
/// the caller's responsibility; a URL-shaped string cannot establish locality.
Bson uploadLocalExpression() {
    return Bson(["$ifNull": Bson([Bson("$local"), Bson(false)])]);
}

/// Mongo equivalent of uploadCategory, generated from the same type tables.
Bson uploadCategoryExpression() {
    auto mime = Bson(["$toLower": Bson(["$trim": Bson([
        "input": Bson(["$arrayElemAt": Bson([
            Bson(["$split": Bson([stringField("$mimeType"), Bson(";")])]), Bson(0)])]),
        "chars": Bson(mimeWhitespace),
    ])])]);
    auto name = Bson(["$toLower": Bson(["$arrayElemAt": Bson([
        Bson(["$split": Bson([Bson(["$replaceAll": Bson([
            "input": uploadOriginalNameExpression(), "find": Bson("\\"), "replacement": Bson("/")
        ])]), Bson("/")])]), Bson(-1)])])]);
    auto parts = Bson(["$split": Bson([Bson("$$name"), Bson(".")])]);
    auto ext = Bson(["$cond": Bson([
        Bson(["$gt": Bson([Bson(["$size": Bson("$$parts")]), Bson(1)])]),
        Bson(["$arrayElemAt": Bson([Bson("$$parts"), Bson(-1)])]), Bson("")])]);
    auto fallback = Bson(["$switch": Bson([
        "branches": Bson([
            Bson(["case": member(Bson("$$ext"), videoExtensions), "then": Bson("video")]),
            Bson(["case": member(Bson("$$ext"), imageExtensions), "then": Bson("image")]),
            Bson(["case": Bson(["$or": Bson([member(Bson("$$ext"), textExtensions), member(Bson("$$name"), textBasenames)])]),
                "then": Bson("text")]),
        ]), "default": Bson("other"),
    ])]);
    fallback = Bson(["$let": Bson([
        "vars": Bson(["parts": parts]),
        "in": Bson(["$let": Bson(["vars": Bson(["ext": ext]), "in": fallback])]),
    ])]);
    return Bson(["$let": Bson([
        "vars": Bson(["mime": mime, "name": name]),
        "in": Bson(["$switch": Bson([
            "branches": Bson([
                Bson(["case": regexMatch("$$mime", "^image/"), "then": Bson("image")]),
                Bson(["case": regexMatch("$$mime", "^video/"), "then": Bson("video")]),
                Bson(["case": Bson(["$or": Bson([regexMatch("$$mime", "^text/"), member(Bson("$$mime"), textMimes)])]),
                    "then": Bson("text")]),
                Bson(["case": member(Bson("$$mime"), genericMimes), "then": fallback]),
            ]), "default": Bson("other"),
        ])]),
    ])]);
}

@("Upload categories honor explicit MIME before stable case-insensitive names")
unittest {
    assert(uploadCategory(" IMAGE/SVG+XML ; charset=utf-8", "example.py") == "image");
    assert(uploadCategory("Video/MP4; codecs=avc1", "example.png") == "video");
    assert(uploadCategory("text/plain", "example.mp4") == "text");
    assert(uploadCategory(" APPLICATION/JSON \t; charset=utf-8", "example.png") == "text");
    assert(uploadCategory("application/pdf", "example.py") == "other");
    assert(uploadCategory("application/zip", "example.txt") == "other");
    assert(uploadCategory("application/octet-stream", "example.PY") == "text");
    assert(uploadCategory("", "example.SVG") == "image");
    assert(uploadCategory("", "example.M4V") == "video");
    assert(uploadCategory("", "example.unknown") == "other");
    assert(uploadCategory("", "example.pdf") == "other");
    assert(uploadCategory("", "") == "other");
    assert(uploadCategory("", "py") == "other");
    assert(uploadCategory("", "directory\\DOCKERFILE") == "text");
    assert(uploadCategory("", "directory/.BASHRC") == "text");
    foreach (ext; textExtensions)
        assert(uploadCategory("", "file." ~ ext) == (ext == "svg" ? "image" : "text"));
    foreach (ext; imageExtensions) assert(uploadCategory("", "file." ~ ext) == "image");
    foreach (ext; videoExtensions) assert(uploadCategory("", "file." ~ ext) == "video");
    foreach (name; textBasenames) assert(uploadCategory("", name) == "text");
    foreach (mime; textMimes) assert(uploadCategory(mime, "file.mp4") == "text");
}

@("Stable upload names ignore renames when original or storage name survives")
unittest {
    enum stored = "0123456789abcdef0123456789abcdef.PY";
    enum url = "https://example.test/uploads/" ~ stored;
    assert(uploadOriginalName("original.TS", url, "renamed.pdf") == "original.TS");
    assert(uploadCategory("", "original.TS", url, "renamed.pdf") == "text");
    assert(uploadOriginalName("", url ~ "?download=1#source", "renamed.pdf") == stored);
    assert(uploadCategory("", "", url, "renamed.pdf") == "text");
    assert(uploadOriginalName("", "https://external.test/picture.png", "legacy.py") == "legacy.py");
    foreach (bad; ["/uploads/short.py", "/uploads/" ~ stored ~ "/child", "/uploads/../" ~ stored,
            "/uploads/" ~ stored ~ "\\child", "ftp://example.test/uploads/" ~ stored,
            "https:///uploads/" ~ stored, "/uploads/" ~ stored ~ " bad"])
        assert(uploadOriginalName("", bad, "legacy.txt") == "legacy.txt");
}

@("Mongo upload classification agrees with the allocation-free categorizer")
unittest {
    import ircfiber.testing.isolated_db : connectIsolatedTestMongo;
    import ircfiber.db.mongo : AppMongoConnection;
    import std.uuid : randomUUID;
    import vibe.db.mongo.cursor;
    if (!connectIsolatedTestMongo("upload_category parity")) return;
    auto collection = AppMongoConnection.getDb()["upload_category_test"];
    const id = randomUUID().toString();
    scope (exit) collection.deleteMany(Bson(["testId": Bson(id)]));
    struct Example { string mime; string original; string url; string display; }
    Example[] examples = [
        Example(" IMAGE/PNG ; charset=binary", "movie.mp4"),
        Example("VIDEO/webm", "photo.svg"), Example("text/plain", "file.png"),
        Example("application/xml", "image.svg"), Example("application/pdf", "source.py"),
        Example("", "file[1].PY"), Example("", "file.unknown"), Example("", "folder\\.BASHRC"),
        Example("", "", "https://example.test/uploads/0123456789abcdef0123456789abcdef.TS?raw=1", "renamed.pdf"),
        Example("", "", "https://external.test/file.png", "DOCKERFILE"),
    ];
    foreach (ext; textExtensions) examples ~= Example("application/octet-stream", "source." ~ ext);
    foreach (ext; imageExtensions) examples ~= Example("", "source." ~ ext);
    foreach (ext; videoExtensions) examples ~= Example("", "source." ~ ext);
    foreach (name; textBasenames) examples ~= Example("", name);
    foreach (mime; textMimes) examples ~= Example(mime, "source.mp4");
    foreach (i, example; examples) {
        auto doc = Bson(["testId": Bson(id), "index": Bson(cast(int)i),
            "mimeType": Bson(example.mime), "originalFilename": Bson(example.original),
            "directUrl": Bson(example.url), "filename": Bson(example.display)]);
        // Missing and explicitly false provenance must both remain false.
        if (i % 3) doc["local"] = Bson(i % 3 == 1);
        collection.insertOne(doc);
    }
    Bson[] pipeline = [Bson(["$match": Bson(["testId": Bson(id)])]), Bson(["$project": Bson([
        "index": Bson(1), "category": uploadCategoryExpression(), "original": uploadOriginalNameExpression(),
        "local": uploadLocalExpression(),
    ])])];
    size_t seen;
    foreach (doc; collection.aggregate!Bson(pipeline)) {
        const example = examples[doc["index"].get!int];
        assert(doc["category"].get!string == uploadCategory(example.mime, example.original, example.url, example.display));
        assert(doc["original"].get!string == uploadOriginalName(example.original, example.url, example.display));
        assert(doc["local"].get!bool == (doc["index"].get!int % 3 == 1));
        ++seen;
    }
    assert(seen == examples.length);
}
