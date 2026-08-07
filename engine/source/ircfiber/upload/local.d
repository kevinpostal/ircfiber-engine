module ircfiber.upload.local;

import std.file : mkdirRecurse, write;
import std.path : buildPath, extension;
import std.uuid : randomUUID;
import std.string : replace;
import std.process : environment;
import vibe.core.log;

/// Upload directory, defaulting to /app/uploads (inside the gateway
/// container). Override via the UPLOAD_DIR environment variable for
/// local dev and testing.
string uploadDir() @safe {
    auto env = environment.get("UPLOAD_DIR");
    return env.length > 0 ? env : "/app/uploads";
}

/// Result of a successful local upload.
struct LocalUploadResult {
    string url; // https://ircfiber.com/uploads/<uuid>.<ext>
}

/// Thrown when the file can't be written.
class LocalUploadException : Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe {
        super(msg, file, line);
    }
}

/// Saves an uploaded file to the local filesystem under uploadDir.
/// Returns a URL constructed from the given baseUrl (e.g. "https://ircfiber.com").
/// Throws LocalUploadException on I/O failure.
LocalUploadResult saveUpload(string filename, string mime, const(ubyte)[] data, string baseUrl) @trusted {
    import std.string : strip;

    // Preserve original extension
    auto ext = extension(filename).strip;
    if (ext.length == 0) {
        // Guess extension from MIME type for common types
        if (mime == "image/png") ext = ".png";
        else if (mime == "image/jpeg" || mime == "image/jpg") ext = ".jpg";
        else if (mime == "image/gif") ext = ".gif";
        else if (mime == "image/webp") ext = ".webp";
        else ext = ".bin";
    }

    auto uuid = randomUUID().toString().replace("-", "");
    auto destName = uuid ~ ext;
    auto dir = uploadDir();
    auto destPath = buildPath(dir, destName);

    // Ensure upload directory exists
    try {
        mkdirRecurse(dir);
    } catch (Exception e) {
        throw new LocalUploadException("Failed to create upload directory: " ~ e.msg);
    }

    // Write the file
    try {
        write(destPath, data);
    } catch (Exception e) {
        throw new LocalUploadException("Failed to write uploaded file: " ~ e.msg);
    }

    // Strip trailing slash from baseUrl
    auto base = baseUrl.strip;
    while (base.length > 0 && base[$-1] == '/') base = base[0..$-1];

    auto url = base ~ "/uploads/" ~ destName;
    logInfo("Saved upload: %s (%s bytes, mime=%s)", url, data.length, mime);
    return LocalUploadResult(url);
}

@("saveUpload generates a URL and writes to disk")
unittest {
    import std.algorithm : canFind, startsWith;
    import std.file : exists;

    auto tmpDir = "/tmp/ircfiber-upload-test";
    auto testData = cast(const(ubyte)[])"fakeimagedata";

    // Set env var to a writable temp dir so the test works on any machine
    environment["UPLOAD_DIR"] = tmpDir;
    scope(exit) environment.remove("UPLOAD_DIR");

    auto result = saveUpload("test.png", "image/png", testData, "https://ircfiber.com");
    assert(result.url.canFind("/uploads/"));
    assert(result.url.canFind(".png"));
    assert(result.url.startsWith("https://ircfiber.com"));
}

@("saveUpload handles filenames without extension")
unittest {
    import std.algorithm : canFind;

    auto tmpDir = "/tmp/ircfiber-upload-test2";
    auto testData = cast(const(ubyte)[])"data";

    environment["UPLOAD_DIR"] = tmpDir;
    scope(exit) environment.remove("UPLOAD_DIR");

    auto result = saveUpload("noext", "image/gif", testData, "http://localhost:8090");
    assert(result.url.canFind(".gif"), "Should guess extension from MIME: " ~ result.url);
}
