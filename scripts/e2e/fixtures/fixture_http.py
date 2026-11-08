#!/usr/bin/env python3
"""HTTP/cookies for an owned loopback-only disposable gateway."""
import http.cookiejar
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


class LoopbackFixtureCookies(http.cookiejar.MozillaCookieJar):
    def __init__(self, base, filename=None):
        target = urllib.parse.urlsplit(base)
        if (target.scheme != "http" or target.hostname != "127.0.0.1"
                or target.username is not None or target.password is not None
                or target.path not in ("", "/") or target.query or target.fragment
                or target.port is None or not 1024 < target.port < 65536):
            raise ValueError("fixture gateway must be an explicit loopback HTTP port")
        self.destination = (target.scheme, target.hostname, target.port)
        super().__init__(filename)

    def add_cookie_header(self, request):
        target = urllib.parse.urlsplit(request.full_url)
        if (target.scheme, target.hostname, target.port) != self.destination:
            raise ValueError("refusing non-fixture cookie destination")
        # Production sets Secure even behind this isolated plain-HTTP relay.
        # Demote only this jar and only after checking every redirect's target.
        for cookie in self:
            cookie.secure = False
        super().add_cookie_header(request)


def main():
    if not 5 <= len(sys.argv) <= 7:
        raise ValueError("usage: fixture_http.py JAR BASE METHOD /path [BODY] [CONTENT_TYPE]")
    filename, base, method, path = sys.argv[1:5]
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("fixture request requires a relative absolute path")
    jar = LoopbackFixtureCookies(base, filename)
    if os.path.exists(filename) and os.path.getsize(filename):
        jar.load(ignore_discard=True)
    body = sys.argv[5] if len(sys.argv) > 5 else ""
    content_type = sys.argv[6] if len(sys.argv) > 6 else "application/json"
    data = body.encode() if body or method in ("POST", "PUT", "PATCH") else None
    request = urllib.request.Request(base.rstrip("/") + path, data=data,
                                     method=method, headers={"Content-Type": content_type})
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        with opener.open(request, timeout=45) as response:
            sys.stdout.buffer.write(response.read())
    except urllib.error.HTTPError as error:
        print(f"fixture HTTP {method} {path}: {error.code}", file=sys.stderr)
        sys.stderr.buffer.write(error.read())
        return 1
    finally:
        jar.save(ignore_discard=True)
        os.chmod(filename, 0o600)
    return 0


if __name__ == "__main__":
    sys.exit(main())
