#!/usr/bin/env bash
# Run after `dub fetch vibe-stream --version=1.4.1`, before compiling consumers.
# Hold the build's DUB-cache lock: neither source nor TLS artifacts may change
# underneath another compiler. Unknown package contents fail closed.
set -euo pipefail

if [ "$#" -gt 1 ]; then
    echo "usage: bash $0 [dub-cache-root]" >&2
    exit 2
fi
cache=${1:-"$HOME/.dub"}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
patch_file="$script_dir/../patches/vibe-stream-1.4.1-abort.patch"
upstream=2fc57dbcde9109dac18f64649fc04c0673c8fca862a7efe136d3d53d69198e3c
patched=0a9543d03245067dddb452d7feed7b430754b5c99768ecc5b1ddf8ba6a4689fc
package=
for candidate in "$cache/packages/vibe-stream/1.4.1/vibe-stream" "$cache/packages/vibe-stream-1.4.1"; do
    if [ -f "$candidate/tls/vibe/stream/openssl.d" ]; then
        if [ -n "$package" ]; then
            echo "Ambiguous vibe-stream 1.4.1 package roots; refusing to patch" >&2
            exit 1
        fi
        package=$candidate
    fi
done
if [ -z "$package" ]; then
    echo "vibe-stream 1.4.1 missing; first run dub fetch vibe-stream --version=1.4.1" >&2
    exit 1
fi
source_file="$package/tls/vibe/stream/openssl.d"
source_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$source_file" | cut -d ' ' -f 1
    else
        shasum -a 256 "$source_file" | cut -d ' ' -f 1
    fi
}
case "$(source_hash)" in
    "$upstream") patch --batch --forward --fuzz=0 -p1 -d "$package" < "$patch_file" ;;
    "$patched") ;;
    *) echo "Unexpected vibe-stream 1.4.1 openssl.d SHA256; refusing to patch" >&2; exit 1 ;;
esac
if [ "$(source_hash)" != "$patched" ]; then
    echo "vibe-stream 1.4.1 abort patch SHA256 mismatch" >&2
    exit 1
fi
# Only the pinned TLS subpackage changed. Clear its version-specific caches
# and copied archive even on an already-patched cache, never unrelated packages.
rm -rf -- "$cache/cache/vibe-stream/1.4.1/+tls" "$package/tls/.dub/build"
rm -f -- "$package/tls/libvibe-stream_tls.a"
printf '%s\n' "vibe-stream 1.4.1 terminal abort patch ready ($patched)"
