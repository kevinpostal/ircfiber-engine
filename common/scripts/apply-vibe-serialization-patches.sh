#!/usr/bin/env bash
# Run after `dub fetch vibe-serialization --version=1.2.0`, before compiling consumers.
# Caller must hold the shared DUB-cache lock and invalidate its workspace
# consumers. Unknown package contents fail closed; never overwrite them.
# Generic serializer resource defaults are unchanged. Holder identity scans opt
# into JsonStringSerializer!(R, false, 128, 65536): depth <=128 and decoded outer
# keys <=64KiB. Skipped strings/numbers/keys never buffer their token contents;
# retained fixed numeric input-range conversions use 128-byte scratch.
set -euo pipefail

if [ "$#" -gt 1 ]; then
    echo "usage: bash $0 [dub-cache-root]" >&2
    exit 2
fi
cache=${1:-"$HOME/.dub"}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
patch_file="$script_dir/../patches/vibe-serialization-1.2.0-streaming.patch"
upstream=162798468ddba36673cbe166e51db6b7902235e958f09b6292f83d19b9ea9f03
patched=2b2082a91da33d6e8d2bfb296283f2837f273a5fe5cf6ba273e8b857f5341506
package=
for candidate in "$cache/packages/vibe-serialization/1.2.0/vibe-serialization" "$cache/packages/vibe-serialization-1.2.0/vibe-serialization"; do
    if [ -f "$candidate/source/vibe/data/json.d" ]; then
        if [ -n "$package" ]; then
            echo "Ambiguous vibe-serialization 1.2.0 package roots; refusing to patch" >&2
            exit 1
        fi
        package=$candidate
    fi
done
if [ -z "$package" ]; then
    echo "vibe-serialization 1.2.0 missing; first run dub fetch vibe-serialization --version=1.2.0" >&2
    exit 1
fi
source_file="$package/source/vibe/data/json.d"
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
    *) echo "Unexpected vibe-serialization 1.2.0 json.d SHA256; refusing to patch" >&2; exit 1 ;;
esac
if [ "$(source_hash)" != "$patched" ]; then
    echo "vibe-serialization 1.2.0 streaming patch SHA256 mismatch" >&2
    exit 1
fi
# Clear only this dependency version, including its copied archive, even on an
# already-patched cache. Container recipes invalidate their workspace consumers.
rm -rf -- "$cache/cache/vibe-serialization/1.2.0" "$package/.dub/build"
rm -f -- "$package/libvibe-serialization.a"
printf '%s\n' "vibe-serialization 1.2.0 streaming patch ready ($patched)"
