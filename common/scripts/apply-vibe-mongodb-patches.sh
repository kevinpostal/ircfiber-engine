#!/usr/bin/env bash
# Patch only the pinned vibe-d aggregate cursor timeout behavior.
# Run after dub fetch with the shared DUB-cache lock held.
set -euo pipefail

if [ "$#" -gt 1 ]; then
    echo "usage: bash $0 [dub-cache-root]" >&2
    exit 2
fi
cache=${1:-"$HOME/.dub"}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
patch_file="$script_dir/../patches/vibe-d-0.10.3-aggregate-getmore.patch"
upstream=6794d7866ecba23bd5877d1fc56ca8f3fd8cf589ee2585f82c6a458aa17cd4b9
patched=9dae56d1414839c625fc4baeec77f9c2237f72fe02283fc260494b8f191c7af6
packages=()
for candidate in "$cache/packages/vibe-d/0.10.3/vibe-d" "$cache/packages/vibe-d-0.10.3/vibe-d"; do
    if [ -f "$candidate/mongodb/vibe/db/mongo/collection.d" ]; then
        packages+=("$candidate")
    fi
done
if [ "${#packages[@]}" -eq 0 ]; then
    echo "vibe-d 0.10.3 missing; first run dub fetch vibe-d --version=0.10.3" >&2
    exit 1
fi
source_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}
# Validate every cached copy before mutating any of them.
for package in "${packages[@]}"; do
    source_file="$package/mongodb/vibe/db/mongo/collection.d"
    case "$(source_hash "$source_file")" in
        "$upstream"|"$patched") ;;
        *) echo "Unexpected vibe-d 0.10.3 collection.d SHA256; refusing to patch: $package" >&2; exit 1 ;;
    esac
done
for package in "${packages[@]}"; do
    source_file="$package/mongodb/vibe/db/mongo/collection.d"
    if [ "$(source_hash "$source_file")" = "$upstream" ]; then
        patch --batch --forward --fuzz=0 -p1 -d "$package" < "$patch_file"
    fi
    if [ "$(source_hash "$source_file")" != "$patched" ]; then
        echo "vibe-d 0.10.3 aggregate getMore patch SHA256 mismatch: $package" >&2
        exit 1
    fi
done
# Remove only artifacts for the affected dependency version.
rm -rf -- "$cache/cache/vibe-d/0.10.3"
for package in "${packages[@]}"; do
    rm -rf -- "$package/.dub/build"
    rm -f -- "$package/libvibe-d.a"
done
printf '%s\n' "vibe-d 0.10.3 aggregate getMore patch ready ($patched)"
