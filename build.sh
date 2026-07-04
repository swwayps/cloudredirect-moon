#!/usr/bin/env bash
# Reproducibly build the 32-bit cloud_redirect.so from this tree.
#
# Builds inside the glibc-2.35 container (Dockerfile.builder) so the result
# loads in the Steam runtime, then copies cloud_redirect.so next to this script.
#
# Usage:  ./build.sh
# Needs:  podman or docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="cloudredirect-moon-builder"

runtime=""
for c in podman docker; do
	if command -v "$c" >/dev/null 2>&1; then runtime="$c"; break; fi
done
[ -n "$runtime" ] || { echo "need podman or docker" >&2; exit 1; }

# Pin the build id so the container's view of the worktree (which may show
# spurious diffs across the bind mount) doesn't mark the version "-dirty".
GIT_SHA="$(git -C "$HERE" rev-parse --short=7 HEAD 2>/dev/null || echo unknown)"

echo "==> building builder image ($IMAGE)"
"$runtime" build -f "$HERE/Dockerfile.builder" -t "$IMAGE" "$HERE"

echo "==> building 32-bit cloud_redirect.so in container (sha $GIT_SHA)"
"$runtime" run --rm -v "$HERE":/build:Z -w /build "$IMAGE" bash -c "
  set -e
  cmake -S . -B build -DLINUX_32BIT=ON -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc-12 -DCMAKE_CXX_COMPILER=g++-12 \
        -DCR_GIT_SHA=$GIT_SHA >/dev/null
  cmake --build build --target cloud_redirect -j\"\$(nproc)\"
"

cp -f "$HERE/build/cloud_redirect.so" "$HERE/cloud_redirect.so"
chmod 755 "$HERE/cloud_redirect.so"

echo "==> done: $HERE/cloud_redirect.so"
file "$HERE/cloud_redirect.so"
# Sanity: must be 32-bit, must NOT require glibc newer than the Steam runtime.
if file -b "$HERE/cloud_redirect.so" | grep -q "ELF 32-bit"; then
	echo "OK: 32-bit"
else
	echo "ERROR: not 32-bit" >&2; exit 1
fi
if readelf -V "$HERE/cloud_redirect.so" 2>/dev/null | grep -qE "GLIBC_ABI_GNU_TLS|GLIBC_2\.3[6-9]|GLIBC_2\.4[0-9]"; then
	echo "ERROR: links against too-new glibc (won't load in Steam runtime)" >&2
	exit 1
fi
echo "OK: glibc symbols within Steam-runtime range"
