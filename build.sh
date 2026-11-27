#!/usr/bin/env bash
# Reproducibly build the 64-bit hook and CLI, plus legacy 32-bit artifacts.
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

echo "==> building 64-bit CloudRedirect hook + CLI in container (sha $GIT_SHA)"
"$runtime" run --rm -v "$HERE":/build:Z -w /build "$IMAGE" bash -c "
  set -e
  cmake -S . -B build64 -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc-12 -DCMAKE_CXX_COMPILER=g++-12 \
        -DCR_GIT_SHA=$GIT_SHA >/dev/null
  cmake --build build64 --target cloud_redirect cloud_redirect_cli -j\"\$(nproc)\"
  cmake -S . -B build32 -DLINUX_32BIT=ON -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc-12 -DCMAKE_CXX_COMPILER=g++-12 \
        -DCR_GIT_SHA=$GIT_SHA >/dev/null
  cmake --build build32 --target cloud_redirect cloud_redirect_cli -j\"\$(nproc)\"
"

cp -f "$HERE/build64/cloud_redirect.so" "$HERE/cloud_redirect.so"
cp -f "$HERE/build64/cloud_redirect_cli" "$HERE/cloud_redirect_cli"
cp -f "$HERE/build32/cloud_redirect32.so" "$HERE/cloud_redirect32.so"
cp -f "$HERE/build32/cloud_redirect_cli32" "$HERE/cloud_redirect_cli32"
chmod 755 "$HERE/cloud_redirect.so"
chmod 755 "$HERE/cloud_redirect_cli"
chmod 755 "$HERE/cloud_redirect32.so"
chmod 755 "$HERE/cloud_redirect_cli32"

echo "==> done"
for artifact in "$HERE/cloud_redirect.so" "$HERE/cloud_redirect_cli" \
               "$HERE/cloud_redirect32.so" "$HERE/cloud_redirect_cli32"; do
	file "$artifact"
	expected="64-bit"
	case "$(basename "$artifact")" in
		*32*) expected="32-bit" ;;
	esac
	if ! file -b "$artifact" | grep -q "ELF $expected"; then
		echo "ERROR: $(basename "$artifact") is not $expected" >&2; exit 1
	fi
	if readelf -V "$artifact" 2>/dev/null | grep -qE "GLIBC_ABI_GNU_TLS|GLIBC_2\.3[6-9]|GLIBC_2\.4[0-9]"; then
		echo "ERROR: $(basename "$artifact") links against too-new glibc" >&2
		exit 1
	fi
done
echo "OK: 64-bit primary and 32-bit legacy artifacts are Steam-runtime compatible"
