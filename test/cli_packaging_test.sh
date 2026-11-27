#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="$root/build.sh"

grep -q -- '--target cloud_redirect cloud_redirect_cli' "$build"
grep -q 'build64/cloud_redirect_cli' "$build"
grep -q 'build32/cloud_redirect_cli32' "$build"
grep -q 'cp -f.*cloud_redirect_cli' "$build"
grep -q 'cp -f.*cloud_redirect32.so' "$build"

echo "cli packaging test passed"
