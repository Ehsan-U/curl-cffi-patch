#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "${1:?Usage: build_windows_fingerprints.sh /absolute/build/directory}"
work_dir=$(cd "$1" && pwd)
uv run --no-project python "$project_root/scripts/build_native.py" "$work_dir/archive"
cd "$project_root"
IMPERSONATE_BUILD_DIR="$work_dir/archive" IMPERSONATE_LINK_TYPE=static uv pip install --no-cache --reinstall-package curl-cffi-patch -e '.[test,dev,integration]'
