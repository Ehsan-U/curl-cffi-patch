#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "$0")/.." && pwd)
if [ "$(uname -s)" = Linux ]; then
    if command -v apk >/dev/null; then
        apk add --no-cache build-base autoconf automake libtool cmake ninja pkgconf patch unzip linux-headers libstdc++-static
    else
        yum install -y autoconf automake libtool pkgconfig patch unzip
        uv tool install ninja==1.13.0
        export PATH="$(uv tool dir --bin):$PATH"
    fi
fi
python3 "$project_root/scripts/build_native.py" "$IMPERSONATE_BUILD_DIR"
