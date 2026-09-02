#!/usr/bin/env bash
set -euo pipefail

min_py="3.10"
py=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if python3 -c "exit(0 if tuple(map(int,'$py'.split('.'))) >= tuple(map(int,'$min_py'.split('.'))) else 1)"; then
    echo "python $py ok"
else
    echo "need python >= $min_py (found $py)" >&2; exit 1
fi

pip install -e ".[dev]"

echo
echo "checking android sdk..."
if command -v sdkmanager &>/dev/null; then
    echo "  sdkmanager: $(which sdkmanager)"
else
    echo "  sdkmanager not found — run: golem sdk install"
fi

echo
echo "checking adb..."
if command -v adb &>/dev/null; then
    echo "  adb: $(adb version | head -1)"
else
    echo "  adb not found — install android-tools"
fi

echo
echo "done. run: golem --help"
