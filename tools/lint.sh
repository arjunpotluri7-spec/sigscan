#!/usr/bin/env bash
# Runs the same lint steps as CI: clang-format check on all sources, clang-tidy on the library.
# Expects the pinned tools from tools/requirements.txt on PATH (for example in .tools/bin) and a
# configured dev build (cmake --preset dev) for compile_commands.json.
set -euo pipefail
cd "$(dirname "$0")/.."

sources=$(find src include tests fuzz -name '*.cpp' -o -name '*.hpp' | sort)
clang-format --dry-run --Werror $sources
echo "clang-format: ok"

extra=()
if [[ "$(uname)" == "Darwin" ]]; then
  # The pip clang-tidy does not know the macOS SDK; point it at the SDK and its libc++ headers.
  sdk=$(xcrun --show-sdk-path)
  extra=(--extra-arg="-isysroot${sdk}" --extra-arg="-isystem${sdk}/usr/include/c++/v1")
fi
clang-tidy -p build/dev --quiet "${extra[@]}" src/lib/*.cpp
echo "clang-tidy: ok"
