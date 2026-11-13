#!/usr/bin/env bash
# Formatting and static analysis for the host-buildable code (core/, host/, firmware/ C sources).
# Usage: tools/lint.sh [--fix] [--no-tidy]
set -euo pipefail
cd "$(dirname "$0")/.."

FIX=0
TIDY=1
for a in "$@"; do
    case "$a" in
    --fix) FIX=1 ;;
    --no-tidy) TIDY=0 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
    esac
done

CLANG_FORMAT=${CLANG_FORMAT:-clang-format}
CLANG_TIDY=${CLANG_TIDY:-clang-tidy}
mapfile -t FILES < <(git ls-files --cached --others --exclude-standard 'core/**/*.c' 'core/**/*.h' 'host/**/*.c' 'host/**/*.h' \
    'firmware/main/*.c' 'firmware/main/*.h' 'firmware/components/**/*.c' 'firmware/components/**/*.h')

echo "== clang-format (${#FILES[@]} files)"
if [ "$FIX" = 1 ]; then
    "$CLANG_FORMAT" -i "${FILES[@]}"
else
    "$CLANG_FORMAT" --dry-run --Werror "${FILES[@]}"
fi

echo "== cppcheck"
cppcheck --std=c17 --language=c --enable=warning,style,performance,portability \
    --inline-suppr --error-exitcode=1 --quiet \
    --suppress=missingIncludeSystem --suppress=unusedFunction --suppress=unmatchedSuppression \
    --suppress=checkersReport \
    -DMBEDTLS_ECP_DP_SECP521R1_ENABLED -DMBEDTLS_SHA1_C -DMBEDTLS_SHA224_C -DMBEDTLS_SHA256_C \
    -DMBEDTLS_SHA384_C -DMBEDTLS_SHA512_C -DMBEDTLS_ECDSA_DETERMINISTIC \
    -I core/include core/src core/crypto host

if [ "$TIDY" = 1 ]; then
    echo "== clang-tidy"
    BUILD=build/tidy
    cmake -S . -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DBUILD_TESTING=OFF >/dev/null
    mapfile -t TIDY_FILES < <(git ls-files --cached --others --exclude-standard 'core/src/*.c' 'core/crypto/**/*.c' 'host/*.c')
    if [ "${#TIDY_FILES[@]}" -gt 0 ]; then
        "$CLANG_TIDY" -p "$BUILD" --quiet "${TIDY_FILES[@]}"
    fi
fi
echo "lint OK"
