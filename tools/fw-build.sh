#!/usr/bin/env bash
# Build the firmware for one target and profile and stage flashable artefacts.
#
#   tools/fw-build.sh <target> [profile] [build-root]
#
# target:  esp32 | esp32c3 | esp32s3
# profile: default | test | <name of firmware/profiles/sdkconfig.<name>.defaults>
# Output:  out/<target>-<profile>/ with bootloader, partition table, app, flasher_args.json,
#          a merged image (pocket-tang-<target>-<profile>.bin) and SHA256SUMS.
set -euo pipefail
TARGET=${1:?target}
PROFILE=${2:-default}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD_ROOT=${3:-${PT_BUILD_ROOT:-$ROOT/build}}
BUILD="$BUILD_ROOT/fw-$TARGET-$PROFILE"
OUT="$ROOT/out/$TARGET-$PROFILE"

if ! command -v idf.py >/dev/null; then
    export IDF_TOOLS_PATH=${IDF_TOOLS_PATH:-/opt/esp/tools}
    # shellcheck disable=SC1091
    . "${IDF_PATH:-/opt/esp/idf}/export.sh" >/dev/null
fi

DEFAULTS="sdkconfig.defaults"
if [ "$PROFILE" != default ]; then
    for p in ${PROFILE//+/ }; do DEFAULTS="$DEFAULTS;profiles/sdkconfig.$p.defaults"; done
fi
cd "$ROOT/firmware"
idf.py -B "$BUILD" -DSDKCONFIG="$BUILD/sdkconfig" -DSDKCONFIG_DEFAULTS="$DEFAULTS" \
    set-target "$TARGET" build

rm -rf "$OUT" && mkdir -p "$OUT"
cp "$BUILD/bootloader/bootloader.bin" "$BUILD/partition_table/partition-table.bin" \
    "$BUILD/pocket-tang.bin" "$BUILD/flasher_args.json" "$BUILD/sdkconfig" "$OUT/"
cp "$BUILD/pocket-tang.elf" "$OUT/" 2>/dev/null || true
# flasher_args.json refers to files relative to the build dir; rewrite to flat names.
python3 - "$OUT/flasher_args.json" <<'PY'
import json, os, sys
p = sys.argv[1]
d = json.load(open(p))
d["flash_files"] = {k: os.path.basename(v) for k, v in d["flash_files"].items()}
for sect in ("bootloader", "partition-table", "app"):
    if sect in d:
        d[sect]["file"] = os.path.basename(d[sect]["file"])
json.dump(d, open(p, "w"), indent=2)
PY
(cd "$OUT" && python3 -m esptool --chip "$TARGET" merge-bin -o "pocket-tang-$TARGET-$PROFILE.bin" \
    @flash_args >/dev/null 2>&1 || esptool.py --chip "$TARGET" merge_bin -o "pocket-tang-$TARGET-$PROFILE.bin" \
    $(python3 -c "import json;d=json.load(open('flasher_args.json'));print(' '.join(d['write_flash_args']+[x for kv in sorted(d['flash_files'].items()) for x in kv]))"))
(cd "$OUT" && sha256sum ./*.bin > SHA256SUMS)
echo "staged $OUT"
ls -la "$OUT"
