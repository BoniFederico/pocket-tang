#!/usr/bin/env python3
"""Generate the ESP Web Tools manifest for the merged release images in a directory.

    tools/gen-manifest.py <dir> <version>

Looks for pocket-tang-v<version>-<target>.bin (merged images flashed at 0x0) and writes
<dir>/manifest.json (https://esphome.github.io/esp-web-tools/ manifest format).
"""
import json
import pathlib
import sys

CHIPS = {"esp32": "ESP32", "esp32c3": "ESP32-C3", "esp32s3": "ESP32-S3"}


def main() -> int:
    d = pathlib.Path(sys.argv[1])
    version = sys.argv[2].lstrip("v")
    builds = []
    for target, family in CHIPS.items():
        img = d / f"pocket-tang-v{version}-{target}.bin"
        if img.exists():
            builds.append({"chipFamily": family, "parts": [{"path": img.name, "offset": 0}]})
    if not builds:
        print(f"no merged images for v{version} in {d}", file=sys.stderr)
        return 1
    manifest = {
        "name": "Pocket Tang",
        "version": version,
        "new_install_prompt_erase": True,
        "builds": builds,
    }
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"manifest for v{version}: {[b['chipFamily'] for b in builds]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
