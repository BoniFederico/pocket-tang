# Development setup

## Host (Linux or WSL 2)

Ubuntu 24.04 packages:

```sh
sudo apt-get install -y build-essential clang-18 clang-tidy-18 clang-format-18 libclang-rt-18-dev \
    cmake ninja-build git python3 python3-venv cppcheck lcov gcovr \
    clevis tang jose cryptsetup jq
```

Host build with sanitizers and tests:

```sh
cmake -S . -B build/host -G Ninja -DCMAKE_BUILD_TYPE=Debug -DPT_SANITIZE=ON
cmake --build build/host
ctest --test-dir build/host --output-on-failure
```

Fuzzing (clang required):

```sh
CC=clang cmake -S . -B build/fuzz -G Ninja -DPT_FUZZ=ON
cmake --build build/fuzz
build/fuzz/core/fuzz/fuzz_json -max_total_time=60 core/fuzz/corpus/json
```

## ESP-IDF

Pocket Tang targets **ESP-IDF v5.5.6** (see ADR-0001).

```sh
git clone --branch v5.5.6 --depth 1 --recursive https://github.com/espressif/esp-idf.git ~/esp/idf
~/esp/idf/install.sh esp32,esp32c3,esp32s3
. ~/esp/idf/export.sh
idf.py -C firmware set-target esp32
idf.py -C firmware build flash monitor
```

On WSL 2 the serial port is not visible inside Linux by default; flash from Windows with
`py -m esptool` (see `tools/hil/README.md`) or attach the device with `usbipd`.

## Hardware-in-the-loop tests

Create `.env.test` at the repository root (git-ignored):

```
TEST_WIFI_SSID=your-2.4GHz-network
TEST_WIFI_PASSWORD=...
```

Then run `python tools/hil/pt_hil.py --port COM3 all --build-dir out/esp32-test`. See `tools/hil/README.md`.
