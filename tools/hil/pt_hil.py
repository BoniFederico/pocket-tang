#!/usr/bin/env python3
"""Hardware-in-the-loop test runner for Pocket Tang.

Runs on the machine the board is attached to. Flashes a *test* build (with the serial test
console), provisions Wi-Fi over the console, then exercises the device over the LAN: clevis
interop (through WSL or a local Linux shell), latency, memory, stress, reboot persistence and
key rotation. Results are written as JSON and Markdown to hil-artifacts/.

Never burns eFuses and never enables flash encryption or secure boot.

Usage examples (Windows, board on COM3, firmware built in WSL):
    py tools/hil/pt_hil.py --port COM3 flash --build-dir \\\\wsl$\\Ubuntu\\root\\build\\fw-esp32-test
    py tools/hil/pt_hil.py --port COM3 provision
    py tools/hil/pt_hil.py --port COM3 all
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import serial  # pyserial

ROOT = pathlib.Path(__file__).resolve().parents[2]
ART = ROOT / "hil-artifacts"

# A valid P-521 client point (public part of an ECMR key generated with jose; not secret).
CLIENT_JWK = json.loads((ROOT / "core/tests/fixtures/tang14/rec_req.json").read_text())


# ----------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def load_env() -> dict[str, str]:
    env = {}
    p = ROOT / ".env.test"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    env.update({k: v for k, v in os.environ.items() if k.startswith("TEST_")})
    return env


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def thumbprint(jwk: dict, alg: str = "sha256") -> str:
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                       separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.new(alg, canon.encode()).digest())


def http(method: str, url: str, body: bytes | None = None, timeout: float = 30.0):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/jwk+json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers.get("Content-Type"), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type"), e.read()


def adv_keys(base: str) -> list[dict]:
    st, _, body = http("GET", f"{base}/adv")
    if st != 200:
        raise RuntimeError(f"/adv returned {st}")
    jws = json.loads(body)
    return json.loads(b64u_dec(jws["payload"]))["keys"]


def exchange_kid(base: str) -> str:
    for k in adv_keys(base):
        if "deriveKey" in k.get("key_ops", []):
            return thumbprint(k)
    raise RuntimeError("no exchange key advertised")


def run_wsl(cmd: str, timeout: int = 900) -> subprocess.CompletedProcess:
    if platform.system() == "Windows":
        argv = ["wsl", "-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", cmd]
    else:
        argv = ["bash", "-lc", cmd]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def repo_in_wsl() -> str:
    if platform.system() != "Windows":
        return str(ROOT)
    drive = ROOT.drive.rstrip(":").lower()
    return f"/mnt/{drive}" + ROOT.as_posix()[2:]


# ----------------------------------------------------------------------------------------------
# serial console
# ----------------------------------------------------------------------------------------------

class Board:
    """Serial connection that does not reset the board on open (DTR/RTS released)."""

    def __init__(self, port: str, baud: int = 115200):
        self.port = port
        self.ser = serial.Serial()
        self.ser.port = port
        self.ser.baudrate = baud
        self.ser.timeout = 0.2
        self.ser.dtr = False
        self.ser.rts = False
        self.ser.open()
        self.lines: list[str] = []
        self.secrets: list[str] = []
        self.logfile = open(ART / "serial.log", "a", encoding="utf-8")

    def close(self):
        self.ser.close()
        self.logfile.close()

    def reset(self):
        """Pulse EN through RTS (DevKit auto-reset circuit), keeping GPIO0 high."""
        self.ser.dtr = False
        self.ser.rts = True
        time.sleep(0.15)
        self.ser.rts = False

    def set_boot_button(self, pressed: bool):
        """Drive GPIO0 low through DTR while RTS (EN) stays released.

        On the usual DevKit auto-reset circuit, DTR=1/RTS=0 pulls IO0 low; at runtime this is the
        same as holding the BOOT button.
        """
        self.ser.rts = False
        self.ser.dtr = pressed

    def readline_until(self, pattern: str, timeout: float) -> re.Match | None:
        rx = re.compile(pattern)
        end = time.time() + timeout
        buf = b""
        while time.time() < end:
            chunk = self.ser.read(512)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = re.sub(r"\x1b\[[0-9;]*m", "", raw.decode("utf-8", "replace")).rstrip("\r")
                self.lines.append(line)
                self.logfile.write(line + "\n")
                m = rx.search(line)
                if m:
                    return m
        return None

    def command(self, cmd: str, expect: str, timeout: float = 10.0) -> re.Match | None:
        self.ser.reset_input_buffer()
        self.ser.write(b"\r\n")
        time.sleep(0.2)
        self.ser.write(cmd.encode() + b"\r\n")
        return self.readline_until(expect, timeout)

    def stats(self) -> dict[str, str]:
        m = self.command("stats", r"PT_STATS (.*)$", 10)
        if not m:
            raise RuntimeError("no PT_STATS line")
        return dict(kv.split("=", 1) for kv in m.group(1).split())


# ----------------------------------------------------------------------------------------------
# steps
# ----------------------------------------------------------------------------------------------

def step_chip(args) -> dict:
    """Read-only chip identification (no eFuse writes)."""
    out = subprocess.run([sys.executable, "-m", "esptool", "--port", args.port, "chip-id"],
                         capture_output=True, text=True, timeout=60).stdout
    info = {}
    for key in ("Chip type", "Features", "Crystal frequency", "MAC"):
        m = re.search(rf"{key}:\s*(.+)", out)
        if m:
            info[key] = m.group(1).strip()
    log(f"chip: {info}")
    return info


def step_flash(args) -> None:
    bdir = pathlib.Path(args.build_dir)
    # SAFETY: never flash an image that enables Secure Boot or flash encryption. Its first boot
    # burns eFuses irreversibly. The HIL runner only ever flashes development images.
    sdk = (bdir / "sdkconfig").read_text(encoding="utf-8") if (bdir / "sdkconfig").exists() else ""
    if not sdk:
        raise SystemExit(f"refusing to flash: no sdkconfig next to the images in {bdir}")
    for danger in ("CONFIG_SECURE_BOOT=y", "CONFIG_SECURE_FLASH_ENC_ENABLED=y",
                   "CONFIG_SECURE_BOOT_V1_ENABLED=y", "CONFIG_SECURE_BOOT_V2_ENABLED=y"):
        if re.search(rf"^{re.escape(danger)}$", sdk, re.M):
            raise SystemExit(f"refusing to flash {bdir}: {danger} would burn eFuses irreversibly")
    fa = json.loads((bdir / "flasher_args.json").read_text())
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="pt-fw-"))
    cmd = [sys.executable, "-m", "esptool", "--chip", fa["extra_esptool_args"]["chip"],
           "--port", args.port, "--baud", "460800", "--before", "default-reset",
           "--after", "hard-reset", "write-flash"]
    cmd += [a for a in fa["write_flash_args"]]
    for off, rel in sorted(fa["flash_files"].items(), key=lambda kv: int(kv[0], 16)):
        dst = tmp / pathlib.Path(rel).name
        shutil.copy(bdir / rel, dst)
        cmd += [off, str(dst)]
    if args.erase:
        log("erasing flash (NVS, keys) before flashing")
        subprocess.run([sys.executable, "-m", "esptool", "--port", args.port, "erase-flash"],
                       check=True, timeout=120)
    log("flashing " + " ".join(cmd[cmd.index("write-flash") + 1:]))
    # CP210x links occasionally drop at high baud rates; one retry is cheap and safe.
    if subprocess.run(cmd, timeout=300).returncode != 0:
        log("flashing failed, retrying once")
        subprocess.run(cmd, check=True, timeout=300)


def step_provision(board: Board, env: dict, args) -> str:
    ssid, pw = env.get("TEST_WIFI_SSID"), env.get("TEST_WIFI_PASSWORD")
    if not ssid or not pw:
        raise SystemExit("TEST_WIFI_SSID / TEST_WIFI_PASSWORD missing (.env.test)")
    board.secrets.append(pw)
    board.reset()
    board.readline_until(r"pt>|Pocket Tang", 15)
    time.sleep(1.5)
    # The password is passed on the serial line only; it is never logged by the firmware.
    m = board.command(f'provision "{ssid}" "{pw}" -n {args.hostname} -p {args.http_port}',
                      r"PT_PROVISION (\S+)", 10)
    if not m or m.group(1) != "OK":
        raise RuntimeError(f"provisioning failed: {m.group(1) if m else 'no answer'}")
    log("provisioned; rebooting")
    return wait_ready(board, reboot=True)


def wait_ready(board: Board, reboot: bool = True, timeout: float = 60) -> str:
    if reboot:
        board.reset()
    t0 = time.time()
    m = board.readline_until(r"PT_READY mode=\w+ ip=(\S+) port=(\d+)", timeout)
    if not m or not m.group(1) or m.group(1) == "":
        raise RuntimeError("device did not report PT_READY with an IP address")
    log(f"device ready at {m.group(1)}:{m.group(2)} after {time.time() - t0:.1f}s")
    return f"http://{m.group(1)}" + ("" if m.group(2) == "80" else f":{m.group(2)}")


def step_interop(base: str) -> dict:
    log(f"clevis interop against {base} (via WSL)")
    r = run_wsl(f"cd {repo_in_wsl()} && bash tools/interop.sh --url {base}")
    (ART / "interop.log").write_text(r.stdout + r.stderr, encoding="utf-8")
    m = re.search(r"== (\d+) passed, (\d+) failed", r.stdout)
    res = {"passed": int(m.group(1)) if m else 0, "failed": int(m.group(2)) if m else -1}
    log(f"interop: {res}")
    return res


def step_latency(base: str, n: int) -> dict:
    kid = exchange_kid(base)
    body = json.dumps(CLIENT_JWK).encode()
    rec, adv = [], []
    for _ in range(n):
        t0 = time.perf_counter()
        st, _, _ = http("POST", f"{base}/rec/{kid}", body)
        rec.append((time.perf_counter() - t0) * 1000)
        if st != 200:
            raise RuntimeError(f"/rec returned {st}")
    for _ in range(n):
        t0 = time.perf_counter()
        st, _, _ = http("GET", f"{base}/adv")
        adv.append((time.perf_counter() - t0) * 1000)

    def summary(v):
        v = sorted(v)
        return {"n": len(v), "min": round(v[0], 1), "p50": round(statistics.median(v), 1),
                "p95": round(v[int(0.95 * (len(v) - 1))], 1), "max": round(v[-1], 1),
                "mean": round(statistics.fmean(v), 1)}

    res = {"rec_ms": summary(rec), "adv_ms": summary(adv)}
    log(f"latency: {res}")
    return res


def step_stress(base: str, seconds: int, workers: int) -> dict:
    """Concurrent valid and hostile requests; the device must stay up and keep answering."""
    kid = exchange_kid(base)
    good = json.dumps(CLIENT_JWK).encode()
    host, port = base.split("//")[1].split(":")[0], int(base.rsplit(":", 1)[1]) if base.count(":") > 1 else 80
    hostile = [
        ("POST", f"/rec/{kid}", b"{" * 1500),
        ("POST", f"/rec/{kid}", b'{"kty":"EC","crv":"P-521","x":"AA","y":"AA"}'),
        ("POST", f"/rec/{kid}", b"A" * 3000),
        ("GET", "/adv/" + "A" * 300, None),
        ("POST", "/rec/AAAA", good),
        ("DELETE", "/adv", None),
    ]
    counts: dict[str, int] = {}
    end = time.time() + seconds

    def slowloris():
        # Open a connection and dribble a header byte per second; must not block others.
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"POST /rec/x HTTP/1.1\r\n")
            while time.time() < end:
                s.sendall(b"X")
                time.sleep(1)
            s.close()
        except OSError:
            pass
        return "slowloris"

    def worker(i):
        local: dict[str, int] = {}
        j = 0
        while time.time() < end:
            if i % 3 == 0:
                m, p, b = hostile[j % len(hostile)]
            elif i % 3 == 1:
                m, p, b = "POST", f"/rec/{kid}", good
            else:
                m, p, b = "GET", "/adv", None
            j += 1
            try:
                st, _, _ = http(m, base + p, b, timeout=15)
                key = str(st)
            except Exception as e:  # noqa: BLE001 - count every failure mode
                key = type(e).__name__
            local[key] = local.get(key, 0) + 1
        return local

    with cf.ThreadPoolExecutor(max_workers=workers + 1) as ex:
        futs = [ex.submit(worker, i) for i in range(workers)] + [ex.submit(slowloris)]
        for f in futs:
            r = f.result()
            if isinstance(r, dict):
                for k, v in r.items():
                    counts[k] = counts.get(k, 0) + v
    # Device must still answer correctly afterwards.
    st, _, _ = http("POST", f"{base}/rec/{kid}", good)
    res = {"seconds": seconds, "workers": workers, "responses": counts, "after_stress_rec": st}
    log(f"stress: {res}")
    return res


def step_persistence(board: Board, base: str) -> dict:
    before = sorted(thumbprint(k) for k in adv_keys(base))
    board.command("reboot", r"PT_REBOOT", 5)
    base2 = wait_ready(board, reboot=False)
    after = sorted(thumbprint(k) for k in adv_keys(base2))
    res = {"same_keys_after_reboot": before == after, "keys": after}
    log(f"persistence: {res['same_keys_after_reboot']}")
    return res


def step_rotation(board: Board, base: str) -> dict:
    """Bind with clevis, rotate on the device, check old binding still decrypts."""
    w = repo_in_wsl()
    sig = [thumbprint(k) for k in adv_keys(base) if "verify" in k.get("key_ops", [])][0]
    r1 = run_wsl(f"echo -n rot-secret | clevis encrypt tang '{{\"url\":\"{base}\",\"thp\":\"{sig}\"}}' > /tmp/pt-rot.jwe && echo OK")
    m = board.command("rotate", r"PT_ROTATE (\S+)", 60)
    rotated = bool(m and m.group(1) == "OK")
    new_sig = [thumbprint(k) for k in adv_keys(base) if "verify" in k.get("key_ops", [])][0]
    r2 = run_wsl("clevis decrypt < /tmp/pt-rot.jwe")
    res = {"bound": "OK" in r1.stdout, "rotated": rotated, "signing_key_changed": new_sig != sig,
           "old_binding_decrypts": r2.stdout.strip() == "rot-secret"}
    log(f"rotation: {res}")
    _ = w
    return res


def step_ui(board: Board, base: str, password: str = "hil-admin-pass-1") -> dict:
    """Set an admin password over the test console, enable LAN admin, test the UI."""
    import ui_test
    board.secrets.append(password)
    m = board.command(f'admin "{password}" --lan', r"PT_ADMIN (\S+)", 15)
    if not m or m.group(1) != "OK":
        raise RuntimeError("could not set the admin password")
    board.command("reboot", r"PT_REBOOT", 5)
    base = wait_ready(board, reboot=False)
    kid = exchange_kid(base)
    body = json.dumps(CLIENT_JWK).encode()
    res = ui_test.run(base, password, lambda: http("POST", f"{base}/rec/{exchange_kid(base)}", body)[0])
    _ = kid
    log(f"ui: passed={res['passed']} {res}")
    return res


def step_button(board: Board) -> dict:
    """BOOT button through DTR: medium press enters setup mode (Tang keeps serving)."""
    res = {}
    board.set_boot_button(True)
    res["led_hold_setup"] = board.readline_until(r"PT_LED hold-setup", 6) is not None
    time.sleep(1.5)
    board.set_boot_button(False)
    m = board.readline_until(r"PT_BUTTON up after (\d+)", 5)
    res["held_ms"] = int(m.group(1)) if m else 0
    m = board.readline_until(r"PT_READY mode=(\w+) ip=(\S*)", 45)
    res["mode_after"] = m.group(1) if m else None
    if m and m.group(2):
        st, _, _ = http("GET", f"http://{m.group(2)}/adv")
        res["tang_in_setup_mode"] = st
    # leave setup mode again
    board.command("reboot", r"PT_REBOOT", 5)
    m = board.readline_until(r"PT_READY mode=(\w+)", 45)
    res["mode_after_reboot"] = m.group(1) if m else None
    res["passed"] = (res["led_hold_setup"] and res["mode_after"] == "setup"
                     and res.get("tang_in_setup_mode") == 200 and res["mode_after_reboot"] == "normal")
    log(f"button: {res}")
    return res


def step_factory_reset(board: Board, env: dict, args, base: str) -> dict:
    """BOOT held >= 10 s: keys and settings erased, device back in first-time setup mode."""
    res = {}
    before = sorted(thumbprint(k) for k in adv_keys(base))
    board.set_boot_button(True)
    res["led_hold_setup"] = board.readline_until(r"PT_LED hold-setup", 6) is not None
    res["led_hold_reset"] = board.readline_until(r"PT_LED hold-reset", 10) is not None
    time.sleep(0.5)
    board.set_boot_button(False)
    res["erased"] = board.readline_until(r"factory reset: erasing", 10) is not None
    m = board.readline_until(r"PT_READY mode=(\w+) ip=(\S*)", 45)
    res["mode_after"] = m.group(1) if m else None
    res["unprovisioned"] = bool(m) and m.group(2) == ""
    base2 = step_provision(board, env, args)
    after = sorted(thumbprint(k) for k in adv_keys(base2))
    res["new_keys"] = set(before).isdisjoint(after)
    res["passed"] = all(res[k] for k in ("led_hold_setup", "led_hold_reset", "erased",
                                          "unprovisioned", "new_keys")) and res["mode_after"] == "setup"
    log(f"factory reset: {res}")
    return res


def step_mqtt(board: Board, base: str, broker: str, n: int = 100) -> dict:
    """MQTT / Home Assistant: discovery, events, birth re-announce, lock switch, LWT, restart
    button, and /rec latency with MQTT on vs off (non-interference). Plain MQTT on port 1883."""
    import mqtt_test
    res: dict = {}
    dev = base.split("//")[1].split(":")[0]
    board.command(f"mqtt mqtt://{broker}:1883", r"PT_MQTT_CFG (\S+)", 10)
    sn = mqtt_test.Sniffer(broker, 1883, ("pocket-tang/#", "homeassistant/#"))
    t0 = time.time()
    board.command("reboot", r"PT_REBOOT", 5)
    res["connected"] = board.readline_until(r"PT_MQTT connected", 60) is not None
    d = sn.wait(lambda m: m[2].startswith("homeassistant/device/"), 15, t0)
    res["discovery"] = mqtt_test.check_discovery(d[3]) if d else None
    avty = res["discovery"]["availability_topic"] if d else ""
    prefix = avty.rsplit("/", 1)[0]
    body = json.dumps(CLIENT_JWK).encode()
    kid = exchange_kid(base)
    t1 = time.time()
    http("POST", f"{base}/rec/{kid}", body)
    http("POST", f"{base}/rec/AAAA", body)
    time.sleep(3)  # events are published asynchronously by the low-priority MQTT task
    res["events"] = sorted(json.loads(m[3])["event_type"]
                           for m in sn.since(t1, lambda t: t == prefix + "/event")) if prefix else []
    time.sleep(2)
    t2 = time.time()
    mqtt_test.pub(broker, "homeassistant/status", "online")
    res["rediscovery"] = sn.wait(lambda m: m[2].startswith("homeassistant/device/"), 10, t2) is not None
    mqtt_test.pub(broker, prefix + "/lock/set", "ON")
    time.sleep(1.5)
    res["rec_locked"] = http("POST", f"{base}/rec/{kid}", body)[0]
    mqtt_test.pub(broker, prefix + "/lock/set", "OFF")
    time.sleep(1.5)
    res["rec_unlocked"] = http("POST", f"{base}/rec/{kid}", body)[0]
    time.sleep(3)
    # Non-interference: latency with MQTT on (every recovery publishes an event)
    t3 = time.time()
    on = step_latency(base, n)["rec_ms"]
    time.sleep(3)
    res["events_delivered"] = f"{len(sn.since(t3, lambda t: t == prefix + '/event'))}/{n}"
    # LWT on an abrupt reset, then the restart button
    t4 = time.time()
    board.reset()
    off_msg = sn.wait(lambda m: m[2] == avty and m[3] == "offline", 70, t4)
    res["lwt_offline_s"] = round(off_msg[0] - t4, 1) if off_msg else None
    board.readline_until(r"PT_MQTT connected", 60)
    time.sleep(3)
    mqtt_test.pub(broker, prefix + "/restart", "PRESS")
    res["restart_button"] = board.readline_until(r"PT_READY mode=normal", 45) is not None
    res["no_private_material"] = all('"d"' not in m[3] for m in sn.since(t0))
    sn.close()
    # MQTT off
    board.command(f"mqtt mqtt://{broker}:1883 --off", r"PT_MQTT_CFG (\S+)", 10)
    board.command("reboot", r"PT_REBOOT", 5)
    board.readline_until(r"MQTT integration disabled|PT_READY mode=normal", 45)
    time.sleep(10)
    off = step_latency(base, n)["rec_ms"]
    res["rec_ms_mqtt_on"] = on
    res["rec_ms_mqtt_off"] = off
    res["passed"] = (res["connected"] and bool(res["discovery"])
                     and res["discovery"]["components_present"] and res["events"] == ["denied", "unlock"]
                     and res["rediscovery"] and res["rec_locked"] == 403 and res["rec_unlocked"] == 200
                     and res["events_delivered"] == f"{n}/{n}" and res["restart_button"]
                     and res["no_private_material"] and res["lwt_offline_s"] is not None)
    log(f"mqtt: {res}")
    _ = dev
    return res


def write_report(results: dict) -> None:
    ART.mkdir(exist_ok=True)
    (ART / "hil-results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    log(f"results written to {ART / 'hil-results.json'}")


# ----------------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--hostname", default="pocket-tang-hil")
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--url", help="device base URL (skip provisioning)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("flash")
    f.add_argument("--build-dir", required=True)
    f.add_argument("--erase", action="store_true", help="erase the whole flash first (wipes keys)")
    sub.add_parser("chip")
    sub.add_parser("provision")
    sub.add_parser("stats")
    sub.add_parser("interop")
    lat = sub.add_parser("latency")
    lat.add_argument("-n", type=int, default=50)
    st = sub.add_parser("stress")
    st.add_argument("--seconds", type=int, default=120)
    st.add_argument("--workers", type=int, default=6)
    sub.add_parser("persistence")
    sub.add_parser("rotation")
    sub.add_parser("ui")
    sub.add_parser("button")
    sub.add_parser("factory-reset")
    mq = sub.add_parser("mqtt")
    mq.add_argument("--broker", required=True, help="broker IPv4 reachable from the board")
    mq.add_argument("-n", type=int, default=100)
    al = sub.add_parser("all")
    al.add_argument("--build-dir")
    al.add_argument("-n", type=int, default=50)
    al.add_argument("--stress-seconds", type=int, default=120)
    args = ap.parse_args()

    ART.mkdir(exist_ok=True)
    env = load_env()
    if args.cmd == "chip":
        step_chip(args)
        return 0
    if args.cmd == "flash":
        step_flash(args)
        return 0

    board = Board(args.port)
    try:
        if args.cmd == "provision":
            print(step_provision(board, env, args))
            return 0
        base = args.url
        if args.cmd == "all":
            results: dict = {"date": dt.datetime.now().isoformat(timespec="seconds")}
            results["chip"] = None
            board.close()
            results["chip"] = step_chip(args)
            if args.build_dir:
                args.erase = True
                step_flash(args)
            board = Board(args.port)
            base = step_provision(board, env, args)
            time.sleep(2)
            results["stats_boot"] = board.stats()
            results["latency"] = step_latency(base, args.n)
            results["stats_after_latency"] = board.stats()
            results["interop"] = step_interop(base)
            results["stress"] = step_stress(base, args.stress_seconds, 6)
            results["stats_after_stress"] = board.stats()
            results["persistence"] = step_persistence(board, base)
            results["rotation"] = step_rotation(board, base)
            results["button"] = step_button(board)
            results["ui"] = step_ui(board, base)
            results["factory_reset"] = step_factory_reset(board, env, args, base)
            results["stats_final"] = board.stats()
            write_report(results)
            ok = (results["interop"]["failed"] == 0 and results["stress"]["after_stress_rec"] == 200
                  and results["persistence"]["same_keys_after_reboot"]
                  and results["rotation"]["old_binding_decrypts"]
                  and results["button"]["passed"] and results["ui"]["passed"]
                  and results["factory_reset"]["passed"])
            log("HIL " + ("PASSED" if ok else "FAILED"))
            return 0 if ok else 1
        if base is None:
            m = board.command("stats", r"PT_STATS ip=(\S+)", 10)
            if not m or not m.group(1):
                raise SystemExit("device has no IP; provision first or pass --url")
            base = f"http://{m.group(1)}" + ("" if args.http_port == 80 else f":{args.http_port}")
        if args.cmd == "stats":
            print(json.dumps(board.stats(), indent=2))
        elif args.cmd == "interop":
            return 0 if step_interop(base)["failed"] == 0 else 1
        elif args.cmd == "latency":
            step_latency(base, args.n)
            print(json.dumps(board.stats(), indent=2))
        elif args.cmd == "stress":
            step_stress(base, args.seconds, args.workers)
            print(json.dumps(board.stats(), indent=2))
        elif args.cmd == "persistence":
            step_persistence(board, base)
        elif args.cmd == "rotation":
            step_rotation(board, base)
        elif args.cmd == "ui":
            return 0 if step_ui(board, base)["passed"] else 1
        elif args.cmd == "mqtt":
            r = step_mqtt(board, base, args.broker, args.n)
            write_report({"mqtt": r})
            return 0 if r["passed"] else 1
        elif args.cmd == "factory-reset":
            return 0 if step_factory_reset(board, env, args, base)["passed"] else 1
        elif args.cmd == "button":
            return 0 if step_button(board)["passed"] else 1
        return 0
    finally:
        try:
            board.close()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    sys.exit(main())
