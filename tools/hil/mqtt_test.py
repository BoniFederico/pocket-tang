"""MQTT / Home Assistant integration checks against a real broker (hardware-in-the-loop).

Requires mosquitto_sub / mosquitto_pub on PATH and a broker the board can reach. Used by
`pt_hil.py mqtt`. Nothing secret is published: the checks also assert that no private key
material ("d") appears in any message.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time


class Sniffer:
    """Collects every message on the broker (topic, payload, retained flag)."""

    def __init__(self, host: str, port: int = 1883, topics=("#",)):
        exe = shutil.which("mosquitto_sub")
        if exe is None:
            raise RuntimeError("mosquitto_sub not found")
        args = [exe, "-h", host, "-p", str(port), "-v", "-F", "%r %t %p"]
        for t in topics:
            args += ["-t", t]
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="replace")
        self.msgs: list[tuple[float, bool, str, str]] = []
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            parts = line.split(" ", 2)
            if len(parts) < 2:
                continue
            retained = parts[0] == "1"
            topic = parts[1]
            payload = parts[2] if len(parts) > 2 else ""
            with self.lock:
                self.msgs.append((time.time(), retained, topic, payload))

    def since(self, t0: float, topic_filter=None):
        with self.lock:
            return [m for m in self.msgs if m[0] >= t0 and (topic_filter is None or topic_filter(m[2]))]

    def wait(self, pred, timeout: float, t0: float = 0.0):
        end = time.time() + timeout
        while time.time() < end:
            for m in self.since(t0):
                if pred(m):
                    return m
            time.sleep(0.1)
        return None

    def close(self):
        self.proc.terminate()


def pub(host: str, topic: str, payload: str, port: int = 1883, retain: bool = False):
    args = [shutil.which("mosquitto_pub"), "-h", host, "-p", str(port), "-t", topic, "-m", payload]
    if retain:
        args.append("-r")
    subprocess.run(args, check=True, timeout=10)


def check_discovery(payload: str) -> dict:
    d = json.loads(payload)
    cmps = d.get("cmps", {})
    platforms = sorted({c["p"] for c in cmps.values()})
    need = {"recovery", "last_unlock", "last_client", "unlocks", "denied", "rssi", "uptime",
            "version", "thp_sig", "thp_exc", "lock", "restart"}
    return {
        "has_dev_and_origin": "dev" in d and "o" in d and "name" in d["o"],
        "availability_topic": d.get("avty_t", ""),
        "components_present": need.issubset(cmps.keys()),
        "platforms": platforms,
        "unique_ids": all("uniq_id" in c for c in cmps.values()),
        "event_types": cmps.get("recovery", {}).get("evt_typ"),
        "button_restart_class": cmps.get("restart", {}).get("dev_cla") == "restart",
        "size": len(payload),
    }
