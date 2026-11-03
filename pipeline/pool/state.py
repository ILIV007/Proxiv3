"""Per-server verification history — OUR data asset, persisted on the data branch.

state = {"servers": {server_id: {"hist": "1011…", "rtt": int|None, "seen": unix}},
         "sources": {source_id: {"found": n, "verified": n, "ts": unix}}}
server_id = sha1("ip|port")[:12]; hist is capped at the last 96 run results.
"""
from __future__ import annotations

import hashlib
import json

HIST_CAP = 96
STALE_AFTER = 30 * 86400


def server_id(ip: str, port: int) -> str:
    return hashlib.sha1(f"{ip}|{port}".encode()).hexdigest()[:12]


class State:
    def __init__(self, data: dict | None = None):
        self.data = data or {"servers": {}, "sources": {}}

    @classmethod
    def load(cls, path: str) -> "State":
        try:
            with open(path, encoding="utf-8") as f:
                return cls(json.load(f))
        except (OSError, ValueError):
            return cls()

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, separators=(",", ":"), sort_keys=True)

    def record(self, sid: str, verified: bool, now: int, rtt: int | None) -> None:
        s = self.data["servers"].setdefault(sid, {"hist": "", "rtt": None, "seen": 0})
        s["hist"] = (s["hist"] + ("1" if verified else "0"))[-HIST_CAP:]
        if rtt is not None:
            s["rtt"] = rtt
        s["seen"] = now

    def stats(self, sid: str) -> dict:
        s = self.data["servers"].get(sid)
        if not s or not s["hist"]:
            return {"uptime": None, "checks": 0}
        hist = s["hist"]
        return {"uptime": hist.count("1") / len(hist), "checks": len(hist)}

    def record_source(self, source_id: str, found: int, verified: int, now: int) -> None:
        self.data["sources"][source_id] = {"found": found, "verified": verified, "ts": now}

    def prune(self, now: int) -> None:
        self.data["servers"] = {
            k: v for k, v in self.data["servers"].items() if now - v.get("seen", 0) <= STALE_AFTER
        }
