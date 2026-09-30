"""Persistent state for wg-monitor."""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any


DEFAULT_STATE = {
    "updated_at": None,
    "next_check_at": None,
    "routed_interface": None,
    "failover_enabled": True,
    "check_interval_sec": None,
    "status": "starting",
    "message": "",
    "wireguards": [],
    "policy": {},
    "name_servers": [],
    "events": [],
    "last_failover": None,
    "failover_in_progress": False,
}


class StateStore:
    def __init__(self, path: str, max_events: int = 50):
        self.path = path
        self.max_events = max_events
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def load(self) -> dict:
        if not os.path.exists(self.path):
            return dict(DEFAULT_STATE)
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return dict(DEFAULT_STATE)
            merged = dict(DEFAULT_STATE)
            merged.update(data)
            return merged
        except (OSError, json.JSONDecodeError):
            return dict(DEFAULT_STATE)

    def save(self, state: dict) -> None:
        self._ensure_dir()
        fd, tmp = tempfile.mkstemp(prefix="wg-monitor-", suffix=".json", dir=os.path.dirname(self.path) or ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def update(self, **kwargs: Any) -> dict:
        state = self.load()
        state.update(kwargs)
        state["updated_at"] = time.time()
        self.save(state)
        return state

    def add_event(self, event_type: str, message: str, **extra: Any) -> dict:
        state = self.load()
        events = list(state.get("events") or [])
        entry = {
            "ts": time.time(),
            "type": event_type,
            "message": message,
        }
        entry.update(extra)
        events.insert(0, entry)
        state["events"] = events[: self.max_events]
        state["updated_at"] = time.time()
        self.save(state)
        return state

    def write_backup(self, backup_dir: str, name: str, payload: Any) -> str:
        os.makedirs(backup_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(backup_dir, f"{name}-{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        return path
