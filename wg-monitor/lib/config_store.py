"""Helpers to persist wg-monitor config.json updates."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


HIDETHIS_KEYS = (
    "hidethis_base_url",
    "hidethis_access_code",
    "hidethis_country",
    "hidethis_awg",
    "hidethis_timeout_sec",
    "auto_provision_enabled",
    "auto_provision_cooldown_sec",
)


def mask_access_code(code: str | None) -> str:
    value = (code or "").strip()
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return ("*" * (len(value) - 4)) + value[-4:]


def public_hidethis_settings(config: dict) -> dict[str, Any]:
    return {
        "hidethis_base_url": config.get("hidethis_base_url") or "https://hidethis.app",
        "hidethis_access_code_set": bool((config.get("hidethis_access_code") or "").strip()),
        "hidethis_access_code_masked": mask_access_code(config.get("hidethis_access_code")),
        "hidethis_country": (config.get("hidethis_country") or "").strip().upper(),
        "hidethis_awg": int(config.get("hidethis_awg", 4) or 4),
        "auto_provision_enabled": bool(config.get("auto_provision_enabled", False)),
        "auto_provision_cooldown_sec": int(config.get("auto_provision_cooldown_sec", 3600) or 3600),
    }


def update_config_file(path: str, updates: dict[str, Any]) -> dict:
    if not path:
        raise ValueError("config path is not set")
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not isinstance(cfg, dict):
        raise ValueError("invalid config file")
    for key, value in updates.items():
        if value is None and key == "hidethis_access_code":
            continue
        cfg[key] = value
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix="wg-monitor-cfg-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return cfg
