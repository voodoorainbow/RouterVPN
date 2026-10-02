"""hidemy.name / hidethis.app WireGuard config API client."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

log = logging.getLogger("wg-monitor.hidethis")

DEFAULT_BASE_URL = "https://hidethis.app"
# 0 = vanilla WG, 1 = AmneziaWG 1.0, 4 = AmneziaWG 2.0
DEFAULT_AWG = 4


class HidethisError(Exception):
    pass


def sanitize_description(name: str, max_len: int = 48) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "", (name or "").strip())
    if not text:
        text = "Hidethis"
    return text[:max_len]


def _post_form(url: str, fields: dict[str, str], timeout: float = 45.0) -> bytes:
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "wg-monitor/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()[:300] if hasattr(exc, "read") else b""
        raise HidethisError(f"HTTP {exc.code} {url}: {body!r}") from exc
    except urllib.error.URLError as exc:
        raise HidethisError(f"URL error {url}: {exc}") from exc


class HidethisClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 45.0):
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    def fetch_serverlist(self, access_code: str) -> list[dict[str, Any]]:
        code = (access_code or "").strip()
        if not code:
            raise HidethisError("Access code is required")
        raw = _post_form(
            f"{self.base_url}/api/serverlist.php?out=js&wg",
            {"code": code},
            timeout=self.timeout,
        )
        text = raw.decode("utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HidethisError(f"Invalid server list response: {text[:200]!r}") from exc
        if isinstance(data, dict):
            servers = list(data.values())
        elif isinstance(data, list):
            servers = data
        else:
            raise HidethisError("Unexpected server list format")
        out = []
        for s in servers:
            if not isinstance(s, dict):
                continue
            wg = (s.get("services") or {}).get("wg")
            if not isinstance(wg, dict) or not wg.get("ip"):
                continue
            out.append(s)
        return out

    def list_countries(self, access_code: str) -> list[dict[str, str]]:
        servers = self.fetch_serverlist(access_code)
        by_code: dict[str, dict[str, Any]] = {}
        for s in servers:
            cc = str(s.get("country_code") or "").upper()
            if not cc:
                continue
            entry = by_code.setdefault(
                cc,
                {"code": cc, "count": 0, "sample": s.get("name_en") or s.get("name") or cc},
            )
            entry["count"] += 1
        return sorted(by_code.values(), key=lambda x: x["code"])

    def servers_for_country(self, access_code: str, country: str) -> list[dict[str, Any]]:
        cc = (country or "").strip().upper()
        if not cc:
            raise HidethisError("Country is required")
        servers = self.fetch_serverlist(access_code)
        matched = [
            s
            for s in servers
            if str(s.get("country_code") or "").upper() == cc
        ]
        matched.sort(key=lambda s: str(s.get("name_en") or s.get("name") or ""))
        return matched

    def get_config(
        self,
        access_code: str,
        server_ip: str,
        awg: int = DEFAULT_AWG,
    ) -> str:
        code = (access_code or "").strip()
        server = (server_ip or "").strip()
        if not code:
            raise HidethisError("Access code is required")
        if not server:
            raise HidethisError("Server IP is required")
        raw = _post_form(
            f"{self.base_url}/api/vpn_get_config_wg.php",
            {"code": code, "server": server, "awg": str(int(awg))},
            timeout=self.timeout,
        )
        text = raw.decode("utf-8", errors="replace").strip()
        if not text.startswith("[Interface]"):
            raise HidethisError(f"Config download failed: {text[:200]}")
        return text

    def download_country_configs(
        self,
        access_code: str,
        country: str,
        awg: int = DEFAULT_AWG,
    ) -> list[dict[str, Any]]:
        servers = self.servers_for_country(access_code, country)
        if not servers:
            raise HidethisError(f"No WireGuard servers for country {country.upper()}")
        results = []
        for s in servers:
            wg = s["services"]["wg"]
            name = s.get("name_en") or s.get("name") or wg["ip"]
            conf = self.get_config(access_code, wg["ip"], awg=awg)
            results.append(
                {
                    "id": s.get("id"),
                    "name": name,
                    "country_code": str(s.get("country_code") or "").upper(),
                    "server_ip": wg["ip"],
                    "server_port": wg.get("port"),
                    "description": sanitize_description(str(name)),
                    "conf": conf,
                }
            )
            log.info("Downloaded config for %s (%s)", name, wg["ip"])
        return results
