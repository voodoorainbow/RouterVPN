"""Keenetic RCI client (NDW2 challenge-response auth)."""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import re
import urllib.error
import urllib.request
from typing import Any, Optional


class KeeneticRciError(Exception):
    pass


class KeeneticRci:
    def __init__(self, base_url: str, username: str, password: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._cj = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cj)
        )

    def _request(
        self,
        path: str,
        method: str = "GET",
        payload: Any = None,
        auth_retry: bool = True,
    ) -> Any:
        url = f"{self.base_url}{path}"
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read()
                if not body:
                    return None
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and auth_retry:
                self.authenticate()
                return self._request(path, method=method, payload=payload, auth_retry=False)
            detail = exc.read()[:300] if hasattr(exc, "read") else b""
            raise KeeneticRciError(f"HTTP {exc.code} {path}: {detail!r}") from exc
        except urllib.error.URLError as exc:
            raise KeeneticRciError(f"URL error {path}: {exc}") from exc

    def authenticate(self) -> None:
        url = f"{self.base_url}/auth"
        req = urllib.request.Request(url, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                # Already authenticated
                resp.read()
                return
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise KeeneticRciError(f"Unexpected auth status {exc.code}") from exc
            challenge = exc.headers.get("X-NDM-Challenge")
            realm = exc.headers.get("X-NDM-Realm", "")
            if not challenge:
                raise KeeneticRciError("Missing X-NDM-Challenge") from exc
            # Consume body / keep cookies from 401
            try:
                exc.read()
            except Exception:
                pass

        ha1 = hashlib.md5(
            f"{self.username}:{realm}:{self.password}".encode("utf-8")
        ).hexdigest()
        token = hashlib.sha256((challenge + ha1).encode("utf-8")).hexdigest()
        payload = {"login": self.username, "password": token}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            raise KeeneticRciError(f"Authentication failed: HTTP {exc.code}") from exc

    def get(self, path: str) -> Any:
        return self._request(path, method="GET")

    def post(self, path: str, payload: Any) -> Any:
        return self._request(path, method="POST", payload=payload)

    def batch(self, commands: list) -> Any:
        return self.post("/rci/", commands)

    def show_interfaces(self) -> dict:
        data = self.get("/rci/show/interface")
        return data if isinstance(data, dict) else {}

    def show_rc_routes(self) -> list:
        data = self.get("/rci/show/rc/ip/route")
        return data if isinstance(data, list) else []

    def show_rc_policy(self) -> dict:
        data = self.get("/rci/show/rc/ip/policy")
        return data if isinstance(data, dict) else {}

    def show_rc_name_servers(self) -> list:
        data = self.get("/rci/show/rc/ip/name-server")
        return data if isinstance(data, list) else []

    def save_configuration(self) -> Any:
        return self.batch([{"system": {"configuration": {"save": {}}}}])

    def wireguard_names(self, ifaces: Optional[dict] = None) -> list[str]:
        data = ifaces if ifaces is not None else self.show_interfaces()
        names = []
        for name, iface in (data or {}).items():
            if isinstance(iface, dict) and iface.get("type") == "Wireguard":
                names.append(name)
        return sorted(names)

    def wireguard_endpoints(self, ifaces: Optional[dict] = None) -> dict[str, str]:
        """Map remote endpoint IP -> interface name."""
        data = ifaces if ifaces is not None else self.show_interfaces()
        mapping: dict[str, str] = {}
        for name, iface in (data or {}).items():
            if not isinstance(iface, dict) or iface.get("type") != "Wireguard":
                continue
            peers = (iface.get("wireguard") or {}).get("peer") or []
            if isinstance(peers, dict):
                peers = [peers]
            for peer in peers:
                if not isinstance(peer, dict):
                    continue
                ep = peer.get("remote-endpoint-address")
                if ep:
                    mapping[str(ep)] = name
        return mapping

    def find_free_wireguard_name(self, ifaces: Optional[dict] = None, max_index: int = 99) -> str:
        used = set()
        for name in self.wireguard_names(ifaces):
            m = re.match(r"(?i)^wireguard(\d+)$", name)
            if m:
                used.add(int(m.group(1)))
        for i in range(0, max_index + 1):
            if i not in used:
                return f"Wireguard{i}"
        raise KeeneticRciError(f"No free Wireguard index in 0..{max_index}")

    def import_wireguard_conf(self, conf_text: str, filename: str = "hidethis.conf") -> dict:
        """Import .conf via native Keenetic wireguard import (supports AWG fields)."""
        encoded = base64.b64encode(conf_text.encode("utf-8")).decode("ascii")
        resp = self.post(
            "/rci/",
            {
                "interface": {
                    "wireguard": {
                        "import": encoded,
                        "name": "",
                        "filename": filename,
                    }
                }
            },
        )
        imp = ((resp or {}).get("interface") or {}).get("wireguard") or {}
        result = imp.get("import") if isinstance(imp, dict) else None
        if not isinstance(result, dict) or not result.get("created"):
            status = (result or {}).get("status") if isinstance(result, dict) else None
            messages = []
            if isinstance(status, list):
                for item in status:
                    if isinstance(item, dict) and item.get("message"):
                        messages.append(str(item["message"]))
            detail = "; ".join(messages) or json.dumps(resp, ensure_ascii=False)[:400]
            raise KeeneticRciError(f"WireGuard import failed: {detail}")
        return result

    def configure_imported_wireguard(
        self,
        iface: str,
        description: str,
        *,
        global_internet: bool = True,
        up: bool = True,
        save: bool = True,
    ) -> None:
        cmds: list[dict] = [
            {
                "interface": {
                    iface: {
                        "description": description,
                        "up": up,
                    }
                }
            }
        ]
        if global_internet:
            cmds.append({"interface": {iface: {"ip": {"global": True}}}})
        self.batch(cmds)
        if save:
            self.save_configuration()
