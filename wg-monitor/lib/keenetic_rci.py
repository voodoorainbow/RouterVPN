"""Keenetic RCI client (NDW2 challenge-response auth)."""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
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
