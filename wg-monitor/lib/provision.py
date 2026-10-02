"""Download hidethis configs and install them on Keenetic."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from .hidethis import DEFAULT_AWG, DEFAULT_BASE_URL, HidethisClient, HidethisError
from .keenetic_rci import KeeneticRci, KeeneticRciError

log = logging.getLogger("wg-monitor.provision")


def require_country(country: Optional[str]) -> str:
    cc = (country or "").strip().upper()
    if not cc:
        raise HidethisError("Country is required")
    if len(cc) != 2 or not cc.isalpha():
        raise HidethisError("Country must be a 2-letter code (e.g. NL)")
    return cc


def require_access_code(code: Optional[str]) -> str:
    value = (code or "").strip()
    if not value:
        raise HidethisError("Access code is required")
    return value


class Provisioner:
    def __init__(self, rci: KeeneticRci, config: dict):
        self.rci = rci
        self.config = config

    def _client(self) -> HidethisClient:
        return HidethisClient(
            base_url=self.config.get("hidethis_base_url") or DEFAULT_BASE_URL,
            timeout=float(self.config.get("hidethis_timeout_sec", 45)),
        )

    def _awg(self) -> int:
        try:
            return int(self.config.get("hidethis_awg", DEFAULT_AWG))
        except (TypeError, ValueError):
            return DEFAULT_AWG

    def list_countries(self, access_code: Optional[str] = None) -> list[dict]:
        code = require_access_code(access_code or self.config.get("hidethis_access_code"))
        return self._client().list_countries(code)

    def list_servers(self, country: Optional[str] = None, access_code: Optional[str] = None) -> list[dict]:
        code = require_access_code(access_code or self.config.get("hidethis_access_code"))
        cc = require_country(country if country is not None else self.config.get("hidethis_country"))
        servers = self._client().servers_for_country(code, cc)
        return [
            {
                "id": s.get("id"),
                "name": s.get("name_en") or s.get("name"),
                "country_code": str(s.get("country_code") or "").upper(),
                "server_ip": s["services"]["wg"]["ip"],
                "server_port": s["services"]["wg"].get("port"),
            }
            for s in servers
        ]

    def install_country(
        self,
        *,
        country: Optional[str] = None,
        access_code: Optional[str] = None,
        awg: Optional[int] = None,
        skip_existing: bool = True,
        limit: Optional[int] = None,
    ) -> dict[str, Any]:
        code = require_access_code(access_code or self.config.get("hidethis_access_code"))
        cc = require_country(country if country is not None else self.config.get("hidethis_country"))
        awg_mode = int(awg) if awg is not None else self._awg()
        client = self._client()

        ifaces = self.rci.show_interfaces()
        existing = self.rci.wireguard_endpoints(ifaces)
        packages = client.download_country_configs(code, cc, awg=awg_mode)
        if limit is not None:
            packages = packages[: max(0, int(limit))]

        created: list[dict] = []
        skipped: list[dict] = []
        errors: list[dict] = []

        for pkg in packages:
            endpoint = pkg["server_ip"]
            if skip_existing and endpoint in existing:
                skipped.append(
                    {
                        "name": pkg["name"],
                        "server_ip": endpoint,
                        "interface": existing[endpoint],
                        "reason": "already_present",
                    }
                )
                continue
            try:
                filename = f"{pkg['description']}.conf"
                result = self.rci.import_wireguard_conf(pkg["conf"], filename=filename)
                iface = result["created"]
                self.rci.configure_imported_wireguard(
                    iface,
                    pkg["description"],
                    global_internet=True,
                    up=True,
                    save=False,
                )
                existing[endpoint] = iface
                created.append(
                    {
                        "name": pkg["name"],
                        "server_ip": endpoint,
                        "interface": iface,
                        "description": pkg["description"],
                    }
                )
                log.info("Installed %s as %s", pkg["name"], iface)
            except (HidethisError, KeeneticRciError) as exc:
                log.exception("Failed to install %s", pkg["name"])
                errors.append(
                    {
                        "name": pkg["name"],
                        "server_ip": endpoint,
                        "error": str(exc),
                    }
                )

        if created:
            try:
                self.rci.save_configuration()
            except KeeneticRciError as exc:
                errors.append({"name": "save", "error": str(exc)})

        return {
            "country": cc,
            "awg": awg_mode,
            "requested": len(packages),
            "created": created,
            "skipped": skipped,
            "errors": errors,
            "ts": time.time(),
        }

    def install_one_for_country(
        self,
        *,
        country: Optional[str] = None,
        access_code: Optional[str] = None,
    ) -> dict[str, Any]:
        """Install a single missing server for the country (auto-provision)."""
        return self.install_country(
            country=country,
            access_code=access_code,
            skip_existing=True,
            limit=1,
        )
