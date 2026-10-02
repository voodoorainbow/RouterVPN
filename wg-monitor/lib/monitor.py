"""WireGuard monitoring and route failover logic."""

from __future__ import annotations

import collections
import logging
import threading
import time
from typing import Any, Optional

from .config_store import public_hidethis_settings, public_update_settings, update_config_file
from .hidethis import HidethisError
from .keenetic_rci import KeeneticRci, KeeneticRciError
from .provision import Provisioner, require_country
from .self_update import SelfUpdateError, SelfUpdater
from .state import StateStore

log = logging.getLogger("wg-monitor")

NEVER_HANDSHAKE = 2147483647


def _format_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(n or 0)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


def peer_is_active(peer: dict, handshake_max_age_sec: int) -> bool:
    if not peer.get("enabled", True):
        return False
    if not peer.get("online"):
        return False
    hs = peer.get("last-handshake")
    if hs is None:
        return False
    try:
        hs_i = int(hs)
    except (TypeError, ValueError):
        return False
    if hs_i <= 0 or hs_i >= NEVER_HANDSHAKE:
        return False
    return hs_i <= handshake_max_age_sec


def summarize_wireguard(ifaces: dict, handshake_max_age_sec: int) -> list[dict]:
    rows = []
    for name, iface in sorted(ifaces.items(), key=lambda x: x[0]):
        if not isinstance(iface, dict) or iface.get("type") != "Wireguard":
            continue
        wg = iface.get("wireguard") or {}
        peers = wg.get("peer") or []
        if not isinstance(peers, list):
            peers = [peers] if peers else []
        active = any(peer_is_active(p, handshake_max_age_sec) for p in peers if isinstance(p, dict))
        peer0 = peers[0] if peers and isinstance(peers[0], dict) else {}
        hs = peer0.get("last-handshake")
        rows.append(
            {
                "id": name,
                "description": iface.get("description") or "",
                "state": iface.get("state"),
                "link": iface.get("link"),
                "connected": iface.get("connected"),
                "address": iface.get("address"),
                "global": bool(iface.get("global")),
                "online": active,
                "last_handshake": hs,
                "rxbytes": peer0.get("rxbytes", 0),
                "txbytes": peer0.get("txbytes", 0),
                "rx_human": _format_bytes(peer0.get("rxbytes", 0) or 0),
                "tx_human": _format_bytes(peer0.get("txbytes", 0) or 0),
                "remote_endpoint": peer0.get("remote-endpoint-address") or "",
                "remote_port": peer0.get("remote-port"),
                "peer_online": bool(peer0.get("online")),
            }
        )
    return rows


def inactivity_seconds(wg: dict, activity: Optional[dict], now: float) -> float:
    """How long the tunnel has been inactive, in seconds."""
    if wg.get("online"):
        return 0.0
    hs = wg.get("last_handshake")
    try:
        hs_i = int(hs) if hs is not None else None
    except (TypeError, ValueError):
        hs_i = None
    if hs_i is not None and 0 < hs_i < NEVER_HANDSHAKE:
        return float(hs_i)
    entry = activity or {}
    if hs_i is not None and hs_i >= NEVER_HANDSHAKE:
        first = entry.get("first_seen_at")
        if first is None:
            return 0.0
        return max(0.0, now - float(first))
    last_on = entry.get("last_online_at")
    if last_on is not None:
        return max(0.0, now - float(last_on))
    first = entry.get("first_seen_at")
    if first is not None:
        return max(0.0, now - float(first))
    return 0.0


def majority_routed_interface(routes: list) -> Optional[str]:
    counts: collections.Counter = collections.Counter()
    for route in routes:
        if not isinstance(route, dict):
            continue
        iface = route.get("interface")
        if iface and str(iface).startswith("Wireguard"):
            counts[iface] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def pick_failover_target(
    wireguards: list[dict],
    preference: list[str],
    exclude: Optional[str],
) -> Optional[str]:
    online = {w["id"] for w in wireguards if w.get("online")}
    online.discard(exclude)
    if not online:
        return None
    for name in preference or []:
        if name in online:
            return name
    return sorted(online)[0]


def _route_delete_cmd(route: dict) -> dict:
    body: dict[str, Any] = {"no": True}
    if route.get("network") is not None:
        body["network"] = route["network"]
        if route.get("mask") is not None:
            body["mask"] = route["mask"]
    elif route.get("host") is not None:
        body["host"] = route["host"]
    if route.get("interface"):
        body["interface"] = route["interface"]
    if route.get("gateway"):
        body["gateway"] = route["gateway"]
    return {"ip": {"route": body}}


def _route_add_cmd(route: dict, new_iface: str) -> dict:
    body: dict[str, Any] = {"interface": new_iface}
    if route.get("network") is not None:
        body["network"] = route["network"]
        if route.get("mask") is not None:
            body["mask"] = route["mask"]
    elif route.get("host") is not None:
        body["host"] = route["host"]
    if route.get("auto"):
        body["auto"] = True
    if route.get("comment"):
        body["comment"] = route["comment"]
    if route.get("gateway"):
        body["gateway"] = route["gateway"]
    return {"ip": {"route": body}}


class Monitor:
    def __init__(
        self,
        config: dict,
        store: StateStore,
        rci: Optional[KeeneticRci] = None,
        config_path: Optional[str] = None,
    ):
        self.config = config
        self.config_path = config_path
        self.store = store
        self.rci = rci or KeeneticRci(
            config["rci_url"],
            config["username"],
            config["password"],
        )
        self.provisioner = Provisioner(self.rci, self.config)
        self.updater = SelfUpdater(self.config)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Seed interval into state on first boot if missing
        state = self.store.load()
        if state.get("check_interval_sec") is None:
            self.store.update(
                check_interval_sec=int(self.config.get("check_interval_sec", 300))
            )

    @property
    def failover_enabled(self) -> bool:
        state = self.store.load()
        if "failover_enabled" in state and state["failover_enabled"] is not None:
            return bool(state["failover_enabled"])
        return bool(self.config.get("failover_enabled", True))

    def set_failover_enabled(self, enabled: bool) -> dict:
        return self.store.update(failover_enabled=bool(enabled))

    @property
    def auto_provision_enabled(self) -> bool:
        state = self.store.load()
        if "auto_provision_enabled" in state and state["auto_provision_enabled"] is not None:
            return bool(state["auto_provision_enabled"])
        return bool(self.config.get("auto_provision_enabled", False))

    def set_auto_provision_enabled(self, enabled: bool) -> dict:
        enabled = bool(enabled)
        self.config["auto_provision_enabled"] = enabled
        if self.config_path:
            update_config_file(self.config_path, {"auto_provision_enabled": enabled})
        return self.store.update(auto_provision_enabled=enabled)

    def hidethis_settings(self) -> dict:
        data = public_hidethis_settings(self.config)
        data["auto_provision_enabled"] = self.auto_provision_enabled
        data["delete_inactive_enabled"] = bool(self.config.get("delete_inactive_enabled", False))
        try:
            data["delete_inactive_after_days"] = max(
                1, int(self.config.get("delete_inactive_after_days", 7) or 7)
            )
        except (TypeError, ValueError):
            data["delete_inactive_after_days"] = 7
        state = self.store.load()
        data["last_provision"] = state.get("last_provision")
        data["last_cleanup"] = state.get("last_cleanup")
        return data

    def update_hidethis_settings(self, body: dict) -> dict:
        updates: dict[str, Any] = {}
        if "hidethis_access_code" in body:
            code = body.get("hidethis_access_code")
            if code is not None:
                code_s = str(code).strip()
                if code_s:
                    updates["hidethis_access_code"] = code_s
        if "hidethis_country" in body:
            country = str(body.get("hidethis_country") or "").strip().upper()
            require_country(country)
            updates["hidethis_country"] = country
        if "hidethis_base_url" in body and body.get("hidethis_base_url") is not None:
            updates["hidethis_base_url"] = str(body.get("hidethis_base_url") or "").rstrip("/")
        if "hidethis_awg" in body and body.get("hidethis_awg") is not None:
            try:
                awg = int(body.get("hidethis_awg"))
            except (TypeError, ValueError) as exc:
                raise KeeneticRciError("hidethis_awg must be an integer") from exc
            if awg not in (0, 1, 4):
                raise KeeneticRciError("hidethis_awg must be 0, 1 or 4")
            updates["hidethis_awg"] = awg
        if "auto_provision_enabled" in body and body.get("auto_provision_enabled") is not None:
            updates["auto_provision_enabled"] = bool(body.get("auto_provision_enabled"))
        if "auto_provision_cooldown_sec" in body and body.get("auto_provision_cooldown_sec") is not None:
            try:
                cool = int(body.get("auto_provision_cooldown_sec"))
            except (TypeError, ValueError) as exc:
                raise KeeneticRciError("auto_provision_cooldown_sec must be an integer") from exc
            updates["auto_provision_cooldown_sec"] = max(60, min(86400, cool))
        if "delete_inactive_enabled" in body and body.get("delete_inactive_enabled") is not None:
            updates["delete_inactive_enabled"] = bool(body.get("delete_inactive_enabled"))
        if "delete_inactive_after_days" in body and body.get("delete_inactive_after_days") is not None:
            try:
                days = int(body.get("delete_inactive_after_days"))
            except (TypeError, ValueError) as exc:
                raise KeeneticRciError("delete_inactive_after_days must be an integer") from exc
            updates["delete_inactive_after_days"] = max(1, min(365, days))
        if not updates:
            return self.hidethis_settings()
        self.config.update(updates)
        if self.config_path:
            update_config_file(self.config_path, updates)
        state_updates = {}
        if "auto_provision_enabled" in updates:
            state_updates["auto_provision_enabled"] = updates["auto_provision_enabled"]
        if state_updates:
            self.store.update(**state_updates)
        self.store.add_event(
            "settings",
            "Updated hidethis settings"
            + (f" (country={updates.get('hidethis_country')})" if "hidethis_country" in updates else ""),
        )
        return self.hidethis_settings()

    def _track_wg_activity(self, wireguards: list[dict]) -> dict:
        now = time.time()
        state = self.store.load()
        activity = dict(state.get("wg_activity") or {})
        seen = {w["id"] for w in wireguards if w.get("id")}
        for w in wireguards:
            name = w.get("id")
            if not name:
                continue
            entry = dict(activity.get(name) or {})
            if entry.get("first_seen_at") is None:
                entry["first_seen_at"] = now
            if w.get("online"):
                entry["last_online_at"] = now
            activity[name] = entry
        # Drop tracking for interfaces that no longer exist
        for name in list(activity.keys()):
            if name not in seen:
                activity.pop(name, None)
        self.store.update(wg_activity=activity)
        return activity

    def cleanup_inactive_wireguards(
        self,
        wireguards: list[dict],
        routed_interface: Optional[str],
    ) -> dict[str, Any]:
        activity = self._track_wg_activity(wireguards)
        enabled = bool(self.config.get("delete_inactive_enabled", False))
        if not enabled:
            return {"deleted": [], "skipped": True}
        try:
            days = max(1, int(self.config.get("delete_inactive_after_days", 7) or 7))
        except (TypeError, ValueError):
            days = 7
        threshold = days * 86400
        now = time.time()
        deleted: list[dict] = []
        for w in wireguards:
            name = w.get("id")
            if not name or w.get("online"):
                continue
            if routed_interface and name == routed_interface:
                continue
            inactive_for = inactivity_seconds(w, activity.get(name), now)
            if inactive_for < threshold:
                continue
            try:
                self.rci.delete_interface(name, save=False)
                deleted.append(
                    {
                        "interface": name,
                        "description": w.get("description") or "",
                        "inactive_days": round(inactive_for / 86400, 2),
                    }
                )
                log.info(
                    "Deleted inactive %s after %.1f days",
                    name,
                    inactive_for / 86400,
                )
            except KeeneticRciError as exc:
                log.warning("Failed to delete %s: %s", name, exc)
                self.store.add_event("error", f"Failed to delete inactive {name}: {exc}")
        if deleted:
            try:
                self.rci.save_configuration()
            except KeeneticRciError as exc:
                self.store.add_event("error", f"Save after inactive cleanup failed: {exc}")
            result = {"deleted": deleted, "days": days, "ts": now}
            self.store.update(last_cleanup=result)
            self.store.add_event(
                "cleanup",
                f"Deleted {len(deleted)} inactive WG (>{days}d): "
                + ", ".join(d["interface"] for d in deleted),
                deleted=deleted,
            )
            # prune activity for deleted
            activity = dict(self.store.load().get("wg_activity") or {})
            for d in deleted:
                activity.pop(d["interface"], None)
            self.store.update(wg_activity=activity)
            return result
        return {"deleted": [], "days": days, "ts": now}

    def update_settings_public(self) -> dict:
        data = public_update_settings(self.config)
        try:
            status = self.updater.status(check_remote=False)
            data.update(
                {
                    "local": status.get("local"),
                    "remote": status.get("remote"),
                    "update_available": status.get("update_available"),
                }
            )
        except Exception as exc:
            data["error"] = str(exc)
        return data

    def update_update_settings(self, body: dict) -> dict:
        updates: dict[str, Any] = {}
        if "update_repo" in body and body.get("update_repo") is not None:
            repo = str(body.get("update_repo") or "").strip()
            if repo and "/" not in repo:
                raise KeeneticRciError("update_repo must look like owner/name")
            if repo:
                updates["update_repo"] = repo
        if "update_ref" in body and body.get("update_ref") is not None:
            ref = str(body.get("update_ref") or "").strip()
            if ref:
                updates["update_ref"] = ref
        if not updates:
            return self.update_settings_public()
        self.config.update(updates)
        if self.config_path:
            update_config_file(self.config_path, updates)
        self.store.add_event("settings", "Updated self-update settings")
        return self.update_settings_public()

    def check_for_updates(self) -> dict:
        status = self.updater.status(check_remote=True)
        self.store.add_event(
            "update",
            "Checked repository: "
            + (
                f"remote {(status.get('remote') or {}).get('short_sha')}"
                if status.get("remote")
                else "no remote"
            )
            + (
                " (update available)"
                if status.get("update_available")
                else " (up to date)"
                if status.get("remote")
                else ""
            ),
        )
        return status

    def apply_self_update(self, force: bool = False) -> dict:
        with self._lock:
            try:
                result = self.updater.apply_update(force=force)
            except SelfUpdateError as exc:
                self.store.add_event("error", f"Self-update failed: {exc}")
                raise
            if result.get("updated"):
                remote = result.get("remote") or {}
                self.store.add_event(
                    "update",
                    result.get("message")
                    or f"Updated to {remote.get('short_sha')}",
                    sha=remote.get("sha"),
                )
            else:
                self.store.add_event("update", "Already up to date")
            return result

    def install_hidethis_country(self, country: Optional[str] = None) -> dict:
        with self._lock:
            cc = (country or self.config.get("hidethis_country") or "").strip().upper()
            require_country(cc)
            self.store.update(status="provisioning", message=f"Installing hidethis configs for {cc}")
            try:
                result = self.provisioner.install_country(country=cc, skip_existing=True)
            except HidethisError as exc:
                self.store.add_event("error", f"hidethis install failed: {exc}")
                raise
            msg = (
                f"hidethis {cc}: created {len(result['created'])}, "
                f"skipped {len(result['skipped'])}, errors {len(result['errors'])}"
            )
            self.store.add_event(
                "provision",
                msg,
                country=result.get("country"),
                created=result.get("created"),
                skipped=result.get("skipped"),
                errors=result.get("errors"),
            )
            snap = self.collect_snapshot()
            return self.store.update(
                wireguards=snap["wireguards"],
                routed_interface=snap["routed_interface"],
                route_count=snap["route_count"],
                last_provision=result,
                status="ok" if not result["errors"] else "provision_partial",
                message=msg,
            )

    @property
    def check_interval_sec(self) -> int:
        state = self.store.load()
        value = state.get("check_interval_sec")
        if value is None:
            value = self.config.get("check_interval_sec", 300)
        try:
            return max(60, min(86400, int(value)))
        except (TypeError, ValueError):
            return 300

    def set_check_interval_sec(self, seconds: int) -> dict:
        try:
            seconds = int(seconds)
        except (TypeError, ValueError) as exc:
            raise KeeneticRciError("check_interval_sec must be an integer") from exc
        seconds = max(60, min(86400, seconds))
        state = self.store.update(
            check_interval_sec=seconds,
            next_check_at=time.time() + seconds,
        )
        self.store.add_event(
            "settings",
            f"Check interval set to {seconds}s ({seconds / 60:.1f} min)",
        )
        self._wake.set()
        return self.store.load()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._wake.clear()
        self._thread = threading.Thread(target=self._loop, name="wg-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        # First run shortly after start
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                log.exception("Monitor cycle failed: %s", exc)
                self.store.update(status="error", message=str(exc))
            interval = self.check_interval_sec
            self.store.update(
                next_check_at=time.time() + interval,
                check_interval_sec=interval,
            )
            self._wake.clear()
            deadline = time.time() + interval
            while not self._stop.is_set() and not self._wake.is_set() and time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                self._stop.wait(min(1.0, remaining))
            if self._wake.is_set() and not self._stop.is_set():
                self._wake.clear()
                # Interval changed — apply immediately with a fresh check
                continue

    def collect_snapshot(self) -> dict:
        handshake_max = int(self.config.get("handshake_max_age_sec", 180))
        ifaces = self.rci.show_interfaces()
        routes = self.rci.show_rc_routes()
        policy = self.rci.show_rc_policy()
        name_servers = self.rci.show_rc_name_servers()
        wireguards = summarize_wireguard(ifaces, handshake_max)
        routed = majority_routed_interface(routes)
        online_map = {w["id"]: w.get("online") for w in wireguards}
        return {
            "wireguards": wireguards,
            "routes": routes,
            "routed_interface": routed,
            "routed_online": bool(online_map.get(routed)) if routed else False,
            "policy": policy,
            "name_servers": name_servers,
            "route_count": len(routes),
        }

    def run_once(self, force_failover_to: Optional[str] = None) -> dict:
        with self._lock:
            return self._run_once_locked(force_failover_to=force_failover_to)

    def _run_once_locked(self, force_failover_to: Optional[str] = None) -> dict:
        snap = self.collect_snapshot()
        routed = snap["routed_interface"]
        interval = self.check_interval_sec

        status = "ok"
        message = "Routed WireGuard is active" if snap["routed_online"] else "Routed WireGuard is inactive"

        state = self.store.update(
            wireguards=snap["wireguards"],
            routed_interface=routed,
            policy=snap["policy"],
            name_servers=snap["name_servers"],
            route_count=snap["route_count"],
            check_interval_sec=interval,
            status=status,
            message=message,
            next_check_at=time.time() + interval,
            failover_enabled=self.failover_enabled,
        )

        target = force_failover_to
        should_failover = False
        any_online = any(w.get("online") for w in snap["wireguards"])

        # Track activity and optionally prune long-inactive tunnels
        try:
            cleanup = self.cleanup_inactive_wireguards(snap["wireguards"], routed)
            if cleanup.get("deleted"):
                snap = self.collect_snapshot()
                routed = snap["routed_interface"]
                any_online = any(w.get("online") for w in snap["wireguards"])
        except Exception as exc:
            log.exception("Inactive WG cleanup failed: %s", exc)
            self.store.add_event("error", f"Inactive cleanup failed: {exc}")

        if force_failover_to:
            should_failover = True
            message = f"Manual failover requested to {force_failover_to}"
        elif not snap["routed_online"]:
            if not self.failover_enabled:
                status = "inactive_no_autofailover"
                message = "Routed WireGuard inactive; autofailover disabled"
            else:
                target = pick_failover_target(
                    snap["wireguards"],
                    list(self.config.get("preference") or []),
                    exclude=routed,
                )
                if not target:
                    status = "no_failover_target"
                    message = "Routed WireGuard inactive; no active alternative"
                else:
                    should_failover = True
                    message = f"Routed WireGuard inactive; failing over to {target}"

        # Auto-provision when there is no active WireGuard at all
        if (
            not force_failover_to
            and not any_online
            and self.auto_provision_enabled
            and (self.config.get("hidethis_access_code") or "").strip()
            and (self.config.get("hidethis_country") or "").strip()
        ):
            cooldown = int(self.config.get("auto_provision_cooldown_sec", 3600) or 3600)
            last = (self.store.load().get("last_provision") or {}).get("ts") or 0
            if time.time() - float(last) >= cooldown:
                try:
                    self.store.update(status="provisioning", message="No active WG; auto-provisioning")
                    prov = self.provisioner.install_one_for_country()
                    self.store.update(last_provision=prov)
                    self.store.add_event(
                        "provision",
                        f"Auto-provision {prov.get('country')}: "
                        f"created {len(prov.get('created') or [])}, "
                        f"skipped {len(prov.get('skipped') or [])}",
                        country=prov.get("country"),
                    )
                    snap = self.collect_snapshot()
                    routed = snap["routed_interface"]
                    any_online = any(w.get("online") for w in snap["wireguards"])
                    if not snap["routed_online"] and self.failover_enabled:
                        target = pick_failover_target(
                            snap["wireguards"],
                            list(self.config.get("preference") or []),
                            exclude=routed,
                        )
                        if target:
                            should_failover = True
                            message = f"After provision, failing over to {target}"
                    if prov.get("created"):
                        status = "provisioned"
                        message = (
                            f"Auto-provisioned {[c['interface'] for c in prov['created']]}"
                        )
                    elif not any_online:
                        status = "no_failover_target"
                        message = "No active WG; auto-provision found nothing new"
                except Exception as exc:
                    log.exception("Auto-provision failed")
                    status = "provision_error"
                    message = f"Auto-provision failed: {exc}"
                    self.store.add_event("error", message)

        if should_failover and target:
            if target == routed and not force_failover_to:
                status = "ok"
                message = "Already on target interface"
            else:
                try:
                    self.store.update(failover_in_progress=True, status="failing_over", message=message)
                    result = self.failover(routed, target, snap["routes"], snap["policy"], snap["name_servers"])
                    status = "failed_over"
                    message = result["message"]
                    self.store.add_event(
                        "failover",
                        message,
                        from_iface=routed,
                        to_iface=target,
                        routes_moved=result.get("routes_moved", 0),
                    )
                    # Refresh after switch
                    snap = self.collect_snapshot()
                    routed = snap["routed_interface"]
                except Exception as exc:
                    log.exception("Failover failed")
                    status = "failover_error"
                    message = f"Failover failed: {exc}"
                    self.store.add_event("error", message, from_iface=routed, to_iface=target)
                finally:
                    self.store.update(failover_in_progress=False)

        updates = {
            "wireguards": snap["wireguards"],
            "routed_interface": routed,
            "policy": snap["policy"],
            "name_servers": snap["name_servers"],
            "route_count": snap.get("route_count", len(snap["routes"])),
            "status": status,
            "message": message,
            "next_check_at": time.time() + interval,
        }
        if status == "failed_over" and target:
            updates["last_failover"] = {
                "ts": time.time(),
                "to": target,
                "message": message,
            }
        return self.store.update(**updates)

    def failover(
        self,
        old_iface: Optional[str],
        new_iface: str,
        routes: list,
        policy: dict,
        name_servers: list,
    ) -> dict:
        backup_dir = self.config.get("backup_dir", "/opt/var/lib/wg-monitor")
        backup_path = self.store.write_backup(
            backup_dir,
            "routes-backup",
            {
                "old_iface": old_iface,
                "new_iface": new_iface,
                "routes": routes,
                "policy": policy,
                "name_servers": name_servers,
            },
        )
        log.info("Wrote route backup to %s", backup_path)

        # Ensure candidate can carry internet-bound traffic
        self.rci.batch(
            [
                {"interface": {new_iface: {"global": True}}},
            ]
        )

        to_move = [
            r
            for r in routes
            if isinstance(r, dict)
            and r.get("interface") == old_iface
            and (r.get("network") is not None or r.get("host") is not None)
        ]
        if not old_iface:
            to_move = []

        batch_size = max(1, int(self.config.get("route_batch_size", 50)))
        moved = 0
        for i in range(0, len(to_move), batch_size):
            chunk = to_move[i : i + batch_size]
            cmds = []
            for route in chunk:
                cmds.append(_route_delete_cmd(route))
                cmds.append(_route_add_cmd(route, new_iface))
            self.rci.batch(cmds)
            moved += len(chunk)
            log.info("Moved routes %s/%s", moved, len(to_move))
            self.store.update(
                status="failing_over",
                message=f"Moving routes {moved}/{len(to_move)} → {new_iface}",
            )

        # Policy: replace WireGuard permit entries that pointed to old iface
        policy_name = self.config.get("policy_name", "Policy0")
        pol = (policy or {}).get(policy_name) or {}
        permits = list(pol.get("permit") or [])
        if permits:
            new_permits = []
            replaced = False
            for p in permits:
                if not isinstance(p, dict):
                    continue
                iface = p.get("interface")
                if old_iface and iface == old_iface:
                    new_permits.append({"enabled": p.get("enabled", True), "interface": new_iface})
                    replaced = True
                elif iface == new_iface:
                    new_permits.append({"enabled": p.get("enabled", True), "interface": iface})
                    replaced = True
                else:
                    new_permits.append({"enabled": p.get("enabled", True), "interface": iface})
            if not replaced:
                # Ensure new WG is present at the front
                new_permits.insert(0, {"enabled": True, "interface": new_iface})
            # Rebuild policy permits: Keenetic replace via full permit list is awkward;
            # remove old WG permit and add new if needed.
            cmds = []
            if old_iface and old_iface != new_iface:
                cmds.append(
                    {
                        "ip": {
                            "policy": {
                                policy_name: {
                                    "permit": {"no": True, "interface": old_iface},
                                }
                            }
                        }
                    }
                )
            cmds.append(
                {
                    "ip": {
                        "policy": {
                            policy_name: {
                                "permit": {"interface": new_iface},
                            }
                        }
                    }
                }
            )
            # Keep description / multipath if present
            if pol.get("description"):
                cmds.append(
                    {
                        "ip": {
                            "policy": {
                                policy_name: {"description": pol["description"]}
                            }
                        }
                    }
                )
            if pol.get("multipath"):
                cmds.append(
                    {
                        "ip": {
                            "policy": {
                                policy_name: {"multipath": True}
                            }
                        }
                    }
                )
            self.rci.batch(cmds)

        # DNS name-servers bound to old WG
        ns_cmds = []
        for ns in name_servers or []:
            if not isinstance(ns, dict):
                continue
            if old_iface and ns.get("interface") == old_iface:
                addr = ns.get("address")
                domain = ns.get("domain", "")
                if not addr:
                    continue
                ns_cmds.append(
                    {
                        "ip": {
                            "name-server": {
                                "no": True,
                                "address": addr,
                                "domain": domain,
                                "interface": old_iface,
                            }
                        }
                    }
                )
                ns_cmds.append(
                    {
                        "ip": {
                            "name-server": {
                                "address": addr,
                                "domain": domain,
                                "interface": new_iface,
                            }
                        }
                    }
                )
        if ns_cmds:
            self.rci.batch(ns_cmds)

        # Optionally turn off global on old iface to avoid dual default candidates
        if old_iface and old_iface != new_iface:
            try:
                self.rci.batch([{"interface": {old_iface: {"global": False}}}])
            except KeeneticRciError as exc:
                log.warning("Could not clear global on %s: %s", old_iface, exc)

        self.rci.save_configuration()
        msg = f"Switched {moved} routes from {old_iface} to {new_iface} (backup {backup_path})"
        log.info(msg)
        return {"message": msg, "routes_moved": moved, "backup": backup_path}

    def manual_switch(self, target: str) -> dict:
        with self._lock:
            snap = self.collect_snapshot()
            ids = {w["id"] for w in snap["wireguards"]}
            if target not in ids:
                raise KeeneticRciError(f"Unknown WireGuard interface: {target}")
            online = {w["id"] for w in snap["wireguards"] if w.get("online")}
            if target not in online:
                raise KeeneticRciError(f"Target {target} is not active")
            return self._run_once_locked(force_failover_to=target)
