"""WireGuard monitoring and route failover logic."""

from __future__ import annotations

import collections
import logging
import threading
import time
from typing import Any, Optional

from .keenetic_rci import KeeneticRci, KeeneticRciError
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
    def __init__(self, config: dict, store: StateStore, rci: Optional[KeeneticRci] = None):
        self.config = config
        self.store = store
        self.rci = rci or KeeneticRci(
            config["rci_url"],
            config["username"],
            config["password"],
        )
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def failover_enabled(self) -> bool:
        state = self.store.load()
        if "failover_enabled" in state and state["failover_enabled"] is not None:
            return bool(state["failover_enabled"])
        return bool(self.config.get("failover_enabled", True))

    def set_failover_enabled(self, enabled: bool) -> dict:
        return self.store.update(failover_enabled=bool(enabled))

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="wg-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        interval = int(self.config.get("check_interval_sec", 300))
        # First run shortly after start
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                log.exception("Monitor cycle failed: %s", exc)
                self.store.update(status="error", message=str(exc))
            interval = int(self.config.get("check_interval_sec", 300))
            self.store.update(next_check_at=time.time() + interval)
            self._stop.wait(interval)

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
        interval = int(self.config.get("check_interval_sec", 300))

        status = "ok"
        message = "Routed WireGuard is active" if snap["routed_online"] else "Routed WireGuard is inactive"

        state = self.store.update(
            wireguards=snap["wireguards"],
            routed_interface=routed,
            policy=snap["policy"],
            name_servers=snap["name_servers"],
            route_count=snap["route_count"],
            status=status,
            message=message,
            next_check_at=time.time() + interval,
            failover_enabled=self.failover_enabled,
        )

        target = force_failover_to
        should_failover = False

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
