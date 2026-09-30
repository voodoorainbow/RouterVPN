#!/usr/bin/env python3
"""WireGuard monitor + failover for Keenetic Entware."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time

# Allow running from source tree or /opt/share/wg-monitor
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from lib.keenetic_rci import KeeneticRci  # noqa: E402
from lib.monitor import Monitor  # noqa: E402
from lib.server import WebServer  # noqa: E402
from lib.state import StateStore  # noqa: E402

DEFAULT_CONFIG_PATHS = [
    os.environ.get("WG_MONITOR_CONFIG"),
    "/opt/etc/wg-monitor/config.json",
    os.path.join(HERE, "config.json"),
]


def load_config(path: str | None) -> dict:
    candidates = [path] if path else DEFAULT_CONFIG_PATHS
    for candidate in candidates:
        if not candidate:
            continue
        if os.path.exists(candidate):
            with open(candidate, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
            if not isinstance(cfg, dict):
                raise SystemExit(f"Invalid config: {candidate}")
            return cfg
    raise SystemExit(
        "Config not found. Copy config.example.json to /opt/etc/wg-monitor/config.json"
    )


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Keenetic WireGuard monitor + failover")
    parser.add_argument("-c", "--config", help="Path to config.json")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single check (and failover if needed) then exit",
    )
    parser.add_argument(
        "--no-web",
        action="store_true",
        help="Do not start the HTTP dashboard",
    )
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    config = load_config(args.config)
    store = StateStore(config.get("state_path", "/opt/var/lib/wg-monitor/state.json"))
    state = store.load()
    if state.get("updated_at") is None:
        store.update(failover_enabled=bool(config.get("failover_enabled", True)))

    rci = KeeneticRci(config["rci_url"], config["username"], config["password"])
    monitor = Monitor(config, store, rci=rci)

    if args.once:
        result = monitor.run_once()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    web = None
    if not args.no_web:
        web = WebServer(
            monitor,
            config.get("listen_host", "0.0.0.0"),
            int(config.get("listen_port", 8088)),
        )
        web.start()

    monitor.start()
    logging.getLogger("wg-monitor").info(
        "Started (interval=%ss, failover=%s)",
        config.get("check_interval_sec", 300),
        config.get("failover_enabled", True),
    )

    stop = False

    def _handle(signum, frame):  # noqa: ARG001
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    while not stop:
        time.sleep(0.5)

    monitor.stop()
    if web:
        web.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
