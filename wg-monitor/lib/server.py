"""HTTP dashboard for wg-monitor."""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .monitor import Monitor

log = logging.getLogger("wg-monitor.web")

HTML_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WireGuard Monitor</title>
  <style>
    :root {
      --bg: #0f1419;
      --panel: #1a2332;
      --text: #e7ecf3;
      --muted: #8b9bb4;
      --ok: #3ecf8e;
      --bad: #ff6b6b;
      --accent: #4da3ff;
      --border: #2a3a52;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background:
        radial-gradient(1200px 600px at 10% -10%, #1b3a5c 0%, transparent 55%),
        radial-gradient(900px 500px at 100% 0%, #123528 0%, transparent 50%),
        var(--bg);
      color: var(--text);
      min-height: 100vh;
    }
    header {
      padding: 28px 24px 8px;
      max-width: 1100px;
      margin: 0 auto;
    }
    h1 {
      margin: 0;
      font-size: 1.75rem;
      letter-spacing: -0.02em;
      font-weight: 650;
    }
    .sub {
      color: var(--muted);
      margin-top: 6px;
      font-size: 0.95rem;
    }
    main {
      max-width: 1100px;
      margin: 0 auto;
      padding: 16px 24px 40px;
      display: grid;
      gap: 16px;
    }
    .row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }
    .card {
      background: color-mix(in srgb, var(--panel) 92%, black);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px 16px;
    }
    .label { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
    .value { margin-top: 6px; font-size: 1.1rem; font-weight: 600; word-break: break-word; }
    .ok { color: var(--ok); }
    .bad { color: var(--bad); }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }
    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 500; font-size: 0.78rem; text-transform: uppercase; }
    .dot {
      display: inline-block;
      width: 8px; height: 8px; border-radius: 50%;
      margin-right: 6px;
      background: var(--bad);
    }
    .dot.on { background: var(--ok); }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }
    button, .toggle {
      appearance: none;
      border: 1px solid var(--border);
      background: #243449;
      color: var(--text);
      border-radius: 8px;
      padding: 8px 12px;
      cursor: pointer;
      font: inherit;
    }
    button:hover { border-color: var(--accent); }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .toggle.active { background: #1e4d3a; border-color: #2f8f66; }
    .events { font-size: 0.88rem; color: var(--muted); }
    .events li { margin-bottom: 8px; }
    .mono { font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 0.85rem; }
    .settings {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid var(--border);
    }
    .settings label { color: var(--muted); font-size: 0.9rem; }
    .settings input {
      width: 88px;
      appearance: none;
      border: 1px solid var(--border);
      background: #152033;
      color: var(--text);
      border-radius: 8px;
      padding: 8px 10px;
      font: inherit;
    }
  </style>
</head>
<body>
  <header>
    <h1>WireGuard Monitor</h1>
    <div class="sub">Keenetic Entware · автопроверка и failover маршрутов</div>
  </header>
  <main>
    <section class="row" id="summary"></section>
    <section class="card">
      <div class="actions" style="margin-bottom:12px">
        <button id="btnRefresh">Обновить</button>
        <button id="btnCheck">Проверить сейчас</button>
        <button id="btnFailover" class="toggle">Автоfailover: …</button>
      </div>
      <div class="settings">
        <label for="intervalMin">Частота проверки</label>
        <input id="intervalMin" type="number" min="1" max="1440" step="1" title="Минуты (минимум 1)">
        <span class="sub" style="margin:0">мин</span>
        <button id="btnInterval">Сохранить</button>
        <span class="sub" id="intervalHint" style="margin:0"></span>
      </div>
      <div class="label" style="margin-top:16px">WireGuard интерфейсы</div>
      <div style="overflow-x:auto;margin-top:8px">
        <table>
          <thead>
            <tr>
              <th>Интерфейс</th>
              <th>Статус</th>
              <th>Handshake</th>
              <th>Трафик</th>
              <th>Endpoint</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="wgBody"></tbody>
        </table>
      </div>
    </section>
    <section class="card">
      <div class="label">События</div>
      <ul class="events" id="events"></ul>
    </section>
  </main>
  <script>
    function fmtTs(ts) {
      if (!ts) return "—";
      return new Date(ts * 1000).toLocaleString();
    }
    function fmtHs(hs) {
      if (hs === null || hs === undefined) return "—";
      if (hs >= 2147483647) return "never";
      return hs + "s ago";
    }
    async function api(path, opts) {
      const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts || {}));
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }
    function render(state) {
      const routed = state.routed_interface || "—";
      const online = (state.wireguards || []).find(w => w.id === routed)?.online;
      const intervalSec = Number(state.check_interval_sec) || 300;
      const intervalMin = Math.max(1, Math.round(intervalSec / 60));
      const summary = document.getElementById("summary");
      summary.innerHTML = `
        <div class="card"><div class="label">Routed WG</div><div class="value mono">${routed}</div></div>
        <div class="card"><div class="label">Routed status</div><div class="value ${online ? "ok" : "bad"}">${online ? "active" : "inactive"}</div></div>
        <div class="card"><div class="label">Status</div><div class="value">${state.status || "—"}</div></div>
        <div class="card"><div class="label">Routes</div><div class="value">${state.route_count ?? "—"}</div></div>
        <div class="card"><div class="label">Интервал</div><div class="value">${intervalMin} мин</div></div>
        <div class="card"><div class="label">Last check</div><div class="value" style="font-size:0.95rem">${fmtTs(state.updated_at)}</div></div>
        <div class="card"><div class="label">Next check</div><div class="value" style="font-size:0.95rem">${fmtTs(state.next_check_at)}</div></div>
      `;
      const intervalInput = document.getElementById("intervalMin");
      if (document.activeElement !== intervalInput) {
        intervalInput.value = String(intervalMin);
      }
      document.getElementById("intervalHint").textContent = "(" + intervalSec + " сек)";
      const btn = document.getElementById("btnFailover");
      const on = !!state.failover_enabled;
      btn.textContent = "Автоfailover: " + (on ? "ON" : "OFF");
      btn.classList.toggle("active", on);
      const tbody = document.getElementById("wgBody");
      tbody.innerHTML = (state.wireguards || []).map(w => {
        const isRouted = w.id === state.routed_interface;
        return `<tr>
          <td><strong>${w.id}</strong><div class="sub" style="margin:0">${w.description || ""}${isRouted ? " · routed" : ""}</div></td>
          <td><span class="dot ${w.online ? "on" : ""}"></span>${w.online ? "online" : "offline"}</td>
          <td class="mono">${fmtHs(w.last_handshake)}</td>
          <td class="mono">↓ ${w.rx_human}<br>↑ ${w.tx_human}</td>
          <td class="mono">${w.remote_endpoint || "—"}${w.remote_port ? ":" + w.remote_port : ""}</td>
          <td><button data-switch="${w.id}" ${(!w.online || isRouted || state.failover_in_progress) ? "disabled" : ""}>Переключить</button></td>
        </tr>`;
      }).join("") || `<tr><td colspan="6">Нет WireGuard интерфейсов</td></tr>`;
      document.querySelectorAll("[data-switch]").forEach(btn => {
        btn.onclick = async () => {
          if (!confirm("Переключить маршруты на " + btn.dataset.switch + "?")) return;
          btn.disabled = true;
          try {
            await api("/api/switch", { method: "POST", body: JSON.stringify({ target: btn.dataset.switch }) });
            await refresh();
          } catch (e) { alert(e.message); }
        };
      });
      const events = document.getElementById("events");
      const list = state.events || [];
      events.innerHTML = list.length
        ? list.map(e => `<li><span class="mono">${fmtTs(e.ts)}</span> · <strong>${e.type}</strong> — ${e.message}</li>`).join("")
        : "<li>Пока нет событий</li>";
    }
    async function refresh() {
      const state = await api("/api/state");
      render(state);
    }
    document.getElementById("btnRefresh").onclick = () => refresh().catch(e => alert(e.message));
    document.getElementById("btnCheck").onclick = async () => {
      try {
        await api("/api/check", { method: "POST", body: "{}" });
        await refresh();
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnFailover").onclick = async () => {
      try {
        const state = await api("/api/state");
        await api("/api/failover", { method: "POST", body: JSON.stringify({ enabled: !state.failover_enabled }) });
        await refresh();
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnInterval").onclick = async () => {
      const minutes = Number(document.getElementById("intervalMin").value);
      if (!Number.isFinite(minutes) || minutes < 1) {
        alert("Укажите интервал в минутах (минимум 1)");
        return;
      }
      try {
        await api("/api/interval", {
          method: "POST",
          body: JSON.stringify({ minutes: Math.round(minutes) })
        });
        await refresh();
      } catch (e) { alert(e.message); }
    };
    refresh().catch(e => alert(e.message));
    setInterval(() => refresh().catch(() => {}), 15000);
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    monitor: "Monitor" = None  # type: ignore

    def log_message(self, fmt: str, *args) -> None:
        log.debug("%s - " + fmt, self.address_string(), *args)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._html(HTML_PAGE)
            return
        if path == "/api/state":
            state = self.monitor.store.load()
            state["check_interval_sec"] = self.monitor.check_interval_sec
            state["failover_enabled"] = self.monitor.failover_enabled
            self._json(200, state)
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/api/check":
                state = self.monitor.run_once()
                self._json(200, state)
                return
            if path == "/api/failover":
                body = self._read_json()
                enabled = bool(body.get("enabled"))
                self.monitor.set_failover_enabled(enabled)
                self._json(200, self.monitor.store.load())
                return
            if path == "/api/interval":
                body = self._read_json()
                if "minutes" in body and body.get("minutes") is not None:
                    minutes = body.get("minutes")
                    try:
                        seconds = int(round(float(minutes) * 60))
                    except (TypeError, ValueError):
                        self._json(400, {"error": "minutes must be a number"})
                        return
                elif "seconds" in body and body.get("seconds") is not None:
                    try:
                        seconds = int(body.get("seconds"))
                    except (TypeError, ValueError):
                        self._json(400, {"error": "seconds must be an integer"})
                        return
                else:
                    self._json(400, {"error": "minutes or seconds required"})
                    return
                if seconds < 60:
                    self._json(400, {"error": "minimum interval is 1 minute"})
                    return
                state = self.monitor.set_check_interval_sec(seconds)
                self._json(200, state)
                return
            if path == "/api/switch":
                body = self._read_json()
                target = body.get("target")
                if not target:
                    self._json(400, {"error": "target required"})
                    return
                state = self.monitor.manual_switch(str(target))
                self._json(200, state)
                return
            self._json(404, {"error": "not found"})
        except Exception as exc:
            log.exception("API error")
            self._json(500, {"error": str(exc)})


def make_handler(monitor: "Monitor"):
    class BoundHandler(DashboardHandler):
        pass

    BoundHandler.monitor = monitor
    return BoundHandler


class WebServer:
    def __init__(self, monitor: "Monitor", host: str, port: int):
        self.monitor = monitor
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = make_handler(self.monitor)
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="wg-web", daemon=True)
        self._thread.start()
        log.info("Dashboard listening on http://%s:%s", self.host, self.port)

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
