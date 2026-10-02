"""HTTP dashboard for wg-monitor."""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from .hidethis import HidethisError
from .self_update import SelfUpdateError

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
    .settings input, .settings select {
      appearance: none;
      border: 1px solid var(--border);
      background: #152033;
      color: var(--text);
      border-radius: 8px;
      padding: 8px 10px;
      font: inherit;
    }
    .settings input[type="number"] { width: 88px; }
    .settings input[type="text"], .settings input[type="password"] { min-width: 160px; }
    .grid-form {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }
    .field { display: flex; flex-direction: column; gap: 6px; }
    .field label { color: var(--muted); font-size: 0.85rem; }
    .hint { color: var(--muted); font-size: 0.85rem; margin-top: 10px; }
  </style>
</head>
<body>
  <header>
    <h1>WireGuard Monitor</h1>
    <div class="sub">Keenetic Entware · автопроверка, failover и hidethis provisioning</div>
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
      <div class="label">hidethis / VPN-конфиги</div>
      <div class="hint">Страна обязательна. Кнопка ставит на роутер все серверы только выбранной страны (уже существующие по endpoint пропускаются).</div>
      <div class="grid-form">
        <div class="field">
          <label for="htCode">Код доступа</label>
          <input id="htCode" type="password" autocomplete="off" placeholder="код из письма">
          <span class="sub" id="htCodeHint" style="margin:0"></span>
        </div>
        <div class="field">
          <label for="htCountry">Страна *</label>
          <select id="htCountry">
            <option value="">— выберите —</option>
          </select>
        </div>
        <div class="field">
          <label for="htAwg">Режим WG</label>
          <select id="htAwg">
            <option value="4">AmneziaWG 2.0 (awg=4)</option>
            <option value="1">AmneziaWG 1.0 (awg=1)</option>
            <option value="0">Vanilla WireGuard (awg=0)</option>
          </select>
        </div>
      </div>
      <div class="actions" style="margin-top:14px">
        <button id="btnHtSave">Сохранить настройки</button>
        <button id="btnHtCountries">Обновить список стран</button>
        <button id="btnHtInstall">Загрузить и установить все по стране</button>
        <button id="btnHtAuto" class="toggle">Авто при отсутствии VPN: …</button>
      </div>
      <div class="settings" style="border-top:none;padding-top:0">
        <button id="btnHtCleanup" class="toggle">Удалять неактивные VPN: …</button>
        <label for="htCleanupDays">через</label>
        <input id="htCleanupDays" type="number" min="1" max="365" step="1" title="Дней без активности">
        <span class="sub" style="margin:0">дн.</span>
        <button id="btnHtCleanupSave">Сохранить срок</button>
      </div>
      <div class="hint" id="htStatus"></div>
    </section>
    <section class="card">
      <div class="label">Обновление приложения</div>
      <div class="hint">Только вручную по кнопке. Берёт код из публичного GitHub-репозитория, конфиг роутера не затирается.</div>
      <div class="grid-form">
        <div class="field">
          <label for="updRepo">Репозиторий</label>
          <input id="updRepo" type="text" value="voodoorainbow/RouterVPN">
        </div>
        <div class="field">
          <label for="updRef">Ветка / тег</label>
          <input id="updRef" type="text" value="wg-monitor">
        </div>
      </div>
      <div class="actions" style="margin-top:14px">
        <button id="btnUpdSave">Сохранить</button>
        <button id="btnUpdCheck">Проверить обновления</button>
        <button id="btnUpdApply">Обновить из репозитория</button>
      </div>
      <div class="hint" id="updStatus"></div>
    </section>
    <section class="card">
      <div class="label">События</div>
      <ul class="events" id="events"></ul>
    </section>
  </main>
  <script>
    let htSettings = null;
    let updInfo = null;
    function shortSha(sha) {
      if (!sha) return "—";
      return String(sha).slice(0, 7);
    }
    function renderUpdate(info) {
      updInfo = info || {};
      const repoInput = document.getElementById("updRepo");
      const refInput = document.getElementById("updRef");
      if (document.activeElement !== repoInput) repoInput.value = updInfo.update_repo || updInfo.repo || "voodoorainbow/RouterVPN";
      if (document.activeElement !== refInput) refInput.value = updInfo.update_ref || updInfo.ref || "wg-monitor";
      const local = updInfo.local || {};
      const remote = updInfo.remote || {};
      let text = "Локально: " + shortSha(local.sha);
      if (remote.sha) {
        text += " · в репозитории: " + shortSha(remote.sha);
        if (remote.message) text += " — " + remote.message;
        if (updInfo.update_available) text += " · есть обновление";
        else text += " · актуально";
      }
      document.getElementById("updStatus").textContent = text;
    }
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
    function setCountryOptions(countries, selected) {
      const sel = document.getElementById("htCountry");
      const current = selected || sel.value || "";
      const opts = ['<option value="">— выберите —</option>'];
      (countries || []).forEach(c => {
        const code = c.code || c;
        const count = c.count != null ? (" · " + c.count) : "";
        const sample = c.sample ? (" — " + c.sample) : "";
        opts.push('<option value="' + code + '">' + code + count + sample + '</option>');
      });
      if (current && !(countries || []).some(c => (c.code || c) === current)) {
        opts.push('<option value="' + current + '">' + current + '</option>');
      }
      sel.innerHTML = opts.join("");
      sel.value = current || "";
    }
    function renderHidethis(settings) {
      htSettings = settings || {};
      const codeHint = document.getElementById("htCodeHint");
      codeHint.textContent = htSettings.hidethis_access_code_set
        ? ("сохранён: " + (htSettings.hidethis_access_code_masked || "****"))
        : "не задан";
      const codeInput = document.getElementById("htCode");
      if (document.activeElement !== codeInput && !codeInput.value) {
        codeInput.placeholder = htSettings.hidethis_access_code_set ? "оставьте пустым, чтобы не менять" : "код из письма";
      }
      document.getElementById("htAwg").value = String(htSettings.hidethis_awg || 4);
      if (htSettings.hidethis_country) {
        const sel = document.getElementById("htCountry");
        if (![...sel.options].some(o => o.value === htSettings.hidethis_country)) {
          sel.insertAdjacentHTML("beforeend", '<option value="' + htSettings.hidethis_country + '">' + htSettings.hidethis_country + '</option>');
        }
        if (document.activeElement !== sel) sel.value = htSettings.hidethis_country;
      }
      const autoBtn = document.getElementById("btnHtAuto");
      const on = !!htSettings.auto_provision_enabled;
      autoBtn.textContent = "Авто при отсутствии VPN: " + (on ? "ON" : "OFF");
      autoBtn.classList.toggle("active", on);
      const cleanBtn = document.getElementById("btnHtCleanup");
      const cleanOn = !!htSettings.delete_inactive_enabled;
      cleanBtn.textContent = "Удалять неактивные VPN: " + (cleanOn ? "ON" : "OFF");
      cleanBtn.classList.toggle("active", cleanOn);
      const daysInput = document.getElementById("htCleanupDays");
      if (document.activeElement !== daysInput) {
        daysInput.value = String(htSettings.delete_inactive_after_days || 7);
      }
      const lp = htSettings.last_provision;
      let statusText = lp
        ? ("Последняя установка: " + fmtTs(lp.ts) + " · " + (lp.country || "") +
           " · +" + ((lp.created || []).length) + " / skip " + ((lp.skipped || []).length) +
           " / err " + ((lp.errors || []).length))
        : "Ещё не устанавливали конфиги из UI.";
      const lc = htSettings.last_cleanup;
      if (lc && (lc.deleted || []).length) {
        statusText += " · очистка: удалено " + lc.deleted.length + " (" + fmtTs(lc.ts) + ")";
      }
      document.getElementById("htStatus").textContent = statusText;
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
    async function refreshHidethis() {
      const settings = await api("/api/hidethis/settings");
      renderHidethis(settings);
      return settings;
    }
    async function refreshUpdate() {
      const info = await api("/api/update/status");
      renderUpdate(info);
      return info;
    }
    async function refresh() {
      const state = await api("/api/state");
      render(state);
      await refreshHidethis().catch(() => {});
      await refreshUpdate().catch(() => {});
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
    document.getElementById("btnHtSave").onclick = async () => {
      const country = document.getElementById("htCountry").value.trim().toUpperCase();
      if (!country) {
        alert("Страна обязательна");
        return;
      }
      const body = {
        hidethis_country: country,
        hidethis_awg: Number(document.getElementById("htAwg").value),
        auto_provision_enabled: !!(htSettings && htSettings.auto_provision_enabled)
      };
      const code = document.getElementById("htCode").value.trim();
      if (code) body.hidethis_access_code = code;
      try {
        const settings = await api("/api/hidethis/settings", { method: "POST", body: JSON.stringify(body) });
        document.getElementById("htCode").value = "";
        renderHidethis(settings);
        alert("Настройки сохранены");
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnHtCountries").onclick = async () => {
      try {
        const code = document.getElementById("htCode").value.trim();
        const q = code ? ("?code=" + encodeURIComponent(code)) : "";
        const data = await api("/api/hidethis/countries" + q);
        setCountryOptions(data.countries || [], (htSettings && htSettings.hidethis_country) || "");
        document.getElementById("htStatus").textContent = "Стран с WG: " + (data.countries || []).length;
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnHtInstall").onclick = async () => {
      const country = document.getElementById("htCountry").value.trim().toUpperCase();
      if (!country) {
        alert("Сначала выберите страну");
        return;
      }
      if (!confirm("Скачать и установить все WG-конфиги для страны " + country + "?")) return;
      const btn = document.getElementById("btnHtInstall");
      btn.disabled = true;
      document.getElementById("htStatus").textContent = "Установка " + country + "…";
      try {
        // save country/awg first if needed
        const saveBody = {
          hidethis_country: country,
          hidethis_awg: Number(document.getElementById("htAwg").value)
        };
        const code = document.getElementById("htCode").value.trim();
        if (code) saveBody.hidethis_access_code = code;
        await api("/api/hidethis/settings", { method: "POST", body: JSON.stringify(saveBody) });
        const state = await api("/api/hidethis/install", {
          method: "POST",
          body: JSON.stringify({ country })
        });
        document.getElementById("htCode").value = "";
        render(state);
        await refreshHidethis();
        const lp = state.last_provision || {};
        alert("Готово: +" + ((lp.created || []).length) + ", skip " + ((lp.skipped || []).length) + ", err " + ((lp.errors || []).length));
      } catch (e) { alert(e.message); }
      finally { btn.disabled = false; }
    };
    document.getElementById("btnHtAuto").onclick = async () => {
      try {
        const cur = !!(htSettings && htSettings.auto_provision_enabled);
        const settings = await api("/api/hidethis/settings", {
          method: "POST",
          body: JSON.stringify({ auto_provision_enabled: !cur })
        });
        renderHidethis(settings);
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnHtCleanup").onclick = async () => {
      try {
        const cur = !!(htSettings && htSettings.delete_inactive_enabled);
        const settings = await api("/api/hidethis/settings", {
          method: "POST",
          body: JSON.stringify({ delete_inactive_enabled: !cur })
        });
        renderHidethis(settings);
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnHtCleanupSave").onclick = async () => {
      const days = Number(document.getElementById("htCleanupDays").value);
      if (!Number.isFinite(days) || days < 1) {
        alert("Укажите срок в днях (минимум 1)");
        return;
      }
      try {
        const settings = await api("/api/hidethis/settings", {
          method: "POST",
          body: JSON.stringify({ delete_inactive_after_days: Math.round(days) })
        });
        renderHidethis(settings);
        alert("Срок очистки сохранён");
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnUpdSave").onclick = async () => {
      try {
        const info = await api("/api/update/settings", {
          method: "POST",
          body: JSON.stringify({
            update_repo: document.getElementById("updRepo").value.trim(),
            update_ref: document.getElementById("updRef").value.trim()
          })
        });
        renderUpdate(info);
        alert("Настройки обновления сохранены");
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnUpdCheck").onclick = async () => {
      try {
        document.getElementById("updStatus").textContent = "Проверка…";
        const info = await api("/api/update/check", { method: "POST", body: "{}" });
        renderUpdate(Object.assign({}, updInfo || {}, info, {
          update_repo: info.repo,
          update_ref: info.ref
        }));
      } catch (e) { alert(e.message); }
    };
    document.getElementById("btnUpdApply").onclick = async () => {
      if (!confirm("Скачать и установить код из репозитория? Конфиг роутера сохранится. Сервис перезапустится.")) return;
      const btn = document.getElementById("btnUpdApply");
      btn.disabled = true;
      document.getElementById("updStatus").textContent = "Обновление…";
      try {
        await api("/api/update/settings", {
          method: "POST",
          body: JSON.stringify({
            update_repo: document.getElementById("updRepo").value.trim(),
            update_ref: document.getElementById("updRef").value.trim()
          })
        });
        const result = await api("/api/update/apply", {
          method: "POST",
          body: JSON.stringify({ force: false })
        });
        document.getElementById("updStatus").textContent = result.message || JSON.stringify(result);
        if (result.restart_scheduled) {
          setTimeout(() => refresh().catch(() => {}), 4000);
        } else {
          await refreshUpdate();
        }
      } catch (e) { alert(e.message); }
      finally { btn.disabled = false; }
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
        query = urlparse(self.path).query
        if path in ("/", "/index.html"):
            self._html(HTML_PAGE)
            return
        if path == "/api/state":
            state = self.monitor.store.load()
            state["check_interval_sec"] = self.monitor.check_interval_sec
            state["failover_enabled"] = self.monitor.failover_enabled
            state["auto_provision_enabled"] = self.monitor.auto_provision_enabled
            self._json(200, state)
            return
        if path == "/api/hidethis/settings":
            self._json(200, self.monitor.hidethis_settings())
            return
        if path == "/api/hidethis/countries":
            try:
                from urllib.parse import parse_qs

                params = parse_qs(query)
                code = (params.get("code") or [None])[0]
                countries = self.monitor.provisioner.list_countries(access_code=code)
                self._json(200, {"countries": countries})
            except HidethisError as exc:
                self._json(400, {"error": str(exc)})
            return
        if path == "/api/hidethis/servers":
            try:
                from urllib.parse import parse_qs

                params = parse_qs(query)
                country = (params.get("country") or [None])[0]
                code = (params.get("code") or [None])[0]
                servers = self.monitor.provisioner.list_servers(country=country, access_code=code)
                self._json(200, {"servers": servers})
            except HidethisError as exc:
                self._json(400, {"error": str(exc)})
            return
        if path == "/api/update/status":
            self._json(200, self.monitor.update_settings_public())
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
            if path == "/api/hidethis/settings":
                body = self._read_json()
                try:
                    settings = self.monitor.update_hidethis_settings(body)
                except (HidethisError, ValueError) as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, settings)
                return
            if path == "/api/hidethis/install":
                body = self._read_json()
                country = body.get("country")
                try:
                    state = self.monitor.install_hidethis_country(country=country)
                except HidethisError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, state)
                return
            if path == "/api/update/settings":
                body = self._read_json()
                try:
                    info = self.monitor.update_update_settings(body)
                except Exception as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, info)
                return
            if path == "/api/update/check":
                try:
                    info = self.monitor.check_for_updates()
                except SelfUpdateError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, info)
                return
            if path == "/api/update/apply":
                body = self._read_json()
                force = bool(body.get("force"))
                try:
                    result = self.monitor.apply_self_update(force=force)
                except SelfUpdateError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, result)
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
