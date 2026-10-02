"""Manual self-update of wg-monitor from a GitHub repository zipball."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any, Optional

log = logging.getLogger("wg-monitor.update")

DEFAULT_REPO = "voodoorainbow/RouterVPN"
DEFAULT_REF = "wg-monitor"
VERSION_NAME = "VERSION"


class SelfUpdateError(Exception):
    pass


def _version_path(share_dir: str) -> str:
    return os.path.join(share_dir, VERSION_NAME)


def read_installed_version(share_dir: str) -> dict[str, Any]:
    path = _version_path(share_dir)
    if not os.path.exists(path):
        return {"sha": None, "ref": None, "repo": None, "updated_at": None}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {
                "sha": data.get("sha"),
                "ref": data.get("ref"),
                "repo": data.get("repo"),
                "updated_at": data.get("updated_at"),
            }
    except (OSError, json.JSONDecodeError):
        pass
    return {"sha": None, "ref": None, "repo": None, "updated_at": None}


def write_installed_version(share_dir: str, *, sha: str, ref: str, repo: str) -> dict[str, Any]:
    payload = {
        "sha": sha,
        "ref": ref,
        "repo": repo,
        "updated_at": time.time(),
    }
    os.makedirs(share_dir, exist_ok=True)
    path = _version_path(share_dir)
    fd, tmp = tempfile.mkstemp(prefix="wg-ver-", suffix=".json", dir=share_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return payload


def _github_request(
    url: str,
    token: Optional[str],
    *,
    accept: str = "application/vnd.github+json",
    timeout: float = 60.0,
) -> tuple[bytes, dict[str, str]]:
    headers = {
        "Accept": accept,
        "User-Agent": "wg-monitor-self-update",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token.strip()}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            meta = {k.lower(): v for k, v in resp.headers.items()}
            return body, meta
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:400] if hasattr(exc, "read") else b""
        raise SelfUpdateError(f"GitHub HTTP {exc.code}: {detail!r}") from exc
    except urllib.error.URLError as exc:
        raise SelfUpdateError(f"GitHub URL error: {exc}") from exc


def fetch_remote_commit(repo: str, ref: str, token: Optional[str], timeout: float = 30.0) -> dict[str, Any]:
    repo = (repo or "").strip()
    ref = (ref or "").strip()
    if not repo or "/" not in repo:
        raise SelfUpdateError("update_repo must look like owner/name")
    if not ref:
        raise SelfUpdateError("update_ref is required")
    from urllib.parse import quote

    url = f"https://api.github.com/repos/{repo}/commits/{quote(ref, safe='')}"
    raw, _ = _github_request(url, token, timeout=timeout)
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SelfUpdateError("Invalid GitHub commit response") from exc
    sha = data.get("sha")
    if not sha:
        raise SelfUpdateError("GitHub commit response has no sha")
    commit = data.get("commit") or {}
    message = ""
    if isinstance(commit, dict):
        message = (commit.get("message") or "").splitlines()[0]
    return {
        "sha": sha,
        "short_sha": sha[:7],
        "message": message,
        "html_url": data.get("html_url"),
        "repo": repo,
        "ref": ref,
    }


def _find_wg_monitor_dir(extract_root: str) -> str:
    for root, dirs, files in os.walk(extract_root):
        if "main.py" in files and os.path.isdir(os.path.join(root, "lib")):
            # Prefer .../wg-monitor/main.py
            base = os.path.basename(root)
            if base == "wg-monitor" or os.path.exists(os.path.join(root, "install.sh")):
                return root
    raise SelfUpdateError("wg-monitor directory not found in archive")


def _copy_tree_files(src_app: str, share_dir: str) -> None:
    os.makedirs(share_dir, exist_ok=True)
    lib_dst = os.path.join(share_dir, "lib")
    os.makedirs(lib_dst, exist_ok=True)

    src_main = os.path.join(src_app, "main.py")
    if not os.path.isfile(src_main):
        raise SelfUpdateError("archive is missing main.py")
    shutil.copy2(src_main, os.path.join(share_dir, "main.py"))
    os.chmod(os.path.join(share_dir, "main.py"), 0o755)

    src_lib = os.path.join(src_app, "lib")
    if not os.path.isdir(src_lib):
        raise SelfUpdateError("archive is missing lib/")
    # Remove old py modules then copy fresh set
    for name in os.listdir(lib_dst):
        path = os.path.join(lib_dst, name)
        if name.endswith(".py") or name == "__pycache__":
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    os.unlink(path)
                except OSError:
                    pass
    for name in os.listdir(src_lib):
        if not name.endswith(".py"):
            continue
        shutil.copy2(os.path.join(src_lib, name), os.path.join(lib_dst, name))

    example = os.path.join(src_app, "config.example.json")
    if os.path.isfile(example):
        shutil.copy2(example, os.path.join(share_dir, "config.example.json"))

    install_src = os.path.join(src_app, "install.sh")
    if os.path.isfile(install_src):
        shutil.copy2(install_src, os.path.join(share_dir, "install.sh"))
        os.chmod(os.path.join(share_dir, "install.sh"), 0o755)


def _update_init_script(src_app: str, opt_root: str) -> None:
    src = os.path.join(src_app, "entware", "S99wg-monitor")
    dst = os.path.join(opt_root, "etc", "init.d", "S99wg-monitor")
    if os.path.isfile(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)


def schedule_restart(opt_root: str = "/opt", delay_sec: float = 1.5) -> None:
    initd = os.path.join(opt_root, "etc", "init.d", "S99wg-monitor")

    def _run() -> None:
        time.sleep(delay_sec)
        try:
            log.info("Restarting wg-monitor after update")
            subprocess.run([initd, "restart"], check=False, timeout=60)
        except Exception:
            log.exception("Failed to restart after update")

    threading.Thread(target=_run, name="wg-update-restart", daemon=True).start()


class SelfUpdater:
    def __init__(self, config: dict, share_dir: Optional[str] = None, opt_root: str = "/opt"):
        self.config = config
        self.opt_root = opt_root
        self.share_dir = share_dir or os.path.join(opt_root, "share", "wg-monitor")
        self._lock = threading.Lock()

    @property
    def repo(self) -> str:
        return (self.config.get("update_repo") or DEFAULT_REPO).strip()

    @property
    def ref(self) -> str:
        return (self.config.get("update_ref") or DEFAULT_REF).strip()

    @property
    def token(self) -> str:
        return (self.config.get("github_token") or "").strip()

    def status(self, *, check_remote: bool = False) -> dict[str, Any]:
        local = read_installed_version(self.share_dir)
        out: dict[str, Any] = {
            "repo": self.repo,
            "ref": self.ref,
            "local": local,
            "remote": None,
            "update_available": None,
        }
        if check_remote:
            remote = fetch_remote_commit(self.repo, self.ref, self.token or None)
            out["remote"] = remote
            local_sha = (local.get("sha") or "").lower()
            remote_sha = (remote.get("sha") or "").lower()
            out["update_available"] = bool(remote_sha and remote_sha != local_sha)
        return out

    def apply_update(self, *, force: bool = False) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise SelfUpdateError("Update already in progress")
        work: Optional[str] = None
        try:
            remote = fetch_remote_commit(self.repo, self.ref, self.token or None)
            local = read_installed_version(self.share_dir)
            if not force and local.get("sha") and local.get("sha") == remote["sha"]:
                return {
                    "updated": False,
                    "reason": "already_up_to_date",
                    "local": local,
                    "remote": remote,
                    "restart_scheduled": False,
                }

            from urllib.parse import quote

            zip_url = (
                f"https://api.github.com/repos/{self.repo}/zipball/{quote(self.ref, safe='')}"
            )
            log.info("Downloading %s @ %s (%s)", self.repo, self.ref, remote["short_sha"])
            raw, _ = _github_request(
                zip_url,
                self.token or None,
                accept="application/vnd.github+json",
                timeout=120.0,
            )
            if len(raw) < 1000:
                raise SelfUpdateError(f"Downloaded archive looks too small ({len(raw)} bytes)")

            work = tempfile.mkdtemp(prefix="wg-upd-")
            zip_path = os.path.join(work, "source.zip")
            with open(zip_path, "wb") as fh:
                fh.write(raw)
            extract_dir = os.path.join(work, "extract")
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            src_app = _find_wg_monitor_dir(extract_dir)
            _copy_tree_files(src_app, self.share_dir)
            _update_init_script(src_app, self.opt_root)
            version = write_installed_version(
                self.share_dir,
                sha=remote["sha"],
                ref=self.ref,
                repo=self.repo,
            )
            # Keep wrapper script in sync
            bin_link = os.path.join(self.opt_root, "bin", "wg-monitor")
            with open(bin_link, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!/bin/sh\n"
                    f"exec {self.opt_root}/bin/python3 {self.share_dir}/main.py \"$@\"\n"
                )
            os.chmod(bin_link, 0o755)

            schedule_restart(self.opt_root)
            log.info("Update applied to %s", remote["short_sha"])
            return {
                "updated": True,
                "local": version,
                "remote": remote,
                "restart_scheduled": True,
                "message": f"Updated to {remote['short_sha']}; restart in ~2s",
            }
        finally:
            if work:
                shutil.rmtree(work, ignore_errors=True)
            self._lock.release()
