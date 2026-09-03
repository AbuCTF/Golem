"""Proxy layer — mitmproxy addon for transparent HTTPS interception.

Runs mitmproxy programmatically as an in-process addon. Captures requests/responses
with full bodies, supports filtering, and pipes traffic for analysis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

# Google system services use cert pinning and will ANR if proxied through mitmproxy.
# Pass these through untouched.
PROXY_IGNORE_HOSTS = [
    r".*\.google\.com", r".*\.googleapis\.com", r".*\.gstatic\.com",
    r".*\.tenor\.com", r".*\.android\.com", r".*\.google\.[a-z]+",
    r".*\.googlevideo\.com", r".*\.gvt[0-9]+\.com", r".*\.1e100\.net",
]


@dataclass
class CapturedFlow:
    id: str
    method: str
    url: str
    host: str
    path: str
    status_code: int | None
    request_headers: dict[str, str]
    request_body: bytes | None
    response_headers: dict[str, str] | None
    response_body: bytes | None
    timestamp: float
    duration: float | None
    content_type: str | None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status_code": self.status_code,
            "request_headers": self.request_headers,
            "request_body_len": len(self.request_body) if self.request_body else 0,
            "response_headers": self.response_headers,
            "response_body_len": len(self.response_body) if self.response_body else 0,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "content_type": self.content_type,
        }


class GolemAddon:
    """mitmproxy addon that captures traffic and applies filters."""

    def __init__(self, *, on_flow: Callable | None = None, filters: list[str] | None = None):
        self.flows: list[CapturedFlow] = []
        self._on_flow = on_flow
        self._filters = filters or []
        self._max_flows = 10000
        self._paused = False

    def response(self, flow):
        if self._paused:
            return

        if self._filters:
            matched = False
            for f in self._filters:
                if f in flow.request.pretty_host or f in flow.request.path:
                    matched = True
                    break
            if not matched:
                return

        req = flow.request
        resp = flow.response

        captured = CapturedFlow(
            id=flow.id,
            method=req.method,
            url=req.pretty_url,
            host=req.pretty_host,
            path=req.path,
            status_code=resp.status_code if resp else None,
            request_headers=dict(req.headers),
            request_body=req.get_content(limit=1_000_000),
            response_headers=dict(resp.headers) if resp else None,
            response_body=resp.get_content(limit=5_000_000) if resp else None,
            timestamp=req.timestamp_start,
            duration=(resp.timestamp_end - req.timestamp_start) if resp and resp.timestamp_end else None,
            content_type=resp.headers.get("content-type") if resp else None,
        )

        self.flows.append(captured)
        if len(self.flows) > self._max_flows:
            self.flows = self.flows[-self._max_flows:]

        if self._on_flow:
            self._on_flow(captured)

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def clear(self):
        self.flows.clear()

    def search(self, pattern: str) -> list[CapturedFlow]:
        """Search flows by URL, body, or header content."""
        results = []
        pattern_lower = pattern.lower()
        for f in self.flows:
            if pattern_lower in f.url.lower():
                results.append(f)
                continue
            if f.request_body and pattern_lower in f.request_body.decode(errors="replace").lower():
                results.append(f)
                continue
            if f.response_body and pattern_lower in f.response_body.decode(errors="replace").lower():
                results.append(f)
        return results


class ProxyServer:
    """Manages an in-process mitmproxy instance."""

    def __init__(self, *, port: int = 8082, host: str = "127.0.0.1"):
        self.port = port
        self.host = host
        self.addon = GolemAddon()
        self._master = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._start_error: Exception | None = None

    async def start(self, *, filters: list[str] | None = None,
                    on_flow: Callable | None = None,
                    ignore_hosts: list[str] | None = None) -> None:
        """Start the proxy server in a background thread."""
        if self._running:
            log.info("proxy already running on %s:%d", self.host, self.port)
            return

        self.addon = GolemAddon(on_flow=on_flow, filters=filters)
        _ignore = ignore_hosts if ignore_hosts is not None else PROXY_IGNORE_HOSTS
        self._start_error = None

        def _run():
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster

            try:
                opts = Options(
                    listen_host=self.host,
                    listen_port=self.port,
                    ignore_hosts=_ignore,
                )
                self._master = DumpMaster(opts)
                self._master.addons.add(self.addon)
                log.info("proxy starting on %s:%d (ignoring %d host patterns)", self.host, self.port, len(_ignore))
                self._running = True
                self._master.run()
            except Exception as e:
                self._start_error = e
                log.error("proxy thread failed: %s", e)
            finally:
                self._running = False

        self._thread = threading.Thread(target=_run, daemon=True, name="golem-proxy")
        self._thread.start()

        for _ in range(30):
            if self._start_error:
                raise RuntimeError(f"proxy failed to start: {self._start_error}") from self._start_error
            if self._running:
                break
            await asyncio.sleep(0.5)
        else:
            raise RuntimeError("proxy failed to start within 15s")

        log.info("proxy ready on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._master:
            self._master.shutdown()
            self._master = None
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None
        log.info("proxy stopped")

    @property
    def ca_cert_path(self) -> Path:
        """Path to mitmproxy's CA certificate (PEM)."""
        return Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    @property
    def ca_cert_cer(self) -> Path:
        """Path to mitmproxy's CA certificate (CER/DER for Android)."""
        return Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"

    @property
    def flows(self) -> list[CapturedFlow]:
        return self.addon.flows

    @property
    def is_running(self) -> bool:
        return self._running


async def install_ca_cert(serial: str, cert_path: Path | None = None) -> str:
    """Install a CA certificate into the Android system trust store.

    Handles both pre-14 and Android 14+ (APEX conscrypt) cert stores.
    Active immediately — no reboot required.

    Returns "apex", "remount", or "legacy" indicating which method was used.
    """
    if cert_path is None:
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    if not cert_path.exists():
        raise FileNotFoundError(f"CA cert not found at {cert_path}")

    hash_proc = await asyncio.create_subprocess_exec(
        "openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path), "-noout",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    hash_out, hash_err = await hash_proc.communicate()
    if hash_proc.returncode != 0:
        raise RuntimeError(f"openssl hash failed: {hash_err.decode()}")
    cert_hash = hash_out.decode().strip()
    dest_name = f"{cert_hash}.0"

    log.info("installing CA cert %s as %s on %s", cert_path.name, dest_name, serial)

    async def _adb(*args):
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        return out.decode(), err.decode(), proc.returncode

    root_out, root_err, root_rc = await _adb("root")
    root_msg = (root_out + root_err).lower()
    if root_rc != 0 or "cannot run as root" in root_msg:
        raise RuntimeError(f"adb root failed (device must be rooted for cert installation): {(root_out + root_err).strip()}")
    for _ in range(10):
        await asyncio.sleep(1)
        try:
            probe_out, _, probe_rc = await _adb("shell", "echo", "ok")
            if probe_rc == 0 and "ok" in probe_out:
                break
        except Exception:
            pass

    api_out, _, _ = await _adb("shell", "getprop", "ro.build.version.sdk")
    api_level = int(api_out.strip()) if api_out.strip().isdigit() else 0

    staging = "/data/local/tmp/golem_cacerts"
    await _adb("push", str(cert_path), f"/data/local/tmp/{dest_name}")

    # Android 14+ (API 34): certs moved to APEX conscrypt module
    if api_level >= 34:
        apex_certs = "/apex/com.android.conscrypt/cacerts"
        out, _, rc = await _adb("shell", "ls", apex_certs)
        if rc == 0:
            result = await _install_apex_cert(serial, dest_name, apex_certs, staging, _adb)
            if result:
                return result

    # Try remount for persistent install + immediate overlay
    _, remount_err, remount_rc = await _adb("remount")
    if remount_rc == 0 and "bootloader" not in remount_err.lower():
        await asyncio.sleep(1)
        await _adb("shell", "cp", f"/data/local/tmp/{dest_name}",
                    f"/system/etc/security/cacerts/{dest_name}")
        await _adb("shell", "chmod", "644", f"/system/etc/security/cacerts/{dest_name}")
        out, _, _ = await _adb("shell", "ls", f"/system/etc/security/cacerts/{dest_name}")
        if dest_name in out:
            log.info("CA cert installed via remount as %s", dest_name)
            return "remount"

    # Fallback: tmpfs overlay on /system/etc/security/cacerts (pre-14)
    log.info("using tmpfs overlay on system cacerts")
    await _adb("shell", "rm", "-rf", staging)
    await _adb("shell", "mkdir", "-p", staging)
    await _adb("shell", "cp", "/system/etc/security/cacerts/*", staging + "/")
    await _adb("shell", "cp", f"/data/local/tmp/{dest_name}", f"{staging}/{dest_name}")
    await _adb("shell", "chmod", "644", f"{staging}/{dest_name}")

    await _adb("shell", "mount", "-t", "tmpfs", "tmpfs", "/system/etc/security/cacerts")
    await _adb("shell", "cp", staging + "/*", "/system/etc/security/cacerts/")
    await _adb("shell", "chmod", "644", "/system/etc/security/cacerts/*")
    await _adb("shell", "chcon", "u:object_r:system_file:s0", "/system/etc/security/cacerts/*")

    out, _, _ = await _adb("shell", "ls", f"/system/etc/security/cacerts/{dest_name}")
    if dest_name in out:
        log.info("CA cert installed via legacy tmpfs overlay as %s", dest_name)
        return "legacy"

    raise RuntimeError("CA cert install failed — all methods exhausted")


async def _install_apex_cert(serial, dest_name, apex_certs, staging, _adb) -> str | None:
    """Install cert into APEX conscrypt cert store (Android 14+).

    Uses nsenter into init's mount namespace so the overlay is visible to all
    processes, then restarts Zygote so new app processes inherit the mount.
    """
    log.info("Android 14+ detected — installing into APEX conscrypt")

    await _adb("shell", "rm", "-rf", staging)
    await _adb("shell", "mkdir", "-p", staging)
    await _adb("shell", "cp", f"{apex_certs}/*", staging + "/")
    await _adb("shell", "cp", f"/data/local/tmp/{dest_name}", f"{staging}/{dest_name}")
    await _adb("shell", "chmod", "644", f"{staging}/{dest_name}")

    mount_cmds = [
        f"mount -t tmpfs tmpfs {apex_certs}",
        f"cp {staging}/* {apex_certs}/",
        f"chmod 644 {apex_certs}/*",
        f"chcon u:object_r:system_file:s0 {apex_certs}/*",
    ]

    # try nsenter (global mount namespace)
    for cmd in mount_cmds:
        await _adb("shell", "nsenter", "--mount=/proc/1/ns/mnt", "--", "sh", "-c", cmd)

    out, _, _ = await _adb("shell", "ls", f"{apex_certs}/{dest_name}")
    if dest_name not in out:
        # fallback: direct mount
        log.info("nsenter failed, trying direct APEX mount")
        await _adb("shell", "mount", "-t", "tmpfs", "tmpfs", apex_certs)
        await _adb("shell", "cp", staging + "/*", apex_certs + "/")
        await _adb("shell", "chmod", "644", apex_certs + "/*")
        await _adb("shell", "chcon", "u:object_r:system_file:s0", apex_certs + "/*")

        out, _, _ = await _adb("shell", "ls", f"{apex_certs}/{dest_name}")
        if dest_name not in out:
            return None

    log.info("APEX overlay mounted — restarting Zygote to apply")
    await _adb("shell", "setprop", "ctl.restart", "zygote")

    # wait for framework to recover
    for _ in range(60):
        await asyncio.sleep(2)
        boot_out, _, _ = await _adb("shell", "getprop", "sys.boot_completed")
        svc_out, _, _ = await _adb("shell", "service", "check", "activity")
        if boot_out.strip() == "1" and "found" in svc_out:
            log.info("framework recovered after Zygote restart")
            return "apex"

    log.warning("framework slow to recover after Zygote restart — cert installed but apps may need manual restart")
    return "apex"


async def inject_cert_into_apps(serial: str, cert_path: Path | None = None) -> int:
    """Inject CA cert into running app processes' mount namespaces.

    Alternative to Zygote restart — injects the cert overlay into each
    running app's view of the cert store so HTTPS interception works
    immediately without killing any apps. Returns the number of processes
    patched.
    """
    if cert_path is None:
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    hash_proc = await asyncio.create_subprocess_exec(
        "openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path), "-noout",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    hash_out, _ = await hash_proc.communicate()
    cert_hash = hash_out.decode().strip()
    dest_name = f"{cert_hash}.0"

    async def _adb(*args):
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        return out.decode(), err.decode(), proc.returncode

    api_out, _, _ = await _adb("shell", "getprop", "ro.build.version.sdk")
    api_level = int(api_out.strip()) if api_out.strip().isdigit() else 0
    cert_dir = "/apex/com.android.conscrypt/cacerts" if api_level >= 34 else "/system/etc/security/cacerts"
    staging = "/data/local/tmp/golem_cacerts"

    out, _, _ = await _adb("shell", f"ls {staging}/{dest_name}")
    if dest_name not in out:
        log.info("cert not staged yet, run install_ca_cert first")
        return 0

    ps_out, _, _ = await _adb("shell", "ps", "-A", "-o", "PID,USER,NAME")
    patched = 0
    for line in ps_out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, user, name = parts
        if not user.startswith("u0_a"):
            continue
        try:
            int(pid)
        except ValueError:
            continue

        mount_script = (
            f"nsenter --mount=/proc/{pid}/ns/mnt -- sh -c '"
            f"mount -t tmpfs tmpfs {cert_dir} 2>/dev/null; "
            f"cp {staging}/* {cert_dir}/ 2>/dev/null; "
            f"chmod 644 {cert_dir}/* 2>/dev/null'"
        )
        _, _, rc = await _adb("shell", "su", "-c", mount_script)
        if rc == 0:
            patched += 1

    log.info("injected cert into %d app processes on %s", patched, serial)
    return patched


async def configure_proxy(serial: str, host: str = "10.0.2.2", port: int = 8082) -> None:
    """Configure the Android emulator to use our proxy.

    Also disables captive portal detection and background ANR dialogs to prevent
    Google system services from causing cascading failures through the proxy.
    10.0.2.2 is the emulator's alias for the host machine's loopback.
    """
    async def _adb(*args):
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        return out.decode(), err.decode(), proc.returncode

    # disable captive portal + background ANR before enabling proxy
    await _adb("shell", "settings", "put", "global", "captive_portal_detection_enabled", "0")
    await _adb("shell", "settings", "put", "global", "captive_portal_mode", "0")
    await _adb("shell", "settings", "put", "secure", "anr_show_background", "0")

    out, err, rc = await _adb("shell", "settings", "put", "global", "http_proxy", f"{host}:{port}")
    if rc != 0:
        raise RuntimeError(f"failed to set proxy on {serial}: {err.strip()}")
    log.info("proxy configured on %s → %s:%d", serial, host, port)


async def clear_proxy(serial: str) -> None:
    """Remove proxy configuration and restore captive portal + ANR settings."""
    async def _adb(*args):
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    await _adb("shell", "settings", "put", "global", "http_proxy", ":0")
    await _adb("shell", "settings", "delete", "global", "global_http_proxy_host")
    await _adb("shell", "settings", "delete", "global", "global_http_proxy_port")
    await _adb("shell", "settings", "delete", "global", "global_http_proxy_exclusion_list")
    # restore settings that configure_proxy disabled
    await _adb("shell", "settings", "put", "global", "captive_portal_detection_enabled", "1")
    await _adb("shell", "settings", "put", "global", "captive_portal_mode", "1")
    await _adb("shell", "settings", "put", "secure", "anr_show_background", "1")
    log.info("proxy cleared on %s", serial)
