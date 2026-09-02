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

    async def start(self, *, filters: list[str] | None = None,
                    on_flow: Callable | None = None) -> None:
        """Start the proxy server in a background thread."""
        if self._running:
            log.info("proxy already running on %s:%d", self.host, self.port)
            return

        self.addon = GolemAddon(on_flow=on_flow, filters=filters)

        def _run():
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster

            opts = Options(listen_host=self.host, listen_port=self.port)
            self._master = DumpMaster(opts)
            self._master.addons.add(self.addon)
            log.info("proxy starting on %s:%d", self.host, self.port)
            self._running = True
            self._master.run()
            self._running = False

        self._thread = threading.Thread(target=_run, daemon=True, name="golem-proxy")
        self._thread.start()

        for _ in range(30):
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


async def install_ca_cert(serial: str, cert_path: Path | None = None) -> None:
    """Install a CA certificate into the Android system trust store.

    Requires root access. Works by:
    1. Computing the OpenSSL hash of the cert
    2. Pushing it to /system/etc/security/cacerts/ with the hash filename
    3. Setting permissions
    """
    if cert_path is None:
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    if not cert_path.exists():
        raise FileNotFoundError(f"CA cert not found at {cert_path}")

    import subprocess
    hash_result = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path), "-noout"],
        capture_output=True, text=True,
    )
    if hash_result.returncode != 0:
        raise RuntimeError(f"openssl hash failed: {hash_result.stderr}")
    cert_hash = hash_result.stdout.strip()
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

    await _adb("root")
    await asyncio.sleep(1)

    # Try direct remount first (works on writable-system images)
    _, remount_err, remount_rc = await _adb("remount")
    if remount_rc == 0 and "bootloader" not in remount_err.lower():
        await asyncio.sleep(1)
        await _adb("push", str(cert_path), f"/system/etc/security/cacerts/{dest_name}")
        await _adb("shell", "chmod", "644", f"/system/etc/security/cacerts/{dest_name}")
        out, _, _ = await _adb("shell", "ls", f"/system/etc/security/cacerts/{dest_name}")
        if dest_name in out:
            log.info("CA cert installed via remount as %s", dest_name)
            return

    # Fallback: tmpfs overlay (Android 11+ with read-only /system)
    log.info("remount failed, using tmpfs overlay method")
    staging = "/data/local/tmp/golem_cacerts"

    await _adb("shell", "rm", "-rf", staging)
    await _adb("shell", "mkdir", "-p", staging)
    # Copy existing system certs to staging
    await _adb("shell", "cp", "/system/etc/security/cacerts/*", staging + "/")
    # Push our cert to staging
    await _adb("push", str(cert_path), f"{staging}/{dest_name}")
    await _adb("shell", "chmod", "644", f"{staging}/{dest_name}")

    # Mount overlay
    await _adb("shell", "mount", "-t", "tmpfs", "tmpfs", "/system/etc/security/cacerts")
    await _adb("shell", "cp", staging + "/*", "/system/etc/security/cacerts/")
    await _adb("shell", "chmod", "644", "/system/etc/security/cacerts/*")
    await _adb("shell", "chcon", "u:object_r:system_file:s0", "/system/etc/security/cacerts/*")

    out, _, _ = await _adb("shell", "ls", f"/system/etc/security/cacerts/{dest_name}")
    if dest_name in out:
        log.info("CA cert installed via tmpfs overlay as %s (persists until reboot)", dest_name)
    else:
        raise RuntimeError("CA cert install failed via both remount and overlay methods")


async def configure_proxy(serial: str, host: str = "10.0.2.2", port: int = 8082) -> None:
    """Configure the Android emulator to use our proxy.

    10.0.2.2 is the emulator's alias for the host machine's loopback.
    """
    async def _adb(*args):
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    await _adb("shell", "settings", "put", "global", "http_proxy", f"{host}:{port}")
    log.info("proxy configured on %s → %s:%d", serial, host, port)


async def clear_proxy(serial: str) -> None:
    """Remove proxy configuration from the device."""
    async def _adb(*args):
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", serial, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    await _adb("shell", "settings", "put", "global", "http_proxy", ":0")
    log.info("proxy cleared on %s", serial)
