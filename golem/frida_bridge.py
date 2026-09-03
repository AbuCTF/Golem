"""Frida bridge — manages Frida sessions, script injection, and message routing.

Handles Frida server lifecycle on the device, script loading from the scripts/
directory, and routes Frida messages back to the session for storage/analysis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from golem import config

log = logging.getLogger(__name__)

FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
FRIDA_SERVER_NAME = "frida-server"


@dataclass
class ScriptHandle:
    name: str
    script: Any
    messages: list[dict] = field(default_factory=list)
    active: bool = True


class FridaBridge:
    """Manages Frida instrumentation for a device session."""

    def __init__(self, serial: str, *, on_message: Callable | None = None):
        self._serial = serial
        self._device = None
        self._session = None
        self._scripts: dict[str, ScriptHandle] = {}
        self._on_message = on_message or self._default_on_message
        self._message_log: list[dict] = []

    async def connect(self) -> None:
        """Connect to Frida on the device."""
        import frida
        try:
            self._device = frida.get_device(self._serial)
        except frida.InvalidArgumentError:
            self._device = frida.get_usb_device()
        log.info("frida connected to %s", self._serial)

    async def ensure_server(self) -> None:
        """Ensure frida-server is running on the device. Auto-downloads if missing."""
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell",
            "ps -A | grep frida-server",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        if b"frida-server" in out:
            log.debug("frida-server already running")
            return

        check = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell",
            f"ls {FRIDA_SERVER_PATH}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await check.communicate()
        if FRIDA_SERVER_PATH.encode() not in out:
            await self._auto_download_server()

        # start as root
        await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell",
            f"su -c '{FRIDA_SERVER_PATH} -D &'",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        for _ in range(10):
            await asyncio.sleep(0.5)
            verify = await asyncio.create_subprocess_exec(
                "adb", "-s", self._serial, "shell",
                "ps -A | grep frida-server",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await verify.communicate()
            if b"frida-server" in out:
                log.info("frida-server started on %s", self._serial)
                return
        raise RuntimeError("frida-server failed to start within 5s")

    async def _auto_download_server(self) -> None:
        """Download frida-server matching the installed frida Python version."""
        import frida
        version = frida.__version__

        arch_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", "getprop", "ro.product.cpu.abi",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        arch_out, _ = await arch_proc.communicate()
        abi = arch_out.decode().strip()
        arch_map = {"x86_64": "x86_64", "x86": "x86", "arm64-v8a": "arm64", "armeabi-v7a": "arm"}
        arch = arch_map.get(abi, abi)

        filename = f"frida-server-{version}-android-{arch}"
        url = f"https://github.com/frida/frida/releases/download/{version}/{filename}.xz"

        cache_dir = Path.home() / ".cache" / "golem" / "frida"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached = cache_dir / filename

        if not cached.exists():
            log.info("downloading frida-server %s for %s...", version, arch)
            dl = await asyncio.create_subprocess_exec(
                "curl", "-fSL", "-o", str(cached) + ".xz", url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, dl_err = await dl.communicate()
            if dl.returncode != 0:
                raise RuntimeError(f"failed to download frida-server: {dl_err.decode().strip()}")
            xz = await asyncio.create_subprocess_exec(
                "xz", "-d", str(cached) + ".xz",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await xz.communicate()
            if not cached.exists():
                raise RuntimeError("xz decompression failed")

        log.info("pushing frida-server to device...")
        push = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "push", str(cached), FRIDA_SERVER_PATH,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, push_err = await push.communicate()
        if push.returncode != 0:
            raise RuntimeError(f"adb push frida-server failed: {push_err.decode().strip()}")

        chmod = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", "chmod", "755", FRIDA_SERVER_PATH,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await chmod.communicate()
        log.info("frida-server %s (%s) installed on device", version, arch)

    async def attach(self, target: str | int) -> None:
        """Attach to a running process by name or PID."""
        if not self._device:
            await self.connect()
        try:
            if isinstance(target, int):
                self._session = self._device.attach(target)
            else:
                self._session = self._device.attach(target)
            log.info("frida attached to %s", target)
        except Exception as e:
            raise RuntimeError(f"failed to attach to {target}: {e}")

    async def spawn(self, package: str, *, paused: bool = True) -> int:
        """Spawn an app and optionally pause it for early instrumentation."""
        if not self._device:
            await self.connect()
        pid = self._device.spawn([package])
        self._session = self._device.attach(pid)
        log.info("spawned %s (pid=%d, paused=%s)", package, pid, paused)
        if not paused:
            self._device.resume(pid)
        return pid

    def resume(self, pid: int) -> None:
        """Resume a spawned process."""
        if self._device:
            self._device.resume(pid)
            log.info("resumed pid %d", pid)

    async def load_script(self, name: str, source: str | None = None) -> ScriptHandle:
        """Load a Frida script by name (from scripts/ dir) or raw source."""
        if not self._session:
            raise RuntimeError("not attached to any process")

        if source is None:
            script_path = config.FRIDA_SCRIPTS_DIR / f"{name}.js"
            if not script_path.exists():
                raise FileNotFoundError(f"script not found: {script_path}")
            source = script_path.read_text()

        script = self._session.create_script(source)
        handle = ScriptHandle(name=name, script=script)
        self._scripts[name] = handle

        def on_msg(message, data):
            self._handle_message(name, message, data)

        script.on("message", on_msg)
        await asyncio.get_running_loop().run_in_executor(None, script.load)
        log.info("loaded frida script '%s'", name)
        return handle

    async def load_scripts(self, *names: str) -> list[ScriptHandle]:
        """Load multiple scripts by name."""
        handles = []
        for name in names:
            h = await self.load_script(name)
            handles.append(h)
        return handles

    async def unload_script(self, name: str) -> None:
        """Unload a script by name."""
        handle = self._scripts.pop(name, None)
        if handle and handle.script:
            try:
                handle.script.unload()
            except Exception:
                pass
            handle.active = False
            log.info("unloaded frida script '%s'", name)

    async def run_snippet(self, js: str) -> Any:
        """Run a one-off JS snippet in the current session."""
        if not self._session:
            raise RuntimeError("not attached to any process")
        script = self._session.create_script(js)
        result = []

        def on_msg(message, data):
            if message.get("type") == "send":
                result.append(message.get("payload"))

        script.on("message", on_msg)
        await asyncio.get_running_loop().run_in_executor(None, script.load)
        await asyncio.sleep(0.5)
        script.unload()
        return result[0] if result else None

    def get_messages(self, script_name: str | None = None) -> list[dict]:
        """Get collected messages, optionally filtered by script."""
        if script_name:
            handle = self._scripts.get(script_name)
            return handle.messages if handle else []
        return list(self._message_log)

    def clear_messages(self, script_name: str | None = None) -> None:
        """Clear collected messages."""
        if script_name:
            handle = self._scripts.get(script_name)
            if handle:
                handle.messages.clear()
        else:
            self._message_log.clear()
            for h in self._scripts.values():
                h.messages.clear()

    async def list_processes(self) -> list[dict]:
        """List running processes on the device."""
        if not self._device:
            await self.connect()
        procs = self._device.enumerate_processes()
        return [{"pid": p.pid, "name": p.name} for p in procs]

    async def detach(self) -> None:
        """Detach from current session."""
        for name in list(self._scripts.keys()):
            await self.unload_script(name)
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None
            log.info("frida detached")

    def _handle_message(self, script_name: str, message: dict, data: Any) -> None:
        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload", {})
            entry = {"script": script_name, "payload": payload}
            self._message_log.append(entry)
            handle = self._scripts.get(script_name)
            if handle:
                handle.messages.append(entry)
            self._on_message(script_name, payload)
        elif msg_type == "error":
            log.error("frida error in '%s': %s", script_name, message.get("description", ""))

    def _default_on_message(self, script_name: str, payload: Any) -> None:
        msg_type = payload.get("type", "?") if isinstance(payload, dict) else "?"
        log.debug("[frida:%s] %s: %s", script_name, msg_type, _truncate(str(payload), 200))

    @property
    def is_attached(self) -> bool:
        return self._session is not None

    @property
    def loaded_scripts(self) -> list[str]:
        return [n for n, h in self._scripts.items() if h.active]

    @staticmethod
    def available_scripts() -> list[str]:
        """List available scripts in the scripts/ directory."""
        if not config.FRIDA_SCRIPTS_DIR.exists():
            return []
        return sorted(
            p.stem for p in config.FRIDA_SCRIPTS_DIR.glob("*.js")
        )


def _truncate(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
