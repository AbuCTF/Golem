"""Session — the core abstraction. One named testing context for one app on one device.

Mirrors Hutch's Session: named, stateful (ACTIVE/PAUSED/HIBERNATED), owns all
device interaction through uiautomator2 + ADB.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from golem import config
from golem.context import ContextTracker, HealthMonitor, ScreenDiff
from golem.device import Device, DeviceInfo
from golem.evidence import EvidenceStore
from golem.observe import Element, format_elements, parse_hierarchy

log = logging.getLogger(__name__)


class State(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    HIBERNATED = "hibernated"


@dataclass
class ScreenState:
    activity: str
    package: str
    hierarchy_xml: str
    screen_size: tuple[int, int]
    orientation: str
    keyboard_shown: bool


class Session:
    """Named testing session bound to a device. Owns uiautomator2 connection."""

    def __init__(self, name: str, device: Device, *, profile_dir: Path | None = None):
        self.name = name
        self.device = device
        self._state = State.HIBERNATED
        self._d = None  # uiautomator2 Device
        self._serial: str | None = None
        self._profile_dir = profile_dir or (config.PROFILES_DIR / name)
        self._meta: dict = {}
        self.context = ContextTracker()
        self._evidence: EvidenceStore | None = None
        self._health: HealthMonitor | None = None

    @property
    def state(self) -> State:
        return self._state

    @property
    def profile_dir(self) -> Path:
        return self._profile_dir

    @property
    def evidence(self) -> EvidenceStore:
        if self._evidence is None:
            self._evidence = EvidenceStore(self.name)
        return self._evidence

    @property
    def health(self) -> HealthMonitor:
        if self._health is None:
            if not self._serial:
                raise RuntimeError("no serial — session not launched")
            self._health = HealthMonitor(self._serial)
        return self._health

    async def health_check(self) -> dict:
        """Run a device health check and return the status as a dict."""
        status = await self.health.check()
        return {
            "device_online": status.device_online,
            "u2_responsive": status.u2_responsive,
            "battery_level": status.battery_level,
            "memory_free_mb": status.memory_free_mb,
            "disk_free_mb": status.disk_free_mb,
            "screen_on": status.screen_on,
            "uptime_seconds": status.uptime_seconds,
        }

    async def launch(self) -> None:
        """Boot device and connect uiautomator2."""
        self._profile_dir.mkdir(parents=True, exist_ok=True)
        self._serial = await self.device.boot()

        import uiautomator2 as u2
        self._d = u2.connect(self._serial)
        self._d.settings["wait_timeout"] = 10.0
        self._d.settings["operation_delay"] = (0.1, 0.1)

        for attempt in range(3):
            try:
                self._d.info
                break
            except Exception:
                if attempt == 2:
                    raise
                log.debug("u2 health check failed, retrying (%d/3)...", attempt + 1)
                await asyncio.sleep(2)
                self._d = u2.connect(self._serial)
                self._d.settings["wait_timeout"] = 10.0
                self._d.settings["operation_delay"] = (0.1, 0.1)

        self._state = State.ACTIVE
        self._save_meta()
        log.info("session '%s' launched on %s", self.name, self._serial)

    async def close(self) -> None:
        """Disconnect u2 but keep device running. State preserved."""
        self._state = State.HIBERNATED
        self._d = None
        self._save_meta()
        log.info("session '%s' hibernated", self.name)

    async def destroy(self) -> None:
        """Shut down device and remove profile."""
        await self.device.shutdown()
        self._state = State.HIBERNATED
        self._d = None
        import shutil
        if self._profile_dir.exists():
            shutil.rmtree(self._profile_dir)
        log.info("session '%s' destroyed", self.name)

    def _require_active(self) -> None:
        if self._state != State.ACTIVE or self._d is None:
            raise RuntimeError(f"session '{self.name}' is not active (state={self._state})")

    async def _u2_reconnect(self) -> None:
        """Reconnect u2 if the connection dropped."""
        import uiautomator2 as u2
        await asyncio.sleep(1)
        self._d = u2.connect(self._serial)
        self._d.settings["wait_timeout"] = 10.0
        self._d.settings["operation_delay"] = (0.1, 0.1)

    async def _u2_retry(self, fn, *args, **kwargs):
        """Call a u2 function with automatic reconnect on connection drop."""
        for attempt in range(3):
            try:
                return fn(*args, **kwargs)
            except (ConnectionError, OSError):
                if attempt == 2:
                    raise
                log.debug("u2 connection dropped, reconnecting (%d/3)...", attempt + 1)
                await self._u2_reconnect()

    # ── App lifecycle ──

    async def app_install(self, apk_path: str | list[str]) -> None:
        """Install APK(s). Handles split APKs automatically."""
        self._require_active()
        if isinstance(apk_path, list):
            cmd = ["adb", "-s", self._serial, "install-multiple", "-r"] + apk_path
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"install failed: {err.decode()}")
            log.info("installed split APK (%d parts) on '%s'", len(apk_path), self.name)
        else:
            self._d.app_install(apk_path)
            log.info("installed %s on '%s'", apk_path, self.name)

    async def app_start(self, package: str, activity: str | None = None) -> dict:
        """Launch an app. Returns screen_state after launch."""
        self._require_active()
        if activity:
            self._d.app_start(package, activity)
        else:
            self._d.app_start(package)
        await asyncio.sleep(1)
        return await self.screen_state()

    async def app_stop(self, package: str) -> None:
        self._require_active()
        self._d.app_stop(package)

    async def app_clear(self, package: str) -> None:
        self._require_active()
        self._d.app_clear(package)

    async def app_list(self) -> list[str]:
        self._require_active()
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", "pm", "list", "packages", "-3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        return [line.replace("package:", "").strip() for line in out.decode().splitlines() if line.strip()]

    # ── UI automation ──

    async def observe(self, *, interactive_only: bool = True) -> list[Element]:
        """Dump the screen and return indexed interactive elements."""
        self._require_active()
        for attempt in range(3):
            try:
                xml = self._d.dump_hierarchy()
                elements = parse_hierarchy(xml, interactive_only=interactive_only)
                current = self._d.app_current()
                self.context.record_screen(
                    activity=current.get("activity", ""),
                    package=current.get("package", ""),
                    elements=elements,
                )
                return elements
            except (ConnectionError, OSError):
                if attempt == 2:
                    raise
                log.debug("u2 connection dropped in observe, reconnecting...")
                await self._u2_reconnect()

    async def observe_formatted(self) -> str:
        elements = await self.observe()
        return format_elements(elements)

    async def tap(self, target: int | str | Element, **kwargs) -> dict:
        """Tap an element by index, text, resourceId, or Element object.

        After tapping, returns the new screen_state.
        """
        self._require_active()
        if isinstance(target, Element):
            x, y = target.center
            await self._u2_retry(self._d.click, x, y)
        elif isinstance(target, int):
            elements = await self.observe()
            if target < 0 or target >= len(elements):
                raise IndexError(f"element index {target} out of range (0..{len(elements)-1})")
            x, y = elements[target].center
            await self._u2_retry(self._d.click, x, y)
        elif isinstance(target, str):
            if target.startswith("id:"):
                await self._u2_retry(self._d(resourceId=target[3:]).click, **kwargs)
            else:
                await self._u2_retry(self._d(text=target).click, **kwargs)
        else:
            raise TypeError(f"unsupported target type: {type(target)}")

        await asyncio.sleep(0.5)
        self.context.record_action("tap", target=str(target))
        return await self.screen_state()

    async def type_text(self, text: str, *, clear: bool = False) -> None:
        """Type text into the currently focused element."""
        self._require_active()
        if clear:
            await self._u2_retry(self._d.clear_text)
        await self._u2_retry(self._d.send_keys, text)
        self.context.record_action("type", text=text, clear=clear)

    async def fill(self, target: int | str | Element, text: str) -> None:
        """Tap a field then type text into it."""
        await self.tap(target)
        await asyncio.sleep(0.3)
        await self.type_text(text, clear=True)

    async def press(self, key: str) -> None:
        """Press a key: back, home, enter, recent, volume_up, volume_down, etc."""
        self._require_active()
        await self._u2_retry(self._d.press, key)
        self.context.record_action("press", key=key)

    async def swipe(self, direction: str = "up", *, scale: float = 0.6) -> None:
        """Swipe in a direction: up, down, left, right."""
        self._require_active()
        await self._u2_retry(self._d.swipe_ext, direction, scale=scale)
        self.context.record_action("swipe", direction=direction)

    async def scroll_to(self, text: str, *, max_swipes: int = 10) -> Element | None:
        """Scroll down until element with text is found."""
        self._require_active()
        for _ in range(max_swipes):
            elements = await self.observe()
            for el in elements:
                if text.lower() in el.text.lower() or text.lower() in el.content_desc.lower():
                    return el
            await self.swipe("up")
            await asyncio.sleep(0.5)
        return None

    # ── Screen state ──

    async def screen_state(self) -> dict:
        """Get current screen state — the Android equivalent of page_state()."""
        self._require_active()
        for attempt in range(3):
            try:
                current = self._d.app_current()
                info = self._d.info
                return {
                    "activity": current.get("activity", ""),
                    "package": current.get("package", ""),
                    "screen_size": (info.get("displayWidth", 0), info.get("displayHeight", 0)),
                    "orientation": _orientation_name(info.get("displayRotation", 0)),
                    "keyboard_shown": info.get("screenOn", False) and self._keyboard_visible(),
                }
            except (ConnectionError, OSError):
                if attempt == 2:
                    raise
                log.debug("u2 connection dropped in screen_state, reconnecting...")
                await self._u2_reconnect()

    async def current_activity(self) -> str:
        self._require_active()
        return self._d.app_current().get("activity", "")

    async def current_package(self) -> str:
        self._require_active()
        return self._d.app_current().get("package", "")

    # ── Screenshots ──

    async def screenshot(self, path: str | None = None) -> bytes:
        """Take a screenshot. Returns PNG bytes. Optionally saves to path."""
        self._require_active()
        for attempt in range(3):
            try:
                img = self._d.screenshot()
                break
            except (ConnectionError, OSError):
                if attempt == 2:
                    raise
                log.debug("u2 connection dropped in screenshot, reconnecting...")
                await self._u2_reconnect()
        import io
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()
        if path:
            Path(path).write_bytes(png_bytes)
            log.info("screenshot saved to %s", path)
        return png_bytes

    # ── Shell ──

    async def shell(self, cmd: str) -> str:
        """Run a shell command on the device."""
        self._require_active()
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        return out.decode()

    async def push(self, local: str, remote: str) -> None:
        self._require_active()
        await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "push", local, remote,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )

    async def pull(self, remote: str, local: str) -> None:
        self._require_active()
        await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "pull", remote, local,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )

    # ── Waits ──

    async def wait_activity(self, activity: str, *, timeout: float = 10) -> bool:
        """Wait until a specific activity is in the foreground."""
        self._require_active()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self._d.app_current().get("activity", "")
            if activity in current:
                return True
            await asyncio.sleep(0.5)
        return False

    async def wait_element(self, *, text: str | None = None, resource_id: str | None = None,
                           timeout: float = 10) -> Element | None:
        """Wait for an element to appear on screen."""
        self._require_active()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            elements = await self.observe(interactive_only=False)
            for el in elements:
                if text and text.lower() in el.text.lower():
                    return el
                if resource_id and resource_id in el.resource_id:
                    return el
            await asyncio.sleep(0.5)
        return None

    async def wait_gone(self, *, text: str | None = None, timeout: float = 10) -> bool:
        """Wait for an element to disappear."""
        self._require_active()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            elements = await self.observe(interactive_only=False)
            found = False
            for el in elements:
                if text and text.lower() in el.text.lower():
                    found = True
                    break
            if not found:
                return True
            await asyncio.sleep(0.5)
        return False

    # ── Evidence capture ──

    async def capture_screenshot_evidence(self, description: str = "") -> str:
        """Take a screenshot and store it as evidence. Returns evidence ID."""
        png = await self.screenshot()
        item = self.evidence.capture_screenshot(png, description)
        return item.id

    async def capture_observe_evidence(self, description: str = "") -> str:
        """Capture current UI hierarchy as evidence. Returns evidence ID."""
        elements = await self.observe(interactive_only=False)
        text = format_elements(elements)
        item = self.evidence.capture_observe(text, description)
        return item.id

    async def observe_diff(self) -> ScreenDiff | None:
        """Run observe() and return what changed since the last observation."""
        await self.observe()
        if len(self.context._history) < 2:
            return None
        prev = self.context._history[-2]
        curr = self.context._history[-1]
        old_texts = prev.element_texts()
        new_texts = curr.element_texts()
        return ScreenDiff(
            timestamp=curr.timestamp,
            activity_changed=prev.activity != curr.activity,
            old_activity=prev.activity,
            new_activity=curr.activity,
            added_elements=[e for e in curr.elements if e.text and e.text not in old_texts],
            removed_texts=old_texts - new_texts,
            added_texts=new_texts - old_texts,
            element_count_delta=curr.element_count - prev.element_count,
        )

    # ── Frida instrumentation ──

    async def frida_attach(self, target: str | int) -> None:
        """Attach Frida to a running process."""
        self._require_active()
        from golem.frida_bridge import FridaBridge
        if not hasattr(self, "_frida") or self._frida is None:
            self._frida = FridaBridge(self._serial)
        await self._frida.ensure_server()
        await self._frida.attach(target)

    async def frida_spawn(self, package: str) -> int:
        """Spawn an app under Frida (paused for early hook)."""
        self._require_active()
        from golem.frida_bridge import FridaBridge
        if not hasattr(self, "_frida") or self._frida is None:
            self._frida = FridaBridge(self._serial)
        await self._frida.ensure_server()
        return await self._frida.spawn(package)

    def frida_resume(self, pid: int) -> None:
        """Resume a Frida-spawned process."""
        if hasattr(self, "_frida") and self._frida:
            self._frida.resume(pid)

    async def frida_load(self, *script_names: str):
        """Load Frida scripts by name (from scripts/ dir)."""
        if not hasattr(self, "_frida") or not self._frida or not self._frida.is_attached:
            raise RuntimeError("frida not attached — call frida_attach() first")
        return await self._frida.load_scripts(*script_names)

    async def frida_run(self, js: str):
        """Run a one-off Frida snippet."""
        if not hasattr(self, "_frida") or not self._frida or not self._frida.is_attached:
            raise RuntimeError("frida not attached — call frida_attach() first")
        return await self._frida.run_snippet(js)

    async def frida_messages(self, script: str | None = None) -> list[dict]:
        """Get Frida messages, optionally filtered by script name."""
        if not hasattr(self, "_frida") or not self._frida:
            return []
        return self._frida.get_messages(script)

    async def frida_detach(self) -> None:
        """Detach Frida from the current process."""
        if hasattr(self, "_frida") and self._frida:
            await self._frida.detach()

    @staticmethod
    def frida_scripts_available() -> list[str]:
        """List available Frida scripts."""
        from golem.frida_bridge import FridaBridge
        return FridaBridge.available_scripts()

    # ── Proxy / cert ──

    async def proxy_install_cert(self, cert_path: Path | None = None) -> None:
        """Install CA cert into the system trust store (requires root)."""
        self._require_active()
        from golem.proxy import install_ca_cert
        await install_ca_cert(self._serial, cert_path)

    async def proxy_configure(self, host: str = "10.0.2.2", port: int = 8082) -> None:
        """Set device HTTP proxy to point at mitmproxy."""
        self._require_active()
        from golem.proxy import configure_proxy
        await configure_proxy(self._serial, host, port)

    async def proxy_clear(self) -> None:
        """Remove proxy configuration from device."""
        self._require_active()
        from golem.proxy import clear_proxy
        await clear_proxy(self._serial)

    # ── Internals ──

    def _keyboard_visible(self) -> bool:
        try:
            result = subprocess.run(
                ["adb", "-s", self._serial, "shell", "dumpsys", "input_method"],
                capture_output=True, text=True, timeout=5,
            )
            return "mInputShown=true" in result.stdout
        except Exception:
            return False

    def _save_meta(self) -> None:
        meta = {
            "name": self.name,
            "state": self._state.value,
            "serial": self._serial,
            "backend": type(self.device).__name__,
        }
        meta_path = self._profile_dir / "golem_meta.json"
        self._profile_dir.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(meta, indent=2))

    @classmethod
    def from_profile_dir(cls, path: Path, device: Device) -> Session:
        meta_path = path / "golem_meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"no golem_meta.json in {path}")
        meta = json.loads(meta_path.read_text())
        session = cls(meta["name"], device, profile_dir=path)
        session._state = State(meta.get("state", "hibernated"))
        session._serial = meta.get("serial")
        return session


def _orientation_name(rotation: int) -> str:
    return {0: "natural", 1: "left", 2: "upsidedown", 3: "right"}.get(rotation, "unknown")
