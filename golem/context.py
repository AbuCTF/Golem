"""Context tracking — ring buffers, screen diffing, and health monitoring.

Maintains a rolling window of screen states, UI changes, and device health
so agents can understand what changed between observations.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from golem.observe import Element

log = logging.getLogger(__name__)


@dataclass
class ScreenSnapshot:
    timestamp: float
    activity: str
    package: str
    elements: list[Element]
    element_count: int
    orientation: str

    def element_texts(self) -> set[str]:
        return {e.text for e in self.elements if e.text}


@dataclass
class ScreenDiff:
    """What changed between two screen observations."""
    timestamp: float
    activity_changed: bool
    old_activity: str
    new_activity: str
    added_elements: list[Element]
    removed_texts: set[str]
    added_texts: set[str]
    element_count_delta: int

    def summary(self) -> str:
        parts = []
        if self.activity_changed:
            parts.append(f"activity: {self.old_activity} → {self.new_activity}")
        if self.added_texts:
            parts.append(f"+{len(self.added_texts)} elements: {', '.join(list(self.added_texts)[:5])}")
        if self.removed_texts:
            parts.append(f"-{len(self.removed_texts)} elements")
        if self.element_count_delta:
            parts.append(f"total: {self.element_count_delta:+d}")
        return "; ".join(parts) if parts else "no change"


class ContextTracker:
    """Tracks screen state history and computes diffs."""

    def __init__(self, *, max_history: int = 50):
        self._history: deque[ScreenSnapshot] = deque(maxlen=max_history)
        self._action_log: deque[dict] = deque(maxlen=200)

    def record_screen(self, activity: str, package: str,
                      elements: list[Element], orientation: str = "natural") -> ScreenDiff | None:
        """Record a screen state and return diff from previous."""
        snapshot = ScreenSnapshot(
            timestamp=time.time(),
            activity=activity,
            package=package,
            elements=list(elements),
            element_count=len(elements),
            orientation=orientation,
        )

        diff = None
        if self._history:
            prev = self._history[-1]
            old_texts = prev.element_texts()
            new_texts = snapshot.element_texts()

            diff = ScreenDiff(
                timestamp=snapshot.timestamp,
                activity_changed=prev.activity != snapshot.activity,
                old_activity=prev.activity,
                new_activity=snapshot.activity,
                added_elements=[e for e in elements if e.text and e.text not in old_texts],
                removed_texts=old_texts - new_texts,
                added_texts=new_texts - old_texts,
                element_count_delta=snapshot.element_count - prev.element_count,
            )

        self._history.append(snapshot)
        return diff

    def record_action(self, action: str, **details) -> None:
        """Log an action taken (tap, type, swipe, etc)."""
        self._action_log.append({
            "timestamp": time.time(),
            "action": action,
            **details,
        })

    @property
    def current(self) -> ScreenSnapshot | None:
        return self._history[-1] if self._history else None

    @property
    def previous(self) -> ScreenSnapshot | None:
        return self._history[-2] if len(self._history) >= 2 else None

    def last_n(self, n: int = 5) -> list[ScreenSnapshot]:
        return list(self._history)[-n:]

    def recent_actions(self, n: int = 10) -> list[dict]:
        return list(self._action_log)[-n:]

    def find_element_history(self, text: str) -> list[tuple[float, bool]]:
        """Track when an element with given text appeared/disappeared."""
        history = []
        prev_present = False
        for snap in self._history:
            present = any(text.lower() in e.text.lower() for e in snap.elements if e.text)
            if present != prev_present:
                history.append((snap.timestamp, present))
                prev_present = present
        return history


@dataclass
class HealthStatus:
    timestamp: float
    device_online: bool
    u2_responsive: bool
    battery_level: int | None
    cpu_usage: float | None
    memory_free_mb: int | None
    disk_free_mb: int | None
    screen_on: bool
    uptime_seconds: float | None


class HealthMonitor:
    """Monitors device health and reports anomalies."""

    def __init__(self, serial: str):
        self._serial = serial
        self._history: deque[HealthStatus] = deque(maxlen=100)
        self._task: asyncio.Task | None = None

    async def check(self) -> HealthStatus:
        """Run a health check on the device."""
        status = HealthStatus(
            timestamp=time.time(),
            device_online=False,
            u2_responsive=False,
            battery_level=None,
            cpu_usage=None,
            memory_free_mb=None,
            disk_free_mb=None,
            screen_on=False,
            uptime_seconds=None,
        )

        # Device online?
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "get-state",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        status.device_online = out.strip() == b"device"
        if not status.device_online:
            self._history.append(status)
            return status

        # Battery
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", "dumpsys", "battery",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        for line in out.decode().splitlines():
            if "level:" in line:
                try:
                    status.battery_level = int(line.split(":")[1].strip())
                except ValueError:
                    pass

        # Memory
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", "cat", "/proc/meminfo",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        for line in out.decode().splitlines():
            if line.startswith("MemAvailable:"):
                try:
                    status.memory_free_mb = int(line.split()[1]) // 1024
                except (ValueError, IndexError):
                    pass

        # Disk
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", "df", "/data",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        lines = out.decode().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 4:
                try:
                    status.disk_free_mb = int(parts[3]) // 1024
                except ValueError:
                    pass

        # Uptime
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell", "cat", "/proc/uptime",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        try:
            status.uptime_seconds = float(out.decode().split()[0])
        except (ValueError, IndexError):
            pass

        # Screen on
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "shell",
            "dumpsys", "display", "|", "grep", "mScreenState",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        status.screen_on = "ON" in out.decode()

        # u2 responsive
        try:
            import uiautomator2 as u2
            d = u2.connect(self._serial)
            d.info
            status.u2_responsive = True
        except Exception:
            status.u2_responsive = False

        self._history.append(status)
        return status

    async def start_periodic(self, interval: float = 30) -> None:
        """Start periodic health checks in the background."""
        async def _loop():
            while True:
                try:
                    await self.check()
                except Exception as e:
                    log.debug("health check error: %s", e)
                await asyncio.sleep(interval)

        self._task = asyncio.create_task(_loop())
        log.info("health monitor started (interval=%ds)", interval)

    async def stop_periodic(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None

    @property
    def latest(self) -> HealthStatus | None:
        return self._history[-1] if self._history else None

    @property
    def history(self) -> list[HealthStatus]:
        return list(self._history)
