"""Device abstraction — AVD, Waydroid, or physical device behind a common interface.

Each backend manages lifecycle (boot, shutdown, snapshot) and exposes an ADB serial
that Session uses for all interaction (uiautomator2, Frida, etc).
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from golem import config

log = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    serial: str
    name: str
    backend: str
    api_level: int | None = None
    model: str | None = None
    arch: str | None = None
    rooted: bool = False
    state: str = "offline"


class Device(ABC):
    """Common interface for all Android device backends."""

    @abstractmethod
    async def boot(self) -> str:
        """Boot the device, return ADB serial."""

    @abstractmethod
    async def shutdown(self) -> None:
        """Shut down the device."""

    @abstractmethod
    async def is_running(self) -> bool:
        """Check if the device is currently running."""

    @abstractmethod
    def serial(self) -> str:
        """ADB serial for this device."""

    @abstractmethod
    async def info(self) -> DeviceInfo:
        """Get device information."""

    async def wait_boot(self, timeout: int = config.EMULATOR_BOOT_TIMEOUT) -> None:
        """Wait until device finishes booting (sys.boot_completed=1)."""
        serial = self.serial()
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell", "getprop", "sys.boot_completed",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                )
                out, _ = await proc.communicate()
                if out.strip() == b"1":
                    log.info("device %s boot complete", serial)
                    return
            except Exception:
                pass
            await asyncio.sleep(2)
        raise TimeoutError(f"device {serial} did not boot within {timeout}s")


class AVDDevice(Device):
    """Android Virtual Device (emulator) backend.

    Creates and manages AVD instances via sdkmanager/avdmanager/emulator.
    This is Golem's primary backend — proven Frida compat, all API levels, snapshots.
    """

    def __init__(
        self,
        name: str,
        *,
        api_level: int = config.DEFAULT_API_LEVEL,
        device_profile: str = config.DEFAULT_DEVICE,
        headless: bool = True,
        gpu: str = "auto",
        ram_mb: int = 2048,
        extra_args: list[str] | None = None,
    ):
        self.name = name
        self.api_level = api_level
        self.device_profile = device_profile
        self.headless = headless
        self.gpu = gpu
        self.ram_mb = ram_mb
        self.extra_args = extra_args or []
        self._process: asyncio.subprocess.Process | None = None
        self._serial: str | None = None
        self._avd_name = f"golem_{name}"

    def serial(self) -> str:
        if not self._serial:
            raise RuntimeError(f"AVD {self.name} not booted yet")
        return self._serial

    async def boot(self) -> str:
        if await self.is_running():
            log.info("AVD %s already running on %s", self._avd_name, self._serial)
            return self._serial

        await self._ensure_avd_exists()

        gpu = self.gpu
        if gpu == "auto" and self.headless:
            gpu = "swiftshader_indirect"
        cmd = [
            str(config.EMULATOR_BIN),
            "-avd", self._avd_name,
            "-gpu", gpu,
            "-memory", str(self.ram_mb),
        ]
        if self.headless:
            cmd.extend(["-no-window", "-no-audio"])
        cmd.extend(["-writable-system"])
        cmd.extend(self.extra_args)

        log.info("booting AVD %s: %s", self._avd_name, " ".join(cmd))
        self._process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._sdk_env(),
        )

        self._serial = await self._find_serial()
        await self.wait_boot()
        return self._serial

    async def shutdown(self) -> None:
        if self._serial:
            try:
                await asyncio.create_subprocess_exec(
                    "adb", "-s", self._serial, "emu", "kill",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            except Exception:
                pass
        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=10)
            except Exception:
                self._process.kill()
            self._process = None
        self._serial = None
        log.info("AVD %s shut down", self._avd_name)

    async def is_running(self) -> bool:
        if not self._serial:
            self._serial = await self._find_existing_serial()
            if not self._serial:
                return False
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial, "get-state",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        return out.strip() == b"device"

    async def info(self) -> DeviceInfo:
        running = await self.is_running()
        model = None
        if running:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", self._serial, "shell", "getprop", "ro.product.model",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc.communicate()
            model = out.decode().strip() or None
        return DeviceInfo(
            serial=self._serial or "not-booted",
            name=self.name,
            backend="avd",
            api_level=self.api_level,
            model=model,
            arch="x86_64",
            rooted=True,
            state="online" if running else "offline",
        )

    async def snapshot_save(self, snap_name: str = "default") -> None:
        await asyncio.create_subprocess_exec(
            "adb", "-s", self.serial(), "emu", "avd", "snapshot", "save", snap_name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        log.info("snapshot '%s' saved for %s", snap_name, self._avd_name)

    async def snapshot_load(self, snap_name: str = "default") -> None:
        await asyncio.create_subprocess_exec(
            "adb", "-s", self.serial(), "emu", "avd", "snapshot", "load", snap_name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        log.info("snapshot '%s' loaded for %s", snap_name, self._avd_name)

    async def _ensure_avd_exists(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            str(config.AVDMANAGER_BIN), "list", "avd", "-c",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            env=self._sdk_env(),
        )
        out, _ = await proc.communicate()
        existing = out.decode().strip().splitlines()
        if self._avd_name in existing:
            log.info("AVD %s already exists", self._avd_name)
            return

        image = f"system-images;android-{self.api_level};google_apis;x86_64"
        log.info("creating AVD %s (device=%s, image=%s)", self._avd_name, self.device_profile, image)
        proc = await asyncio.create_subprocess_exec(
            str(config.AVDMANAGER_BIN), "create", "avd",
            "--name", self._avd_name,
            "--device", self.device_profile,
            "--package", image,
            "--force",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._sdk_env(),
        )
        # Answer "no" to custom hardware profile question
        out, err = await proc.communicate(input=b"no\n")
        if proc.returncode != 0:
            raise RuntimeError(f"failed to create AVD: {err.decode()}")
        log.info("AVD %s created", self._avd_name)

    async def _find_serial(self, timeout: int = 90) -> str:
        """Wait for our new emulator to appear in adb devices."""
        deadline = asyncio.get_event_loop().time() + timeout
        known_before = await self._list_emulator_serials()
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(2)
            if self._process and self._process.returncode is not None:
                stderr = b""
                try:
                    stderr = await self._process.stderr.read()
                except Exception:
                    pass
                raise RuntimeError(
                    f"emulator exited with code {self._process.returncode}: {stderr.decode(errors='replace')[:500]}"
                )
            current = await self._list_emulator_serials()
            new = current - known_before
            if new:
                serial = sorted(new)[0]
                log.info("AVD %s connected as %s", self._avd_name, serial)
                return serial
        raise TimeoutError(f"AVD {self._avd_name} did not appear in adb devices within {timeout}s")

    async def _find_existing_serial(self) -> str | None:
        """Try to find a running emulator matching this AVD name."""
        for serial in await self._list_emulator_serials():
            for prop in ("ro.boot.qemu.avd_name", "ro.kernel.qemu.avd_name"):
                proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "shell", "getprop", prop,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                )
                out, _ = await proc.communicate()
                if out.decode().strip() == self._avd_name:
                    return serial
        return None

    @staticmethod
    async def _list_emulator_serials() -> set[str]:
        proc = await asyncio.create_subprocess_exec(
            "adb", "devices",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        serials = set()
        for line in out.decode().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("emulator-"):
                serials.add(parts[0])
        return serials

    def _sdk_env(self) -> dict[str, str]:
        import os
        env = os.environ.copy()
        env["ANDROID_HOME"] = str(config.ANDROID_HOME)
        env["ANDROID_SDK_ROOT"] = str(config.ANDROID_HOME)
        avd_home = os.environ.get("ANDROID_AVD_HOME")
        if not avd_home:
            xdg = os.environ.get("XDG_CONFIG_HOME")
            if xdg:
                avd_home = os.path.join(xdg, ".android", "avd")
            else:
                avd_home = os.path.join(os.path.expanduser("~"), ".android", "avd")
        env["ANDROID_AVD_HOME"] = avd_home
        return env


class PhysicalDevice(Device):
    """Physical Android device connected via USB or network ADB."""

    def __init__(self, name: str, serial: str):
        self.name = name
        self._serial_str = serial

    def serial(self) -> str:
        return self._serial_str

    async def boot(self) -> str:
        if ":" in self._serial_str:
            proc = await asyncio.create_subprocess_exec(
                "adb", "connect", self._serial_str,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            if b"connected" not in out.lower() and b"already" not in out.lower():
                raise RuntimeError(f"failed to connect to {self._serial_str}: {out.decode()}")
        return self._serial_str

    async def shutdown(self) -> None:
        if ":" in self._serial_str:
            await asyncio.create_subprocess_exec(
                "adb", "disconnect", self._serial_str,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )

    async def is_running(self) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", self._serial_str, "get-state",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        return out.strip() == b"device"

    async def info(self) -> DeviceInfo:
        running = await self.is_running()
        model = api = None
        if running:
            for prop, target in [("ro.product.model", "model"), ("ro.build.version.sdk", "api")]:
                proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", self._serial_str, "shell", "getprop", prop,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                )
                out, _ = await proc.communicate()
                val = out.decode().strip()
                if target == "model":
                    model = val
                elif target == "api":
                    try:
                        api = int(val)
                    except ValueError:
                        pass
        return DeviceInfo(
            serial=self._serial_str,
            name=self.name,
            backend="physical",
            api_level=api,
            model=model,
            arch="arm64",
            rooted=False,
            state="online" if running else "offline",
        )


def create_device(name: str, spec: str, **kwargs) -> Device:
    """Create a device from a spec string.

    Formats:
        "avd"               → AVD with defaults (Pixel 7, API 34)
        "avd:pixel_8"       → AVD with specific device profile
        "avd:pixel_7:33"    → AVD with device profile and API level
        "physical:SERIAL"   → physical device by ADB serial
        "usb"               → first USB-connected device
    """
    parts = spec.split(":")
    backend = parts[0]

    if backend == "avd":
        device_profile = parts[1] if len(parts) > 1 else config.DEFAULT_DEVICE
        api = int(parts[2]) if len(parts) > 2 else config.DEFAULT_API_LEVEL
        return AVDDevice(name, device_profile=device_profile, api_level=api, **kwargs)
    elif backend == "physical":
        if len(parts) < 2:
            raise ValueError("physical device requires serial: 'physical:SERIAL'")
        return PhysicalDevice(name, serial=parts[1])
    elif backend == "usb":
        return PhysicalDevice(name, serial=_find_usb_device())
    else:
        raise ValueError(f"unknown device backend: {backend}")


def _find_usb_device() -> str:
    result = subprocess.run(
        ["adb", "devices"], capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device" and not parts[0].startswith("emulator-"):
            return parts[0]
    raise RuntimeError("no USB device found — connect a device or use 'avd' backend")
