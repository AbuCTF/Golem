"""Golem configuration — paths, defaults, environment."""

from __future__ import annotations

import os
from pathlib import Path

GOLEM_HOME = Path(os.environ.get("GOLEM_HOME", Path.home() / ".golem"))
PROFILES_DIR = GOLEM_HOME / "profiles"
ARTIFACTS_DIR = GOLEM_HOME / "artifacts"
SOCK_PATH = GOLEM_HOME / "golem.sock"
PID_FILE = GOLEM_HOME / "golem.pid"

ANDROID_HOME = Path(os.environ.get("ANDROID_HOME", Path.home() / "Android" / "Sdk"))
EMULATOR_BIN = ANDROID_HOME / "emulator" / "emulator"
SDKMANAGER_BIN = ANDROID_HOME / "cmdline-tools" / "latest" / "bin" / "sdkmanager"
AVDMANAGER_BIN = ANDROID_HOME / "cmdline-tools" / "latest" / "bin" / "avdmanager"

DEFAULT_API_LEVEL = 34
DEFAULT_IMAGE = f"system-images;android-{DEFAULT_API_LEVEL};google_apis;x86_64"
DEFAULT_DEVICE = "pixel_7"

FRIDA_SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"

MAX_SESSIONS = 4
ADB_CONNECT_TIMEOUT = 30
EMULATOR_BOOT_TIMEOUT = 300

def ensure_dirs():
    for d in (GOLEM_HOME, PROFILES_DIR, ARTIFACTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
