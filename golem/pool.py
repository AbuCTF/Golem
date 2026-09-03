"""Pool — manages named sessions across devices.

Mirrors Hutch's Pool: discovers existing sessions from profile dirs, enforces
max-concurrent limit, provides parallel execution.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from golem import config
from golem.device import Device, create_device
from golem.session import Session, State

log = logging.getLogger(__name__)


class Pool:
    """Manages named Golem sessions."""

    def __init__(self, *, max_sessions: int = config.MAX_SESSIONS):
        self.max_sessions = max_sessions
        self._sessions: dict[str, Session] = {}
        config.ensure_dirs()

    async def __aenter__(self) -> Pool:
        self._discover_existing()
        return self

    async def __aexit__(self, *exc) -> None:
        for session in list(self._sessions.values()):
            if session and session.state == State.ACTIVE:
                await session.close()

    def _discover_existing(self) -> None:
        """Discover sessions from profile dirs on disk."""
        if not config.PROFILES_DIR.exists():
            return
        for d in config.PROFILES_DIR.iterdir():
            if not d.is_dir():
                continue
            meta_path = d / "golem_meta.json"
            if meta_path.exists():
                import json
                meta = json.loads(meta_path.read_text())
                name = meta.get("name", d.name)
                if name not in self._sessions:
                    log.debug("discovered session '%s' from %s", name, d)
                    self._sessions[name] = None  # placeholder, loaded on get()

    async def create(
        self,
        name: str,
        *,
        device_spec: str = "avd",
        headless: bool = True,
        launch: bool = True,
        **device_kwargs,
    ) -> Session:
        """Create a new session, optionally launching it immediately."""
        if name in self._sessions and self._sessions[name] is not None:
            existing = self._sessions[name]
            if existing.state == State.ACTIVE:
                raise ValueError(f"session '{name}' already exists and is active")

        active = sum(1 for s in self._sessions.values() if s and s.state == State.ACTIVE)
        if active >= self.max_sessions:
            raise RuntimeError(f"max sessions ({self.max_sessions}) reached — close one first")

        device = create_device(name, device_spec, headless=headless, **device_kwargs)
        session = Session(name, device)
        self._sessions[name] = session

        if launch:
            await session.launch()
        return session

    async def get(self, name: str, *, launch: bool = False) -> Session:
        """Get a session by name. Optionally relaunch if hibernated."""
        session = self._sessions.get(name)
        if session is None:
            profile = config.PROFILES_DIR / name
            if not profile.exists():
                raise KeyError(f"session '{name}' not found")
            import json
            meta = json.loads((profile / "golem_meta.json").read_text())
            device = create_device(name, meta.get("device_spec", "avd"))
            session = Session.from_profile_dir(profile, device)
            self._sessions[name] = session

        if launch and session.state != State.ACTIVE:
            await session.launch()
        return session

    def list(self) -> list[dict]:
        """List all known sessions."""
        result = []
        for name, session in self._sessions.items():
            if session:
                result.append({
                    "name": name,
                    "state": session.state.value,
                    "profile_dir": str(session.profile_dir),
                })
            else:
                result.append({
                    "name": name,
                    "state": "discovered",
                    "profile_dir": str(config.PROFILES_DIR / name),
                })
        return result

    async def close(self, name: str) -> None:
        session = await self.get(name)
        await session.close()

    async def destroy(self, name: str) -> None:
        try:
            session = await self.get(name)
            await session.destroy()
        except (KeyError, FileNotFoundError):
            # Profile already gone — kill orphan emulator if any
            from golem.device import AVDDevice
            dev = AVDDevice(name, headless=True)
            await dev.shutdown()
            profile = config.PROFILES_DIR / name
            if profile.exists():
                import shutil
                shutil.rmtree(profile)
            log.info("session '%s' destroyed (orphan cleanup)", name)
        self._sessions.pop(name, None)

    async def parallel(self, names: list[str], action) -> list:
        """Run an async action across multiple sessions in parallel."""
        sessions = [await self.get(n, launch=True) for n in names]
        return await asyncio.gather(*(action(s) for s in sessions))
