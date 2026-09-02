"""BBP harness integration bridge.

Provides the interface for the BBP orchestrator to drive Golem sessions
as part of automated bug-bounty hunts. All target-facing traffic MUST
route through the BBP scope gate / run_hunt_tool — this bridge is the
local device-control layer only.

Usage from the BBP harness:
    from golem.bbp_bridge import GolemHuntSession

    async with GolemHuntSession("hunt-opensea-001") as hunt:
        await hunt.setup("com.opensea.app", apk_path="opensea.apk")
        await hunt.instrument(["ssl_bypass", "crypto_monitor", "intent_intercept"])
        elements = await hunt.observe()
        await hunt.tap("Sign in")
        evidence_id = await hunt.capture("login screen reached")
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from golem.pool import Pool
from golem.session import Session
from golem.evidence import EvidenceStore

log = logging.getLogger(__name__)


@dataclass
class HuntFinding:
    """A potential finding discovered during a hunt session."""
    title: str
    category: str
    severity: str
    description: str
    evidence_ids: list[str] = field(default_factory=list)
    frida_data: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "evidence_ids": self.evidence_ids,
            "frida_data": self.frida_data,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


class GolemHuntSession:
    """Wraps a Golem session for BBP hunt workflows."""

    def __init__(self, hunt_id: str, *, device_spec: str = "avd",
                 headless: bool = True, persona_seed: str | None = None):
        self.hunt_id = hunt_id
        self._device_spec = device_spec
        self._headless = headless
        self._persona_seed = persona_seed
        self._pool: Pool | None = None
        self._session: Session | None = None
        self._findings: list[HuntFinding] = []
        self._package: str | None = None

    async def __aenter__(self) -> GolemHuntSession:
        self._pool = Pool()
        await self._pool.__aenter__()
        self._session = await self._pool.create(
            self.hunt_id, device_spec=self._device_spec, headless=self._headless,
        )
        if self._persona_seed:
            from golem.persona import generate_persona
            persona = generate_persona(self._persona_seed)
            persona.save(self._session.profile_dir / "persona.json")
        return self

    async def __aexit__(self, *exc) -> None:
        if self._pool:
            await self._pool.__aexit__(*exc)

    @property
    def session(self) -> Session:
        if self._session is None:
            raise RuntimeError("hunt session not started — use 'async with'")
        return self._session

    @property
    def evidence(self) -> EvidenceStore:
        return self.session.evidence

    async def setup(self, package: str, *, apk_path: str | list[str] | None = None) -> dict:
        """Install and launch the target app."""
        self._package = package
        if apk_path:
            await self.session.app_install(apk_path)
        state = await self.session.app_start(package)
        log.info("hunt %s: launched %s", self.hunt_id, package)
        return state

    async def instrument(self, scripts: list[str], *, spawn: bool = False) -> None:
        """Attach Frida and load instrumentation scripts."""
        if not self._package:
            raise RuntimeError("call setup() first")
        if spawn:
            pid = await self.session.frida_spawn(self._package)
            await self.session.frida_load(*scripts)
            self.session.frida_resume(pid)
        else:
            await self.session.frida_attach(self._package)
            await self.session.frida_load(*scripts)
        log.info("hunt %s: instrumented with %s", self.hunt_id, scripts)

    async def observe(self) -> list:
        return await self.session.observe()

    async def tap(self, target) -> dict:
        return await self.session.tap(target)

    async def type_text(self, text: str, *, clear: bool = False) -> None:
        await self.session.type_text(text, clear=clear)

    async def fill(self, target, text: str) -> None:
        await self.session.fill(target, text)

    async def press(self, key: str) -> None:
        await self.session.press(key)

    async def swipe(self, direction: str = "up") -> None:
        await self.session.swipe(direction)

    async def shell(self, cmd: str) -> str:
        return await self.session.shell(cmd)

    async def screenshot(self, path: str | None = None) -> bytes:
        return await self.session.screenshot(path)

    async def capture(self, description: str = "") -> str:
        """Capture screenshot evidence. Returns evidence ID."""
        return await self.session.capture_screenshot_evidence(description)

    async def capture_observe(self, description: str = "") -> str:
        """Capture UI hierarchy evidence. Returns evidence ID."""
        return await self.session.capture_observe_evidence(description)

    async def frida_messages(self, script: str | None = None) -> list[dict]:
        return await self.session.frida_messages(script)

    async def health_check(self) -> dict:
        return await self.session.health_check()

    async def diff(self):
        return await self.session.observe_diff()

    def add_finding(self, title: str, category: str, severity: str,
                    description: str, evidence_ids: list[str] | None = None,
                    **metadata) -> HuntFinding:
        """Record a potential finding for later validation."""
        finding = HuntFinding(
            title=title,
            category=category,
            severity=severity,
            description=description,
            evidence_ids=evidence_ids or [],
            metadata=metadata,
        )
        self._findings.append(finding)
        log.info("hunt %s: finding recorded — %s [%s]", self.hunt_id, title, severity)
        return finding

    @property
    def findings(self) -> list[HuntFinding]:
        return list(self._findings)

    def findings_summary(self) -> str:
        if not self._findings:
            return "no findings"
        lines = []
        for i, f in enumerate(self._findings):
            lines.append(f"  [{i}] [{f.severity}] {f.title} ({f.category}) — {len(f.evidence_ids)} evidence items")
        return "\n".join(lines)

    async def cleanup(self) -> None:
        """Stop instrumentation and app. Evidence is preserved."""
        await self.session.frida_detach()
        if self._package:
            await self.session.app_stop(self._package)
