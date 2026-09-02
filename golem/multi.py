"""Multi-session parallel execution.

Run the same action across multiple sessions concurrently, or run different
actions in parallel on different sessions. Used by the BBP harness for
cross-account IDOR testing and parallel app instrumentation.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from golem.pool import Pool
from golem.session import Session

log = logging.getLogger(__name__)


@dataclass
class ParallelResult:
    session: str
    success: bool
    result: Any = None
    error: str | None = None


async def parallel_observe(pool: Pool, session_names: list[str]) -> list[ParallelResult]:
    """Observe all sessions in parallel and return results."""
    from golem.observe import format_elements

    async def _observe(name: str) -> ParallelResult:
        try:
            session = await pool.get(name, launch=True)
            elements = await session.observe()
            return ParallelResult(session=name, success=True, result=format_elements(elements))
        except Exception as e:
            return ParallelResult(session=name, success=False, error=str(e))

    return await asyncio.gather(*[_observe(n) for n in session_names])


async def parallel_screenshot(pool: Pool, session_names: list[str]) -> list[ParallelResult]:
    """Screenshot all sessions in parallel."""
    async def _screenshot(name: str) -> ParallelResult:
        try:
            session = await pool.get(name, launch=True)
            png = await session.screenshot()
            return ParallelResult(session=name, success=True, result=len(png))
        except Exception as e:
            return ParallelResult(session=name, success=False, error=str(e))

    return await asyncio.gather(*[_screenshot(n) for n in session_names])


async def parallel_action(pool: Pool, session_names: list[str],
                          action: Callable[[Session], Awaitable[Any]]) -> list[ParallelResult]:
    """Run an arbitrary async action on each session in parallel."""
    async def _run(name: str) -> ParallelResult:
        try:
            session = await pool.get(name, launch=True)
            result = await action(session)
            return ParallelResult(session=name, success=True, result=result)
        except Exception as e:
            return ParallelResult(session=name, success=False, error=str(e))

    return await asyncio.gather(*[_run(n) for n in session_names])


async def cross_account_test(pool: Pool, sessions: list[str],
                             setup_action: Callable[[Session, int], Awaitable[Any]],
                             verify_action: Callable[[Session, int, Any], Awaitable[bool]]) -> list[dict]:
    """Run a cross-account IDOR test across sessions.

    setup_action(session, index) runs on each session to create a resource.
    verify_action(session, index, other_result) checks if session can access
    another session's resource. Returns a matrix of results.
    """
    setup_results = []
    for i, name in enumerate(sessions):
        session = await pool.get(name, launch=True)
        result = await setup_action(session, i)
        setup_results.append(result)

    findings = []
    for i, attacker_name in enumerate(sessions):
        attacker = await pool.get(attacker_name, launch=True)
        for j, victim_name in enumerate(sessions):
            if i == j:
                continue
            accessible = await verify_action(attacker, j, setup_results[j])
            findings.append({
                "attacker": attacker_name,
                "victim": victim_name,
                "accessible": accessible,
                "victim_resource": setup_results[j],
            })

    return findings


class SessionGroup:
    """Manages a named group of sessions for coordinated testing."""

    def __init__(self, pool: Pool, name: str):
        self.pool = pool
        self.name = name
        self._sessions: list[str] = []

    async def add(self, session_name: str, *, device_spec: str = "avd",
                  headless: bool = True) -> Session:
        session = await self.pool.create(session_name, device_spec=device_spec, headless=headless)
        self._sessions.append(session_name)
        return session

    async def add_existing(self, session_name: str) -> Session:
        session = await self.pool.get(session_name, launch=True)
        self._sessions.append(session_name)
        return session

    @property
    def session_names(self) -> list[str]:
        return list(self._sessions)

    async def observe_all(self) -> list[ParallelResult]:
        return await parallel_observe(self.pool, self._sessions)

    async def screenshot_all(self) -> list[ParallelResult]:
        return await parallel_screenshot(self.pool, self._sessions)

    async def run_all(self, action: Callable[[Session], Awaitable[Any]]) -> list[ParallelResult]:
        return await parallel_action(self.pool, self._sessions, action)

    async def install_all(self, apk_path: str) -> list[ParallelResult]:
        return await parallel_action(
            self.pool, self._sessions,
            lambda s: s.app_install(apk_path),
        )

    async def launch_all(self, package: str) -> list[ParallelResult]:
        return await parallel_action(
            self.pool, self._sessions,
            lambda s: s.app_start(package),
        )

    async def close_all(self) -> None:
        for name in self._sessions:
            try:
                await self.pool.close(name)
            except Exception as e:
                log.warning("failed to close session %s: %s", name, e)

    async def destroy_all(self) -> None:
        for name in self._sessions:
            try:
                await self.pool.destroy(name)
            except Exception as e:
                log.warning("failed to destroy session %s: %s", name, e)
        self._sessions.clear()
