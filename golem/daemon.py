"""Daemon — persistent JSON-RPC server over Unix socket.

Mirrors Hutch's daemon pattern: long-running process that owns the Pool,
accepts JSON-RPC calls over ~/.golem/golem.sock.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from pathlib import Path

from golem import config
from golem.pool import Pool
from golem.session import Session

log = logging.getLogger(__name__)


class Daemon:
    """Golem daemon — persistent process managing sessions via JSON-RPC."""

    def __init__(self):
        self._pool: Pool | None = None
        self._server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        config.ensure_dirs()
        self._pool = Pool()
        await self._pool.__aenter__()

        sock_path = str(config.SOCK_PATH)
        if os.path.exists(sock_path):
            os.unlink(sock_path)

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=sock_path,
        )
        os.chmod(sock_path, 0o600)

        pid_file = config.PID_FILE
        pid_file.write_text(str(os.getpid()))

        self._running = True
        log.info("daemon started on %s (pid=%d)", sock_path, os.getpid())

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.ensure_future(self.stop()))

        await self._server.serve_forever()

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._server:
            self._server.close()
        if self._pool:
            await self._pool.__aexit__(None, None, None)
        if config.PID_FILE.exists():
            config.PID_FILE.unlink()
        if config.SOCK_PATH.exists():
            config.SOCK_PATH.unlink()
        log.info("daemon stopped")

    async def _handle_client(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode())
                except json.JSONDecodeError:
                    writer.write(json.dumps({
                        "error": {"code": -32700, "message": "parse error"},
                    }).encode() + b"\n")
                    await writer.drain()
                    continue

                response = await self._dispatch(request)
                writer.write(json.dumps(response).encode() + b"\n")
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def _dispatch(self, request: dict) -> dict:
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        try:
            handler = getattr(self, f"_rpc_{method.replace('.', '_')}", None)
            if not handler:
                return {"id": req_id, "error": {"code": -32601, "message": f"unknown method: {method}"}}
            result = await handler(params)
            return {"id": req_id, "result": result}
        except Exception as e:
            log.exception("RPC error in %s", method)
            return {"id": req_id, "error": {"code": -32000, "message": str(e)}}

    # ── RPC methods ──

    async def _rpc_session_create(self, params: dict) -> dict:
        name = params["name"]
        device_spec = params.get("device_spec", "avd")
        headless = params.get("headless", True)
        session = await self._pool.create(name, device_spec=device_spec, headless=headless)
        info = await session.device.info()
        return {"name": name, "serial": info.serial, "state": session.state.value}

    async def _rpc_session_list(self, params: dict) -> list:
        return self._pool.list()

    async def _rpc_session_status(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        info = await session.device.info()
        return {
            "name": session.name, "state": session.state.value,
            "serial": info.serial, "model": info.model,
            "api": info.api_level, "backend": info.backend,
        }

    async def _rpc_session_close(self, params: dict) -> dict:
        await self._pool.close(params["name"])
        return {"status": "hibernated"}

    async def _rpc_session_destroy(self, params: dict) -> dict:
        await self._pool.destroy(params["name"])
        return {"status": "destroyed"}

    async def _rpc_observe(self, params: dict) -> list:
        session = await self._pool.get(params["name"], launch=True)
        interactive_only = params.get("interactive_only", True)
        elements = await session.observe(interactive_only=interactive_only)
        return [{"idx": e.idx, "cls": e.cls, "text": e.text,
                 "resource_id": e.resource_id, "content_desc": e.content_desc,
                 "bounds": list(e.bounds), "clickable": e.clickable,
                 "scrollable": e.scrollable, "editable": e.editable,
                 "short": e.short} for e in elements]

    async def _rpc_tap(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        target = params["target"]
        if isinstance(target, str):
            try:
                target = int(target)
            except ValueError:
                pass
        state = await session.tap(target)
        return state

    async def _rpc_type_text(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.type_text(params["text"], clear=params.get("clear", False))
        return {"status": "typed"}

    async def _rpc_fill(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        target = params["target"]
        try:
            target = int(target)
        except (ValueError, TypeError):
            pass
        await session.fill(target, params["text"])
        return {"status": "filled"}

    async def _rpc_press(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.press(params["key"])
        return {"status": "pressed"}

    async def _rpc_swipe(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.swipe(params.get("direction", "up"))
        return {"status": "swiped"}

    async def _rpc_screenshot(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        import base64
        png = await session.screenshot()
        path = params.get("path")
        if path:
            Path(path).write_bytes(png)
        return {"size": len(png), "base64": base64.b64encode(png).decode(),
                "path": path}

    async def _rpc_screen_state(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        return await session.screen_state()

    async def _rpc_shell(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        out = await session.shell(params["cmd"])
        return {"output": out}

    async def _rpc_app_install(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.app_install(params["apk"])
        return {"status": "installed"}

    async def _rpc_app_start(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        state = await session.app_start(params["package"])
        return state

    async def _rpc_app_stop(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.app_stop(params["package"])
        return {"status": "stopped"}

    async def _rpc_app_list(self, params: dict) -> list:
        session = await self._pool.get(params["name"], launch=True)
        return await session.app_list()

    async def _rpc_frida_attach(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.frida_attach(params["target"])
        return {"status": "attached"}

    async def _rpc_frida_load(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        scripts = params["scripts"]
        if isinstance(scripts, str):
            scripts = [scripts]
        await session.frida_load(*scripts)
        return {"loaded": scripts}

    async def _rpc_frida_messages(self, params: dict) -> list:
        session = await self._pool.get(params["name"], launch=True)
        return await session.frida_messages(params.get("script"))

    async def _rpc_frida_detach(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.frida_detach()
        return {"status": "detached"}

    async def _rpc_frida_scripts(self, params: dict) -> list:
        return Session.frida_scripts_available()

    async def _rpc_health_check(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        return await session.health_check()

    async def _rpc_observe_diff(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        diff = await session.observe_diff()
        if diff is None:
            return {"diff": None}
        return {
            "activity_changed": diff.activity_changed,
            "old_activity": diff.old_activity,
            "new_activity": diff.new_activity,
            "added_texts": list(diff.added_texts),
            "removed_texts": list(diff.removed_texts),
            "element_count_delta": diff.element_count_delta,
            "summary": diff.summary(),
        }

    async def _rpc_evidence_list(self, params: dict) -> list:
        session = await self._pool.get(params["name"], launch=True)
        items = session.evidence.list(type_filter=params.get("type"))
        return [i.to_dict() for i in items]

    async def _rpc_evidence_capture_screenshot(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        eid = await session.capture_screenshot_evidence(params.get("description", ""))
        return {"evidence_id": eid}

    async def _rpc_evidence_capture_observe(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        eid = await session.capture_observe_evidence(params.get("description", ""))
        return {"evidence_id": eid}

    async def _rpc_context_recent(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        actions = session.context.recent_actions(params.get("n", 10))
        current = session.context.current
        return {
            "recent_actions": actions,
            "current_activity": current.activity if current else None,
            "current_package": current.package if current else None,
            "screen_history_depth": len(session.context._history),
        }

    async def _rpc_proxy_install_cert(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.proxy_install_cert()
        return {"status": "installed"}

    async def _rpc_proxy_configure(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.proxy_configure(port=params.get("port", 8082))
        return {"status": "configured"}

    async def _rpc_proxy_clear(self, params: dict) -> dict:
        session = await self._pool.get(params["name"], launch=True)
        await session.proxy_clear()
        return {"status": "cleared"}


async def run_daemon():
    d = Daemon()
    await d.start()
