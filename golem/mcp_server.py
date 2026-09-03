"""MCP server — exposes Golem tools to Claude/agents via Model Context Protocol.

Tools: golem_observe, golem_tap, golem_type, golem_press, golem_swipe,
golem_screenshot, golem_screen_state, golem_shell, golem_install, golem_launch,
golem_frida_load, golem_frida_messages, golem_sessions.

Connects to the daemon's Unix socket or manages its own Pool inline.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def create_mcp_server():
    """Create an MCP server with Golem tools."""
    from mcp.server import Server
    from mcp.types import Tool, TextContent, ImageContent

    server = Server("golem")
    _pool = None

    async def _get_pool():
        nonlocal _pool
        if _pool is None:
            from golem.pool import Pool
            _pool = Pool()
            await _pool.__aenter__()
        return _pool

    async def _get_session(name: str):
        pool = await _get_pool()
        return await pool.get(name, launch=True)

    @server.list_tools()
    async def list_tools():
        return [
            Tool(
                name="golem_sessions",
                description="List active Golem Android sessions",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="golem_observe",
                description="Dump interactive UI elements on the Android screen. Returns indexed list for tap/fill targets.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string", "description": "Session name"},
                        "all": {"type": "boolean", "description": "Include non-interactive elements", "default": False},
                    },
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_tap",
                description="Tap a UI element by index (from observe), text label, or resource ID (prefix with id:). Returns new screen state.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "target": {"description": "Element index (int), text string, or 'id:resource_id'"},
                    },
                    "required": ["session", "target"],
                },
            ),
            Tool(
                name="golem_type",
                description="Type text into the currently focused element.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "text": {"type": "string"},
                        "clear": {"type": "boolean", "default": False},
                    },
                    "required": ["session", "text"],
                },
            ),
            Tool(
                name="golem_fill",
                description="Tap a field then type text into it.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "target": {"description": "Element index or text"},
                        "text": {"type": "string"},
                    },
                    "required": ["session", "target", "text"],
                },
            ),
            Tool(
                name="golem_press",
                description="Press a key: back, home, enter, recent, volume_up, volume_down.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "key": {"type": "string"},
                    },
                    "required": ["session", "key"],
                },
            ),
            Tool(
                name="golem_swipe",
                description="Swipe in a direction on the screen.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "direction": {"type": "string", "enum": ["up", "down", "left", "right"], "default": "up"},
                    },
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_screenshot",
                description="Take a screenshot of the Android screen. Returns the image.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "path": {"type": "string", "description": "Optional save path"},
                    },
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_screen_state",
                description="Get current screen state: activity, package, orientation, keyboard.",
                inputSchema={
                    "type": "object",
                    "properties": {"session": {"type": "string"}},
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_shell",
                description="Run a shell command on the Android device.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "cmd": {"type": "string"},
                    },
                    "required": ["session", "cmd"],
                },
            ),
            Tool(
                name="golem_install",
                description="Install an APK on the device.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "apk": {"description": "APK path or list of paths for split APKs"},
                    },
                    "required": ["session", "apk"],
                },
            ),
            Tool(
                name="golem_launch",
                description="Launch an app by package name.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "package": {"type": "string"},
                    },
                    "required": ["session", "package"],
                },
            ),
            Tool(
                name="golem_frida_load",
                description="Load Frida instrumentation scripts. Available: ssl_bypass, root_bypass, emulator_bypass, crypto_monitor, webview_dump, intent_intercept, sharedprefs_monitor.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "package": {"type": "string", "description": "App package to attach to"},
                        "scripts": {"type": "array", "items": {"type": "string"}, "description": "Script names to load"},
                    },
                    "required": ["session", "package", "scripts"],
                },
            ),
            Tool(
                name="golem_frida_messages",
                description="Get messages from loaded Frida scripts (crypto keys, intents, WebView bridges, etc).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "script": {"type": "string", "description": "Filter by script name"},
                    },
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_health",
                description="Check device health: online status, battery, memory, disk, u2 responsiveness.",
                inputSchema={
                    "type": "object",
                    "properties": {"session": {"type": "string"}},
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_diff",
                description="Observe the screen and report what changed since the last observation.",
                inputSchema={
                    "type": "object",
                    "properties": {"session": {"type": "string"}},
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_evidence_capture",
                description="Capture a screenshot as evidence with a description. Returns evidence ID.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "description": {"type": "string", "default": ""},
                    },
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_evidence_list",
                description="List all captured evidence items for a session.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "type": {"type": "string", "description": "Filter by type: screenshot, traffic, frida, shell, observe"},
                    },
                    "required": ["session"],
                },
            ),
            Tool(
                name="golem_context",
                description="Get recent action history and current screen context for a session.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session": {"type": "string"},
                        "n": {"type": "integer", "default": 10, "description": "Number of recent actions"},
                    },
                    "required": ["session"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            if name == "golem_sessions":
                pool = await _get_pool()
                sessions = pool.list()
                return [TextContent(type="text", text=json.dumps(sessions, indent=2))]

            session_name = arguments.get("session")
            session = await _get_session(session_name)

            if name == "golem_observe":
                from golem.observe import format_elements
                elements = await session.observe(interactive_only=not arguments.get("all", False))
                return [TextContent(type="text", text=format_elements(elements))]

            elif name == "golem_tap":
                target = arguments["target"]
                try:
                    target = int(target)
                except (ValueError, TypeError):
                    pass
                state = await session.tap(target)
                return [TextContent(type="text", text=json.dumps(state))]

            elif name == "golem_type":
                await session.type_text(arguments["text"], clear=arguments.get("clear", False))
                return [TextContent(type="text", text="typed")]

            elif name == "golem_fill":
                target = arguments["target"]
                try:
                    target = int(target)
                except (ValueError, TypeError):
                    pass
                await session.fill(target, arguments["text"])
                return [TextContent(type="text", text="filled")]

            elif name == "golem_press":
                await session.press(arguments["key"])
                return [TextContent(type="text", text=f"pressed {arguments['key']}")]

            elif name == "golem_swipe":
                await session.swipe(arguments.get("direction", "up"))
                return [TextContent(type="text", text=f"swiped {arguments.get('direction', 'up')}")]

            elif name == "golem_screenshot":
                png = await session.screenshot(arguments.get("path"))
                return [ImageContent(type="image", data=base64.b64encode(png).decode(), mimeType="image/png")]

            elif name == "golem_screen_state":
                state = await session.screen_state()
                return [TextContent(type="text", text=json.dumps(state, indent=2))]

            elif name == "golem_shell":
                out = await session.shell(arguments["cmd"])
                return [TextContent(type="text", text=out)]

            elif name == "golem_install":
                await session.app_install(arguments["apk"])
                return [TextContent(type="text", text="installed")]

            elif name == "golem_launch":
                state = await session.app_start(arguments["package"])
                return [TextContent(type="text", text=json.dumps(state))]

            elif name == "golem_frida_load":
                package = arguments["package"]
                scripts = arguments["scripts"]
                if not session._frida or not session._frida.is_attached:
                    await session.frida_attach(package)
                await session.frida_load(*scripts)
                return [TextContent(type="text", text=f"attached to {package}, loaded: {', '.join(scripts)}")]

            elif name == "golem_frida_messages":
                msgs = await session.frida_messages(arguments.get("script"))
                return [TextContent(type="text", text=json.dumps(msgs[-50:], indent=2, default=str))]

            elif name == "golem_health":
                status = await session.health_check()
                return [TextContent(type="text", text=json.dumps(status, indent=2))]

            elif name == "golem_diff":
                diff = await session.observe_diff()
                if diff is None:
                    return [TextContent(type="text", text="no previous observation to diff against")]
                return [TextContent(type="text", text=diff.summary())]

            elif name == "golem_evidence_capture":
                eid = await session.capture_screenshot_evidence(arguments.get("description", ""))
                return [TextContent(type="text", text=f"captured: {eid}")]

            elif name == "golem_evidence_list":
                items = session.evidence.list(type_filter=arguments.get("type"))
                out = [{"id": i.id, "type": i.type, "description": i.description, "timestamp": i.timestamp} for i in items]
                return [TextContent(type="text", text=json.dumps(out, indent=2))]

            elif name == "golem_context":
                n = arguments.get("n", 10)
                actions = session.context.recent_actions(n)
                current = session.context.current
                result = {
                    "recent_actions": actions,
                    "current_activity": current.activity if current else None,
                    "current_package": current.package if current else None,
                }
                return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

            else:
                return [TextContent(type="text", text=f"unknown tool: {name}")]

        except Exception as e:
            return [TextContent(type="text", text=f"error: {e}")]

    return server


def main():
    """Run the MCP server over stdio."""
    import mcp.server.stdio
    server = create_mcp_server()
    mcp.server.stdio.run(server)


if __name__ == "__main__":
    main()
