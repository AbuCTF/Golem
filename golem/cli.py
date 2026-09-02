"""Golem CLI — create, control, and inspect Android testing sessions."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from golem import __version__


def main():
    parser = argparse.ArgumentParser(
        prog="golem",
        description="Agent-driven Android testing harness",
    )
    parser.add_argument("--version", action="version", version=f"golem {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command")

    # create
    p = sub.add_parser("create", help="create a new session")
    p.add_argument("name")
    p.add_argument("--device", default="avd", help="device spec (avd, avd:pixel_8, physical:SERIAL, usb)")
    p.add_argument("--headed", action="store_true", help="show emulator window")
    p.add_argument("--no-launch", action="store_true", help="create without booting")

    # list
    sub.add_parser("list", help="list sessions")

    # status
    p = sub.add_parser("status", help="show session status")
    p.add_argument("name")

    # observe
    p = sub.add_parser("observe", help="dump interactive elements on screen")
    p.add_argument("name")
    p.add_argument("--all", action="store_true", help="include non-interactive elements")

    # tap
    p = sub.add_parser("tap", help="tap an element")
    p.add_argument("name")
    p.add_argument("target", help="element index, text, or id:resource_id")

    # type
    p = sub.add_parser("type", help="type text into focused element")
    p.add_argument("name")
    p.add_argument("text")
    p.add_argument("--clear", action="store_true")

    # fill
    p = sub.add_parser("fill", help="tap a field then type text")
    p.add_argument("name")
    p.add_argument("target")
    p.add_argument("text")

    # press
    p = sub.add_parser("press", help="press a key (back, home, enter, recent)")
    p.add_argument("name")
    p.add_argument("key")

    # swipe
    p = sub.add_parser("swipe", help="swipe in a direction")
    p.add_argument("name")
    p.add_argument("direction", choices=["up", "down", "left", "right"], default="up", nargs="?")

    # screenshot
    p = sub.add_parser("screenshot", help="take a screenshot")
    p.add_argument("name")
    p.add_argument("output", nargs="?", default="screenshot.png")

    # screen
    p = sub.add_parser("screen", help="show current screen state")
    p.add_argument("name")

    # install
    p = sub.add_parser("install", help="install an APK")
    p.add_argument("name")
    p.add_argument("apk", nargs="+", help="APK file(s) — multiple for split APKs")

    # launch
    p = sub.add_parser("launch", help="launch an app")
    p.add_argument("name")
    p.add_argument("package")

    # stop
    p = sub.add_parser("stop", help="stop an app")
    p.add_argument("name")
    p.add_argument("package")

    # apps
    p = sub.add_parser("apps", help="list installed apps")
    p.add_argument("name")

    # shell
    p = sub.add_parser("shell", help="run shell command on device")
    p.add_argument("name")
    p.add_argument("cmd", nargs=argparse.REMAINDER)

    # close
    p = sub.add_parser("close", help="hibernate a session (keep device)")
    p.add_argument("name")

    # destroy
    p = sub.add_parser("destroy", help="shut down and remove a session")
    p.add_argument("name")

    # cert-install
    p = sub.add_parser("cert-install", help="install mitmproxy CA cert on device")
    p.add_argument("name")
    p.add_argument("--cert", help="path to PEM cert (default: mitmproxy CA)")

    # proxy-on
    p = sub.add_parser("proxy-on", help="configure device to use proxy")
    p.add_argument("name")
    p.add_argument("--port", type=int, default=8082)

    # proxy-off
    p = sub.add_parser("proxy-off", help="remove proxy from device")
    p.add_argument("name")

    # frida-scripts
    sub.add_parser("frida-scripts", help="list available Frida scripts")

    # daemon
    sub.add_parser("daemon", help="start the Golem daemon (JSON-RPC over Unix socket)")

    # mcp
    sub.add_parser("mcp", help="start the MCP server (stdio)")

    # sdk
    p_sdk = sub.add_parser("sdk", help="manage Android SDK")
    sdk_sub = p_sdk.add_subparsers(dest="sdk_cmd")
    sdk_sub.add_parser("status", help="show SDK status")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    if args.command == "daemon":
        from golem.daemon import run_daemon
        asyncio.run(run_daemon())
        return

    if args.command == "mcp":
        from golem.mcp_server import main as mcp_main
        mcp_main()
        return

    asyncio.run(_run(args))


async def _run(args):
    from golem.pool import Pool
    from golem import config

    if args.command == "sdk":
        await _cmd_sdk(args)
        return

    async with Pool() as pool:
        cmd = args.command

        if cmd == "create":
            session = await pool.create(
                args.name,
                device_spec=args.device,
                headless=not args.headed,
                launch=not args.no_launch,
            )
            info = await session.device.info()
            print(f"session '{args.name}' created")
            print(f"  backend: {info.backend}")
            print(f"  serial:  {info.serial}")
            print(f"  model:   {info.model}")
            print(f"  api:     {info.api_level}")
            print(f"  state:   {session.state.value}")

        elif cmd == "list":
            sessions = pool.list()
            if not sessions:
                print("no sessions")
                return
            for s in sessions:
                print(f"  {s['name']:20s}  {s['state']:12s}  {s['profile_dir']}")

        elif cmd == "status":
            session = await pool.get(args.name)
            info = await session.device.info()
            print(f"session:  {session.name}")
            print(f"state:    {session.state.value}")
            print(f"backend:  {info.backend}")
            print(f"serial:   {info.serial}")
            print(f"model:    {info.model}")
            print(f"api:      {info.api_level}")
            print(f"device:   {info.state}")

        elif cmd == "observe":
            session = await pool.get(args.name, launch=True)
            elements = await session.observe(interactive_only=not args.all)
            from golem.observe import format_elements
            print(format_elements(elements))

        elif cmd == "tap":
            session = await pool.get(args.name, launch=True)
            target = args.target
            try:
                target = int(target)
            except ValueError:
                pass
            state = await session.tap(target)
            print(f"tapped → {state.get('activity', '?')}")

        elif cmd == "type":
            session = await pool.get(args.name, launch=True)
            await session.type_text(args.text, clear=args.clear)
            print("typed")

        elif cmd == "fill":
            session = await pool.get(args.name, launch=True)
            target = args.target
            try:
                target = int(target)
            except ValueError:
                pass
            await session.fill(target, args.text)
            print("filled")

        elif cmd == "press":
            session = await pool.get(args.name, launch=True)
            await session.press(args.key)
            print(f"pressed {args.key}")

        elif cmd == "swipe":
            session = await pool.get(args.name, launch=True)
            await session.swipe(args.direction)
            print(f"swiped {args.direction}")

        elif cmd == "screenshot":
            session = await pool.get(args.name, launch=True)
            await session.screenshot(args.output)
            print(f"saved to {args.output}")

        elif cmd == "screen":
            session = await pool.get(args.name, launch=True)
            state = await session.screen_state()
            for k, v in state.items():
                print(f"  {k}: {v}")

        elif cmd == "install":
            session = await pool.get(args.name, launch=True)
            if len(args.apk) > 1:
                await session.app_install(args.apk)
            else:
                await session.app_install(args.apk[0])
            print(f"installed {len(args.apk)} APK(s)")

        elif cmd == "launch":
            session = await pool.get(args.name, launch=True)
            state = await session.app_start(args.package)
            print(f"launched → {state.get('activity', '?')}")

        elif cmd == "stop":
            session = await pool.get(args.name, launch=True)
            await session.app_stop(args.package)
            print(f"stopped {args.package}")

        elif cmd == "apps":
            session = await pool.get(args.name, launch=True)
            apps = await session.app_list()
            for a in sorted(apps):
                print(f"  {a}")

        elif cmd == "shell":
            session = await pool.get(args.name, launch=True)
            out = await session.shell(" ".join(args.cmd))
            print(out, end="")

        elif cmd == "close":
            await pool.close(args.name)
            print(f"session '{args.name}' hibernated")

        elif cmd == "destroy":
            await pool.destroy(args.name)
            print(f"session '{args.name}' destroyed")

        elif cmd == "cert-install":
            from pathlib import Path
            session = await pool.get(args.name, launch=True)
            cert = Path(args.cert) if args.cert else None
            await session.proxy_install_cert(cert)
            print("CA cert installed — reboot device to activate")

        elif cmd == "proxy-on":
            session = await pool.get(args.name, launch=True)
            await session.proxy_configure(port=args.port)
            print(f"proxy configured → 10.0.2.2:{args.port}")

        elif cmd == "proxy-off":
            session = await pool.get(args.name, launch=True)
            await session.proxy_clear()
            print("proxy cleared")

        elif cmd == "frida-scripts":
            from golem.session import Session
            scripts = Session.frida_scripts_available()
            for s in scripts:
                print(f"  {s}")


async def _cmd_sdk(args):
    from golem import config
    print(f"ANDROID_HOME: {config.ANDROID_HOME}")
    print(f"  emulator:   {'yes' if config.EMULATOR_BIN.exists() else 'no'}")
    print(f"  sdkmanager: {'yes' if config.SDKMANAGER_BIN.exists() else 'no'}")
    print(f"  avdmanager: {'yes' if config.AVDMANAGER_BIN.exists() else 'no'}")


if __name__ == "__main__":
    main()
