"""Golem CLI — create, control, and inspect Android testing sessions."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import textwrap

from golem import __version__


HELP_TEXT = f"""\
usage: golem [options] <command> [<args>]

instrumented android session orchestrator

options:
  -h, --help        show this help message and exit
  --version         show program's version number and exit
  -v, --verbose     enable debug logging

session:
  create          create a new session
  list            list sessions
  status          show session details
  close           hibernate a session (keep device)
  destroy         shut down and remove a session

ui automation:
  observe         dump interactive elements on screen
  tap             tap an element by index, text, or resource id
  type            type text into focused element
  fill            tap a field then type text
  press           press a key (back, home, enter, recent)
  swipe           swipe in a direction
  screenshot      take a screenshot
  screen          show current screen state
  diff            show what changed since last observe

app management:
  install         install an APK
  launch          launch an app by package name
  stop            stop a running app
  apps            list installed apps
  shell           run shell command on device

instrumentation:
  cert-install    install mitmproxy CA cert on device
  proxy-on        configure device to use proxy
  proxy-off       remove proxy from device
  frida-scripts   list available Frida scripts

analysis:
  analyze         run static analysis on an APK
  persona         generate a device persona from a seed
  health          show device health status
  evidence        manage evidence items

daemon:
  daemon          start the Golem daemon (JSON-RPC over Unix socket)
  mcp             start the MCP server (stdio)

other:
  sdk             manage Android SDK
"""


def main():
    parser = argparse.ArgumentParser(
        prog="golem",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command")

    # create
    p = sub.add_parser("create")
    p.add_argument("name")
    p.add_argument("--device", default="avd", help="device spec (avd, avd:pixel_8, physical:SERIAL, usb)")
    p.add_argument("--headed", action="store_true", help="show emulator window")
    p.add_argument("--no-launch", action="store_true", help="create without booting")

    # list
    sub.add_parser("list")

    # status
    p = sub.add_parser("status")
    p.add_argument("name")

    # observe
    p = sub.add_parser("observe")
    p.add_argument("name")
    p.add_argument("--all", action="store_true", help="include non-interactive elements")

    # tap
    p = sub.add_parser("tap")
    p.add_argument("name")
    p.add_argument("target", help="element index, text, or id:resource_id")

    # type
    p = sub.add_parser("type")
    p.add_argument("name")
    p.add_argument("text")
    p.add_argument("--clear", action="store_true")

    # fill
    p = sub.add_parser("fill")
    p.add_argument("name")
    p.add_argument("target")
    p.add_argument("text")

    # press
    p = sub.add_parser("press")
    p.add_argument("name")
    p.add_argument("key")

    # swipe
    p = sub.add_parser("swipe")
    p.add_argument("name")
    p.add_argument("direction", choices=["up", "down", "left", "right"], default="up", nargs="?")

    # screenshot
    p = sub.add_parser("screenshot")
    p.add_argument("name")
    p.add_argument("output", nargs="?", default="screenshot.png")

    # screen
    p = sub.add_parser("screen")
    p.add_argument("name")

    # install
    p = sub.add_parser("install")
    p.add_argument("name")
    p.add_argument("apk", nargs="+", help="APK file(s) — multiple for split APKs")

    # launch
    p = sub.add_parser("launch")
    p.add_argument("name")
    p.add_argument("package")

    # stop
    p = sub.add_parser("stop")
    p.add_argument("name")
    p.add_argument("package")

    # apps
    p = sub.add_parser("apps")
    p.add_argument("name")

    # shell
    p = sub.add_parser("shell")
    p.add_argument("name")
    p.add_argument("cmd", nargs=argparse.REMAINDER)

    # close
    p = sub.add_parser("close")
    p.add_argument("name")

    # destroy
    p = sub.add_parser("destroy")
    p.add_argument("name")

    # cert-install
    p = sub.add_parser("cert-install")
    p.add_argument("name")
    p.add_argument("--cert", help="path to PEM cert (default: mitmproxy CA)")

    # proxy-on
    p = sub.add_parser("proxy-on")
    p.add_argument("name")
    p.add_argument("--port", type=int, default=8082)

    # proxy-off
    p = sub.add_parser("proxy-off")
    p.add_argument("name")

    # diff
    p = sub.add_parser("diff")
    p.add_argument("name")

    # health
    p = sub.add_parser("health")
    p.add_argument("name")

    # evidence
    p = sub.add_parser("evidence")
    p.add_argument("name")
    p_ev_sub = p.add_subparsers(dest="evidence_cmd")
    p_ev_sub.add_parser("list")
    p_ev_cap = p_ev_sub.add_parser("capture")
    p_ev_cap.add_argument("--desc", default="", help="description")
    p_ev_sub.add_parser("count")

    # persona
    p = sub.add_parser("persona")
    p.add_argument("seed", help="seed string for consistent identity")
    p.add_argument("--profile", type=int, help="device profile index (0-5)")

    # frida-scripts
    sub.add_parser("frida-scripts")

    # analyze
    p = sub.add_parser("analyze")
    p.add_argument("apk", help="path to APK file")
    p.add_argument("--output", "-o", help="output directory")

    # daemon
    sub.add_parser("daemon")

    # mcp
    sub.add_parser("mcp")

    # sdk
    p_sdk = sub.add_parser("sdk")
    sdk_sub = p_sdk.add_subparsers(dest="sdk_cmd")
    sdk_sub.add_parser("status")

    args = parser.parse_args()

    if args.version:
        print(f"golem {__version__}")
        return

    if args.help or not args.command:
        print(HELP_TEXT, end="")
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

        elif cmd == "diff":
            session = await pool.get(args.name, launch=True)
            diff = await session.observe_diff()
            if diff is None:
                print("no previous observation to diff against")
            else:
                print(diff.summary())

        elif cmd == "health":
            session = await pool.get(args.name, launch=True)
            status = await session.health_check()
            for k, v in status.items():
                print(f"  {k}: {v}")

        elif cmd == "evidence":
            session = await pool.get(args.name, launch=True)
            sub_cmd = args.evidence_cmd or "list"
            if sub_cmd == "list":
                items = session.evidence.list()
                if not items:
                    print("no evidence items")
                else:
                    for item in items:
                        print(f"  {item.id:20s}  {item.type:12s}  {item.description or '-'}")
            elif sub_cmd == "capture":
                eid = await session.capture_screenshot_evidence(args.desc)
                print(f"captured screenshot evidence: {eid}")
            elif sub_cmd == "count":
                print(f"evidence items: {session.evidence.count}")

        elif cmd == "persona":
            from golem.persona import generate_persona
            persona = generate_persona(args.seed, profile_index=args.profile)
            print(f"  model:      {persona.model}")
            print(f"  brand:      {persona.brand} / {persona.manufacturer}")
            print(f"  device:     {persona.device}")
            print(f"  android_id: {persona.android_id}")
            print(f"  imei:       {persona.imei}")
            print(f"  carrier:    {persona.sim_operator_name}")
            print(f"  serial:     {persona.serial_number}")
            print(f"  build:      {persona.build_display}")
            print(f"  seed:       {persona.seed}")

        elif cmd == "frida-scripts":
            from golem.session import Session
            scripts = Session.frida_scripts_available()
            for s in scripts:
                print(f"  {s}")

        elif cmd == "analyze":
            from golem.static import analyze_apk
            result = await analyze_apk(args.apk, output_dir=args.output)
            print(result.summary())


async def _cmd_sdk(args):
    from golem import config
    print(f"ANDROID_HOME: {config.ANDROID_HOME}")
    print(f"  emulator:   {'yes' if config.EMULATOR_BIN.exists() else 'no'}")
    print(f"  sdkmanager: {'yes' if config.SDKMANAGER_BIN.exists() else 'no'}")
    print(f"  avdmanager: {'yes' if config.AVDMANAGER_BIN.exists() else 'no'}")


if __name__ == "__main__":
    main()
