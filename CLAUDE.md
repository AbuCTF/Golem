# Golem — Android emulation & instrumentation harness

Agent-driven Android testing harness. Counterpart to Hutch (Playwright browser orchestrator).

## Architecture

Pool → Session → Device (AVD / Physical)
- **Pool**: manages named sessions, discovers from `~/.golem/profiles/`
- **Session**: stateful (ACTIVE/PAUSED/HIBERNATED), owns u2 + Frida connections
- **Device**: AVD (emulator) or Physical (USB/network ADB)
- **observe()**: dumps Android accessibility tree as indexed Element list
- **FridaBridge**: manages Frida sessions, script loading, message routing

## Key paths

- `~/.golem/profiles/<name>/golem_meta.json` — session persistence
- `~/Android/Sdk/` — ANDROID_HOME (emulator, platform-tools, system images)
- `scripts/*.js` — Frida scripts (ssl_bypass, root_bypass, emulator_bypass, etc.)

## Emulator details

- Default: Pixel 7, Android 14 (API 34), google_apis x86_64
- AVD created via avdmanager, AVDs stored at `$XDG_CONFIG_HOME/.android/avd/`
- Headless uses `swiftshader_indirect` GPU; headed uses `auto`
- First boot takes ~4min; snapshot boots are fast
- u2 (uiautomator2) connection needs retry on rapid CLI reconnection

## Frida scripts

All in `scripts/`: ssl_bypass, root_bypass, emulator_bypass, crypto_monitor,
webview_dump, intent_intercept, sharedprefs_monitor. Load by name via session.frida_load().

## Commits

Subject = version only (`vX.Y.Z`), body = terse lowercase area-prefixed `-` bullets.
No AI attribution.
