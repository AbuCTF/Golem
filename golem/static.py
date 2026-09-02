"""Static analysis pipeline — APK decompilation, secrets extraction, endpoint discovery.

Pipeline stages: APKiD (packer/obfuscation detect) → apktool (resources/manifest) →
jadx (Java source) → secrets scan → endpoint extraction → manifest analysis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from golem import config

log = logging.getLogger(__name__)


@dataclass
class APKAnalysis:
    apk_path: str
    package_name: str | None = None
    version: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    exported_components: list[dict] = field(default_factory=list)
    deep_links: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    webview_bridges: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    packer_info: dict | None = None
    source_dir: Path | None = None
    resources_dir: Path | None = None

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v}
        d["apk_path"] = self.apk_path
        if self.source_dir:
            d["source_dir"] = str(self.source_dir)
        if self.resources_dir:
            d["resources_dir"] = str(self.resources_dir)
        return d

    def summary(self) -> str:
        lines = [f"package: {self.package_name}"]
        lines.append(f"version: {self.version}  sdk: {self.min_sdk}→{self.target_sdk}")
        lines.append(f"permissions: {len(self.permissions)}")
        lines.append(f"exported: {len(self.exported_components)}")
        lines.append(f"deep links: {len(self.deep_links)}")
        lines.append(f"endpoints: {len(self.endpoints)}")
        lines.append(f"secrets: {len(self.secrets)}")
        lines.append(f"webview bridges: {len(self.webview_bridges)}")
        lines.append(f"native libs: {len(self.native_libs)}")
        return "\n".join(lines)


async def analyze_apk(apk_path: str, *, output_dir: str | None = None) -> APKAnalysis:
    """Run the full static analysis pipeline on an APK."""
    apk = Path(apk_path)
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    if output_dir:
        out = Path(output_dir)
    else:
        out = config.ARTIFACTS_DIR / apk.stem
    out.mkdir(parents=True, exist_ok=True)

    analysis = APKAnalysis(apk_path=str(apk))

    # Run stages concurrently where possible
    await asyncio.gather(
        _run_apktool(apk, out, analysis),
        _run_jadx(apk, out, analysis),
        _run_apkid(apk, analysis),
    )

    # Post-decompile analysis (needs jadx output)
    if analysis.source_dir and analysis.source_dir.exists():
        await asyncio.gather(
            _scan_secrets(analysis.source_dir, analysis),
            _scan_endpoints(analysis.source_dir, analysis),
            _scan_webview_bridges(analysis.source_dir, analysis),
        )

    # Parse manifest (needs apktool output)
    if analysis.resources_dir:
        manifest = analysis.resources_dir / "AndroidManifest.xml"
        if manifest.exists():
            _parse_manifest(manifest, analysis)

    report_path = out / "analysis.json"
    report_path.write_text(json.dumps(analysis.to_dict(), indent=2, default=str))
    log.info("analysis saved to %s", report_path)

    return analysis


async def _run_apktool(apk: Path, out: Path, analysis: APKAnalysis) -> None:
    """Decompile resources and manifest with apktool."""
    apktool_dir = out / "apktool"
    if apktool_dir.exists():
        log.debug("apktool output exists, skipping")
        analysis.resources_dir = apktool_dir
        return

    if not _cmd_exists("apktool"):
        log.warning("apktool not found, skipping resource decompilation")
        return

    proc = await asyncio.create_subprocess_exec(
        "apktool", "d", str(apk), "-o", str(apktool_dir), "-f",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        log.warning("apktool failed: %s", err.decode()[:200])
        return

    analysis.resources_dir = apktool_dir
    log.info("apktool decompiled to %s", apktool_dir)


async def _run_jadx(apk: Path, out: Path, analysis: APKAnalysis) -> None:
    """Decompile to Java source with jadx."""
    jadx_dir = out / "jadx"
    if jadx_dir.exists():
        log.debug("jadx output exists, skipping")
        analysis.source_dir = jadx_dir
        return

    if not _cmd_exists("jadx"):
        log.warning("jadx not found, skipping source decompilation")
        return

    proc = await asyncio.create_subprocess_exec(
        "jadx", str(apk), "-d", str(jadx_dir),
        "--no-res", "--threads-count", "4",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        log.warning("jadx had warnings: %s", err.decode()[:200])

    analysis.source_dir = jadx_dir
    log.info("jadx decompiled to %s", jadx_dir)


async def _run_apkid(apk: Path, analysis: APKAnalysis) -> None:
    """Detect packers, obfuscators, and protections with APKiD."""
    if not _cmd_exists("apkid"):
        return

    proc = await asyncio.create_subprocess_exec(
        "apkid", "-j", str(apk),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await proc.communicate()
    try:
        analysis.packer_info = json.loads(out.decode())
    except json.JSONDecodeError:
        pass


# ── Secret patterns ──

_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "api_key"),
    (r'(?:secret|token|password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{8,})["\']', "secret"),
    (r'(?:aws_access_key_id|AKIA)[A-Z0-9]{16}', "aws_key"),
    (r'["\']AIza[0-9A-Za-z_-]{35}["\']', "google_api_key"),
    (r'["\']ghp_[0-9a-zA-Z]{36}["\']', "github_token"),
    (r'["\']sk-[0-9a-zA-Z]{32,}["\']', "stripe_key"),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "private_key"),
    (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "jwt"),
    (r'["\'](?:Bearer |Basic )[A-Za-z0-9+/=_-]{20,}["\']', "auth_header"),
    (r'firebase[_-]?(?:key|secret|token)\s*[=:]\s*["\']([^\s"\']+)["\']', "firebase"),
]

_COMPILED_SECRETS = [(re.compile(p, re.IGNORECASE), label) for p, label in _SECRET_PATTERNS]


async def _scan_secrets(source_dir: Path, analysis: APKAnalysis) -> None:
    """Scan decompiled source for hardcoded secrets."""
    java_files = list(source_dir.rglob("*.java"))
    for jf in java_files:
        try:
            content = jf.read_text(errors="replace")
        except Exception:
            continue
        for pattern, label in _COMPILED_SECRETS:
            for match in pattern.finditer(content):
                analysis.secrets.append({
                    "type": label,
                    "value": match.group()[:100],
                    "file": str(jf.relative_to(source_dir)),
                    "line": content[:match.start()].count("\n") + 1,
                })
    log.info("secrets scan: %d findings in %d files", len(analysis.secrets), len(java_files))


# ── Endpoint patterns ──

_ENDPOINT_PATTERNS = [
    re.compile(r'https?://[^\s"\'<>{}|\\^`\[\]]+', re.IGNORECASE),
    re.compile(r'["\'](/api/[^\s"\']+)["\']'),
    re.compile(r'["\'](/v[0-9]+/[^\s"\']+)["\']'),
]


async def _scan_endpoints(source_dir: Path, analysis: APKAnalysis) -> None:
    """Extract API endpoints and URLs from decompiled source."""
    seen = set()
    for jf in source_dir.rglob("*.java"):
        try:
            content = jf.read_text(errors="replace")
        except Exception:
            continue
        for pattern in _ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                url = match.group().rstrip('")},;')
                if url not in seen and not _is_boilerplate_url(url):
                    seen.add(url)
                    analysis.endpoints.append(url)
    log.info("endpoint scan: %d unique endpoints", len(analysis.endpoints))


def _is_boilerplate_url(url: str) -> bool:
    skip = [
        "schemas.android.com", "schemas.xmlsoap.org", "www.w3.org",
        "xmlns.", "ns.adobe.com", "purl.org", "apache.org",
        "google.com/schemas", "developer.android.com",
        ".xsd", ".dtd", ".example.com",
    ]
    return any(s in url.lower() for s in skip)


async def _scan_webview_bridges(source_dir: Path, analysis: APKAnalysis) -> None:
    """Find @JavascriptInterface annotated methods (WebView bridge attack surface)."""
    bridge_pattern = re.compile(r'@JavascriptInterface\s+.*?(?:public\s+)?(\w+\s+\w+)\s*\(', re.DOTALL)
    for jf in source_dir.rglob("*.java"):
        try:
            content = jf.read_text(errors="replace")
        except Exception:
            continue
        if "@JavascriptInterface" in content:
            for match in bridge_pattern.finditer(content):
                analysis.webview_bridges.append(
                    f"{jf.relative_to(source_dir)}:{match.group(1)}"
                )


def _parse_manifest(manifest_path: Path, analysis: APKAnalysis) -> None:
    """Parse AndroidManifest.xml for security-relevant info."""
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(manifest_path)
    except ET.ParseError:
        return

    root = tree.getroot()
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    analysis.package_name = root.get("package")

    # SDK versions
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = uses_sdk.get(f"{{{ns['android']}}}minSdkVersion")
        target_sdk = uses_sdk.get(f"{{{ns['android']}}}targetSdkVersion")
        analysis.min_sdk = int(min_sdk) if min_sdk else None
        analysis.target_sdk = int(target_sdk) if target_sdk else None

    # Version
    analysis.version = root.get(f"{{{ns['android']}}}versionName")

    # Permissions
    for perm in root.findall("uses-permission"):
        name = perm.get(f"{{{ns['android']}}}name")
        if name:
            analysis.permissions.append(name)

    # Components
    app = root.find("application")
    if app is None:
        return

    for tag, store in [("activity", analysis.activities), ("service", analysis.services),
                       ("receiver", analysis.receivers), ("provider", analysis.providers)]:
        for comp in app.findall(tag):
            name = comp.get(f"{{{ns['android']}}}name", "")
            store.append(name)

            exported = comp.get(f"{{{ns['android']}}}exported")
            has_filter = comp.find("intent-filter") is not None
            if exported == "true" or (exported is None and has_filter):
                component = {"type": tag, "name": name}
                if has_filter:
                    for intent_filter in comp.findall("intent-filter"):
                        for data in intent_filter.findall("data"):
                            scheme = data.get(f"{{{ns['android']}}}scheme", "")
                            host = data.get(f"{{{ns['android']}}}host", "")
                            path = data.get(f"{{{ns['android']}}}path", "")
                            path_prefix = data.get(f"{{{ns['android']}}}pathPrefix", "")
                            if scheme:
                                deep_link = f"{scheme}://{host}{path or path_prefix}"
                                analysis.deep_links.append(deep_link)
                                component.setdefault("deep_links", []).append(deep_link)
                analysis.exported_components.append(component)

    # Native libs
    lib_dir = manifest_path.parent / "lib"
    if lib_dir.exists():
        for so in lib_dir.rglob("*.so"):
            analysis.native_libs.append(str(so.relative_to(manifest_path.parent)))


def _cmd_exists(cmd: str) -> bool:
    return subprocess.run(
        ["which", cmd], capture_output=True
    ).returncode == 0
