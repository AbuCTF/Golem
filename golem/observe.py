"""View hierarchy parsing — the Android equivalent of Hutch's observe().

Dumps the Android accessibility tree (via uiautomator2) and returns a flat list
of interactive elements with indices, so an agent can say "tap element 3".
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class Element:
    idx: int
    cls: str
    text: str
    resource_id: str
    content_desc: str
    bounds: tuple[int, int, int, int]
    clickable: bool
    scrollable: bool
    editable: bool
    checked: bool | None
    enabled: bool

    @property
    def center(self) -> tuple[int, int]:
        l, t, r, b = self.bounds
        return ((l + r) // 2, (t + b) // 2)

    @property
    def short(self) -> str:
        label = self.text or self.content_desc or self.resource_id or self.cls.rsplit(".", 1)[-1]
        if len(label) > 50:
            label = label[:47] + "..."
        tag = self.cls.rsplit(".", 1)[-1]
        flags = []
        if self.clickable:
            flags.append("click")
        if self.scrollable:
            flags.append("scroll")
        if self.editable:
            flags.append("edit")
        return f"[{self.idx}] {tag} — {label}" + (f" ({','.join(flags)})" if flags else "")


def parse_hierarchy(xml_str: str, *, interactive_only: bool = True) -> list[Element]:
    """Parse uiautomator2 dump_hierarchy() XML into indexed Element list."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return []

    elements: list[Element] = []
    for node in root.iter("node"):
        clickable = node.get("clickable") == "true"
        scrollable = node.get("scrollable") == "true"
        editable = node.get("class", "").endswith("EditText") or node.get("class", "").endswith("AutoCompleteTextView")
        enabled = node.get("enabled") == "true"

        if interactive_only and not (clickable or scrollable or editable):
            continue

        if not enabled and interactive_only:
            continue

        bounds = _parse_bounds(node.get("bounds", ""))
        if not bounds:
            continue

        checked_str = node.get("checked")
        checked = None
        if node.get("checkable") == "true":
            checked = checked_str == "true"

        elements.append(Element(
            idx=len(elements),
            cls=node.get("class", ""),
            text=node.get("text", ""),
            resource_id=_short_id(node.get("resource-id", "")),
            content_desc=node.get("content-desc", ""),
            bounds=bounds,
            clickable=clickable,
            scrollable=scrollable,
            editable=editable,
            checked=checked,
            enabled=enabled,
        ))

    return elements


def format_elements(elements: list[Element]) -> str:
    """Format elements for display / agent consumption."""
    if not elements:
        return "(no interactive elements on screen)"
    return "\n".join(e.short for e in elements)


_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")

def _parse_bounds(bounds_str: str) -> tuple[int, int, int, int] | None:
    m = _BOUNDS_RE.match(bounds_str)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))


def _short_id(resource_id: str) -> str:
    if ":" in resource_id and "/" in resource_id:
        return resource_id.split("/", 1)[1]
    return resource_id
