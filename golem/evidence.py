"""Evidence store — captures, indexes, and retrieves proof artifacts.

Every action that might constitute evidence (screenshot, traffic capture,
Frida message, shell output) gets stored with metadata for report generation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from golem import config

log = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    id: str
    type: str  # screenshot, traffic, frida, shell, observe, custom
    timestamp: float
    session: str
    description: str
    data_path: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "timestamp": self.timestamp,
            "session": self.session,
            "description": self.description,
            "data_path": self.data_path,
            "metadata": self.metadata,
        }


class EvidenceStore:
    """Manages evidence collection for a session."""

    def __init__(self, session_name: str, *, base_dir: Path | None = None):
        self.session_name = session_name
        self._dir = (base_dir or config.ARTIFACTS_DIR) / session_name / "evidence"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._items: list[EvidenceItem] = []
        self._counter = 0
        self._load_existing()

    def _load_existing(self) -> None:
        index_path = self._dir / "index.json"
        if index_path.exists():
            data = json.loads(index_path.read_text())
            self._items = [EvidenceItem(**item) for item in data]
            self._counter = len(self._items)

    def _save_index(self) -> None:
        index_path = self._dir / "index.json"
        index_path.write_text(json.dumps(
            [item.to_dict() for item in self._items], indent=2,
        ))

    def _next_id(self, evidence_type: str) -> str:
        self._counter += 1
        return f"{evidence_type}_{self._counter:04d}"

    def capture_screenshot(self, png_bytes: bytes, description: str = "",
                           **metadata) -> EvidenceItem:
        """Store a screenshot as evidence."""
        eid = self._next_id("screenshot")
        filename = f"{eid}.png"
        filepath = self._dir / filename
        filepath.write_bytes(png_bytes)

        item = EvidenceItem(
            id=eid, type="screenshot", timestamp=time.time(),
            session=self.session_name, description=description,
            data_path=str(filepath),
            metadata={
                "size": len(png_bytes),
                "sha256": hashlib.sha256(png_bytes).hexdigest()[:16],
                **metadata,
            },
        )
        self._items.append(item)
        self._save_index()
        log.debug("evidence: screenshot %s (%d bytes)", eid, len(png_bytes))
        return item

    def capture_traffic(self, flows: list[dict], description: str = "",
                        **metadata) -> EvidenceItem:
        """Store captured traffic flows as evidence."""
        eid = self._next_id("traffic")
        filename = f"{eid}.json"
        filepath = self._dir / filename
        filepath.write_text(json.dumps(flows, indent=2, default=str))

        item = EvidenceItem(
            id=eid, type="traffic", timestamp=time.time(),
            session=self.session_name, description=description,
            data_path=str(filepath),
            metadata={"flow_count": len(flows), **metadata},
        )
        self._items.append(item)
        self._save_index()
        return item

    def capture_frida(self, messages: list[dict], script: str = "",
                      description: str = "", **metadata) -> EvidenceItem:
        """Store Frida instrumentation output as evidence."""
        eid = self._next_id("frida")
        filename = f"{eid}.json"
        filepath = self._dir / filename
        filepath.write_text(json.dumps(messages, indent=2, default=str))

        item = EvidenceItem(
            id=eid, type="frida", timestamp=time.time(),
            session=self.session_name, description=description,
            data_path=str(filepath),
            metadata={"script": script, "message_count": len(messages), **metadata},
        )
        self._items.append(item)
        self._save_index()
        return item

    def capture_shell(self, command: str, output: str, description: str = "",
                      **metadata) -> EvidenceItem:
        """Store shell command output as evidence."""
        eid = self._next_id("shell")
        filename = f"{eid}.txt"
        filepath = self._dir / filename
        filepath.write_text(f"$ {command}\n{output}")

        item = EvidenceItem(
            id=eid, type="shell", timestamp=time.time(),
            session=self.session_name, description=description,
            data_path=str(filepath),
            metadata={"command": command, **metadata},
        )
        self._items.append(item)
        self._save_index()
        return item

    def capture_observe(self, elements_text: str, description: str = "",
                        **metadata) -> EvidenceItem:
        """Store UI hierarchy observation as evidence."""
        eid = self._next_id("observe")
        filename = f"{eid}.txt"
        filepath = self._dir / filename
        filepath.write_text(elements_text)

        item = EvidenceItem(
            id=eid, type="observe", timestamp=time.time(),
            session=self.session_name, description=description,
            data_path=str(filepath), metadata=metadata,
        )
        self._items.append(item)
        self._save_index()
        return item

    def capture_custom(self, data: bytes | str, ext: str = "txt",
                       description: str = "", **metadata) -> EvidenceItem:
        """Store arbitrary data as evidence."""
        eid = self._next_id("custom")
        filename = f"{eid}.{ext}"
        filepath = self._dir / filename
        if isinstance(data, bytes):
            filepath.write_bytes(data)
        else:
            filepath.write_text(data)

        item = EvidenceItem(
            id=eid, type="custom", timestamp=time.time(),
            session=self.session_name, description=description,
            data_path=str(filepath), metadata=metadata,
        )
        self._items.append(item)
        self._save_index()
        return item

    def list(self, *, type_filter: str | None = None) -> list[EvidenceItem]:
        if type_filter:
            return [i for i in self._items if i.type == type_filter]
        return list(self._items)

    def get(self, evidence_id: str) -> EvidenceItem | None:
        for item in self._items:
            if item.id == evidence_id:
                return item
        return None

    def read(self, evidence_id: str) -> bytes | str | None:
        """Read the data of an evidence item."""
        item = self.get(evidence_id)
        if not item or not item.data_path:
            return None
        path = Path(item.data_path)
        if not path.exists():
            return None
        if item.type == "screenshot":
            return path.read_bytes()
        return path.read_text()

    @property
    def count(self) -> int:
        return len(self._items)

    @property
    def directory(self) -> Path:
        return self._dir
