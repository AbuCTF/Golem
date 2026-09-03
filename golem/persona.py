"""DevicePersona — generates consistent device fingerprints from a seed.

Each persona is a complete device identity: IMEI, Android ID, build properties,
SIM info, etc. Same seed always produces the same identity, so sessions
maintain consistent fingerprints across restarts.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from golem import config


# Real device profiles to base personas on
_DEVICE_PROFILES = [
    {
        "model": "Pixel 7", "manufacturer": "Google", "brand": "google",
        "device": "panther", "product": "panther", "board": "pantah",
        "hardware": "tensor", "fingerprint_prefix": "google/panther/panther:14/",
    },
    {
        "model": "Pixel 6 Pro", "manufacturer": "Google", "brand": "google",
        "device": "raven", "product": "raven", "board": "raven",
        "hardware": "tensor", "fingerprint_prefix": "google/raven/raven:14/",
    },
    {
        "model": "SM-S918B", "manufacturer": "samsung", "brand": "samsung",
        "device": "dm3q", "product": "dm3qxxx", "board": "s5e9925",
        "hardware": "qcom", "fingerprint_prefix": "samsung/dm3qxxx/dm3q:14/",
    },
    {
        "model": "SM-A546B", "manufacturer": "samsung", "brand": "samsung",
        "device": "a54x", "product": "a54xnsxx", "board": "s5e8835",
        "hardware": "exynos", "fingerprint_prefix": "samsung/a54xnsxx/a54x:14/",
    },
    {
        "model": "22101316G", "manufacturer": "Xiaomi", "brand": "Redmi",
        "device": "sapphire", "product": "sapphire", "board": "sapphire",
        "hardware": "qcom", "fingerprint_prefix": "Redmi/sapphire/sapphire:14/",
    },
    {
        "model": "CPH2585", "manufacturer": "OPPO", "brand": "OPPO",
        "device": "OP5913L1", "product": "OP5913L1", "board": "mt6789",
        "hardware": "mt6789", "fingerprint_prefix": "OPPO/OP5913L1/OP5913L1:14/",
    },
]

_CARRIERS = [
    {"operator_name": "T-Mobile", "operator": "310260", "country": "us"},
    {"operator_name": "Verizon", "operator": "311480", "country": "us"},
    {"operator_name": "AT&T", "operator": "310410", "country": "us"},
    {"operator_name": "Vodafone", "operator": "23415", "country": "gb"},
    {"operator_name": "Jio", "operator": "40588", "country": "in"},
    {"operator_name": "Airtel", "operator": "40410", "country": "in"},
]


@dataclass
class DevicePersona:
    seed: str
    model: str
    manufacturer: str
    brand: str
    device: str
    product: str
    board: str
    hardware: str
    fingerprint: str
    android_id: str
    imei: str
    serial_number: str
    sim_operator: str
    sim_operator_name: str
    sim_serial: str
    subscriber_id: str
    wifi_mac: str
    bluetooth_mac: str
    build_id: str
    build_display: str
    build_tags: str = "release-keys"
    build_type: str = "user"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> DevicePersona:
        return cls(**json.loads(path.read_text()))

    def to_build_prop_overrides(self) -> dict[str, str]:
        """Generate build.prop key=value pairs for this persona."""
        return {
            "ro.product.model": self.model,
            "ro.product.manufacturer": self.manufacturer,
            "ro.product.brand": self.brand,
            "ro.product.device": self.device,
            "ro.product.name": self.product,
            "ro.product.board": self.board,
            "ro.hardware": self.hardware,
            "ro.build.fingerprint": self.fingerprint,
            "ro.build.display.id": self.build_display,
            "ro.build.id": self.build_id,
            "ro.build.tags": self.build_tags,
            "ro.build.type": self.build_type,
            "ro.serialno": self.serial_number,
        }

    def to_frida_overrides_js(self) -> str:
        """Generate Frida script to apply this persona at runtime."""
        props = self.to_build_prop_overrides()
        lines = ["Java.perform(function() {"]
        lines.append("  var Build = Java.use('android.os.Build');")
        field_map = {
            "ro.product.model": "MODEL",
            "ro.product.manufacturer": "MANUFACTURER",
            "ro.product.brand": "BRAND",
            "ro.product.device": "DEVICE",
            "ro.product.name": "PRODUCT",
            "ro.product.board": "BOARD",
            "ro.hardware": "HARDWARE",
            "ro.build.fingerprint": "FINGERPRINT",
            "ro.build.display.id": "DISPLAY",
            "ro.build.id": "ID",
            "ro.build.tags": "TAGS",
            "ro.build.type": "TYPE",
            "ro.serialno": "SERIAL",
        }
        for prop_key, build_field in field_map.items():
            val = props.get(prop_key, "")
            lines.append(f"  Build.{build_field}.value = '{val}';")

        lines.append("  var Settings = Java.use('android.provider.Settings$Secure');")
        lines.append(f"  // android_id override: {self.android_id}")

        lines.append("  send({type: 'persona', status: 'applied', model: '" + self.model + "'});")
        lines.append("});")
        return "\n".join(lines)


def generate_persona(seed: str, *, profile_index: int | None = None) -> DevicePersona:
    """Generate a consistent device persona from a seed string."""
    rng = random.Random(hashlib.sha256(seed.encode()).hexdigest())

    if profile_index is not None:
        profile = _DEVICE_PROFILES[profile_index % len(_DEVICE_PROFILES)]
    else:
        profile = rng.choice(_DEVICE_PROFILES)

    carrier = rng.choice(_CARRIERS)

    def _hex(n: int) -> str:
        return "".join(rng.choices("0123456789abcdef", k=n))

    def _digits(n: int) -> str:
        return "".join(rng.choices("0123456789", k=n))

    def _luhn_check_digit(partial: str) -> str:
        digits = [int(d) for d in partial]
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 0:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return str((10 - total % 10) % 10)

    build_id = f"AP2A.{rng.randint(230901, 261231)}.{_digits(3)}"
    build_num = _digits(8)

    imei_base = f"35{_digits(12)}"
    iccid_base = f"8901{_digits(14)}"
    op = carrier["operator"]

    return DevicePersona(
        seed=seed,
        model=profile["model"],
        manufacturer=profile["manufacturer"],
        brand=profile["brand"],
        device=profile["device"],
        product=profile["product"],
        board=profile["board"],
        hardware=profile["hardware"],
        fingerprint=f"{profile['fingerprint_prefix']}{build_id}/{build_num}:user/release-keys",
        android_id=_hex(16),
        imei=imei_base + _luhn_check_digit(imei_base),
        serial_number=f"{profile['device'].upper()[:4]}{_hex(8).upper()}",
        sim_operator=op,
        sim_operator_name=carrier["operator_name"],
        sim_serial=iccid_base + _luhn_check_digit(iccid_base),
        subscriber_id=f"{op}{_digits(15 - len(op))}",
        wifi_mac=":".join(_hex(2) for _ in range(6)),
        bluetooth_mac=":".join(_hex(2) for _ in range(6)),
        build_id=build_id,
        build_display=f"{build_id}.{build_num}",
    )
