"""MAC OUI -> vendor lookup with an embedded mini-database of common IoT brands.

The full IEEE OUI database is ~30k entries; we ship a curated subset of brands
that overwhelmingly appear on consumer/SOHO IoT networks. Users can extend
``data/oui.txt`` with the standard ``XX:XX:XX  VendorName`` format.
"""
from __future__ import annotations

import os
from functools import lru_cache

# Curated subset of IoT-relevant OUIs. Format: first 3 octets uppercase, no separators.
_BUILTIN_OUI: dict[str, str] = {
    # Amazon (Echo, Ring, Fire TV)
    "FCA183": "Amazon",
    "44650D": "Amazon",
    "F0D2F1": "Amazon",
    "747548": "Amazon",
    # Google (Nest, Chromecast, Home)
    "F4F5D8": "Google",
    "A4DA22": "Google",
    "6466B3": "Google",
    "1C3947": "Google",
    # Apple
    "3C0754": "Apple",
    "F0D1A9": "Apple",
    "A4B197": "Apple",
    # TP-Link / Kasa
    "501FC6": "TP-Link",
    "98DAC4": "TP-Link",
    "AC84C6": "TP-Link",
    # Belkin / Wemo
    "08863B": "Belkin",
    "94103E": "Belkin",
    # Philips Hue
    "00178A": "Philips Lighting",
    "ECB5FA": "Philips Lighting",
    # Sonos
    "B8E937": "Sonos",
    "5CAAFD": "Sonos",
    # Roku
    "CC6DA0": "Roku",
    "D83134": "Roku",
    # Wyze
    "2CAA8E": "Wyze",
    "7C78B2": "Wyze",
    # Ring
    "B0095A": "Ring",
    # Nest
    "18B430": "Nest Labs",
    "64166D": "Nest Labs",
    # Samsung SmartThings / appliances
    "E848B8": "Samsung",
    "F0728C": "Samsung",
    # Xiaomi
    "F8A45F": "Xiaomi",
    "286C07": "Xiaomi",
    # Tuya (powers many no-name smart plugs)
    "DC4F22": "Tuya",
    "D8F15B": "Tuya",
    # Hikvision / Dahua (cameras/DVRs)
    "BC078D": "Hikvision",
    "C0511C": "Hikvision",
    "3CEF8C": "Dahua",
    # Ubiquiti
    "245A4C": "Ubiquiti",
    "B4FBE4": "Ubiquiti",
    # Espressif (ESP32/ESP8266 - DIY IoT)
    "240AC4": "Espressif",
    "EC64C9": "Espressif",
    "84F3EB": "Espressif",
    # Raspberry Pi
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    # ASUS, Netgear, Linksys (routers/APs)
    "508140": "ASUS",
    "9C5C8E": "ASUS",
    "C40415": "Netgear",
    "C0FFD4": "Netgear",
    "C8D7B0": "Linksys",
}


def _normalize(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "").replace(".", "")[:6]


@lru_cache(maxsize=1)
def _load_user_oui() -> dict[str, str]:
    """Load optional user-provided OUI extensions from data/oui.txt."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "oui.txt",
    )
    mapping: dict[str, str] = {}
    if not os.path.exists(path):
        return mapping
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            oui = _normalize(parts[0])
            if len(oui) == 6:
                mapping[oui] = parts[1].strip()
    return mapping


def lookup_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    key = _normalize(mac)
    if len(key) < 6:
        return None
    user = _load_user_oui()
    return user.get(key) or _BUILTIN_OUI.get(key)
