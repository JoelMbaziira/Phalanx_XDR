"""
OUI (Organizationally Unique Identifier) lookup.
Maps the first 3 bytes of a MAC address to a manufacturer name.
Uses the IEEE OUI database — embedded subset of the most common vendors.
Falls back to HTTP fetch of full database if needed.
"""

import re
import urllib.request
from functools import lru_cache
from pathlib import Path

# ── Embedded common vendor table (covers ~80% of devices seen in practice) ──

_COMMON_OUI: dict[str, str] = {
    # Apple
    "3C:22:FB": "Apple", "A4:C3:F0": "Apple", "F0:18:98": "Apple",
    "DC:A4:CA": "Apple", "00:CD:FE": "Apple", "BC:92:6B": "Apple",
    "8C:85:90": "Apple", "F4:F1:5A": "Apple", "AC:BC:32": "Apple",
    "00:26:BB": "Apple", "04:4B:ED": "Apple", "3C:D0:F8": "Apple",
    "A8:51:AB": "Apple", "18:AF:61": "Apple", "70:56:81": "Apple",
    "14:5A:05": "Apple", "00:88:65": "Apple", "28:CF:E9": "Apple",
    # Samsung
    "BC:20:BA": "Samsung", "F0:25:B7": "Samsung", "E4:40:E2": "Samsung",
    "8C:C8:CD": "Samsung", "CC:07:AB": "Samsung", "00:26:37": "Samsung",
    "A0:0B:BA": "Samsung", "7C:0B:C6": "Samsung", "50:01:BB": "Samsung",
    # Google
    "54:60:09": "Google", "F4:F5:D8": "Google", "3C:5A:B4": "Google",
    "94:EB:2C": "Google", "A4:77:33": "Google", "48:D6:D5": "Google",
    # Microsoft
    "00:50:F2": "Microsoft", "28:18:78": "Microsoft", "7C:1E:52": "Microsoft",
    "00:17:FA": "Microsoft", "60:45:CB": "Microsoft",
    # Dell
    "F8:DB:88": "Dell",  "18:03:73": "Dell",  "14:18:77": "Dell",
    "B8:CA:3A": "Dell",  "F0:4D:A2": "Dell",  "00:21:70": "Dell",
    # HP / HPE
    "3C:52:82": "HP",    "00:21:5A": "HP",    "FC:15:B4": "HP",
    "D4:85:64": "HP",    "10:60:4B": "HP",    "A0:B3:CC": "HPE",
    # Lenovo
    "04:7B:CB": "Lenovo", "34:17:EB": "Lenovo", "50:E5:49": "Lenovo",
    "8C:8D:28": "Lenovo", "D4:81:D7": "Lenovo",
    # Huawei
    "00:46:4B": "Huawei", "48:DB:50": "Huawei", "54:89:98": "Huawei",
    "3C:47:11": "Huawei", "28:31:52": "Huawei", "BC:76:70": "Huawei",
    # Xiaomi
    "28:6C:07": "Xiaomi", "F4:8B:32": "Xiaomi", "8C:BE:BE": "Xiaomi",
    "64:09:80": "Xiaomi", "AC:C1:EE": "Xiaomi",
    # Raspberry Pi / Pi Foundation
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # Intel (Wi-Fi chipsets in many laptops)
    "00:15:17": "Intel",  "8C:EC:4B": "Intel",  "10:02:B5": "Intel",
    "78:92:9C": "Intel",  "38:BA:F8": "Intel",
    "00:23:14": "Intel",
    # Qualcomm / Atheros (Wi-Fi chipsets)
    "00:26:5A": "Qualcomm", "E0:91:F5": "Qualcomm",
    # Cisco / Meraki
    "00:0C:85": "Cisco",  "00:1A:2F": "Cisco",  "F8:72:EA": "Cisco",
    "58:AC:78": "Cisco",  "00:1B:2B": "Cisco Meraki",
    # TP-Link
    "10:FE:ED": "TP-Link", "54:C8:0F": "TP-Link", "00:27:19": "TP-Link",
    "74:DA:38": "TP-Link", "90:F6:52": "TP-Link",
    # Ubiquiti
    "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti", "68:72:51": "Ubiquiti",
    "24:A4:3C": "Ubiquiti", "78:8A:20": "Ubiquiti",
    # MikroTik
    "4C:5E:0C": "MikroTik", "CC:2D:E0": "MikroTik", "00:0C:42": "MikroTik",
    "74:4D:28": "MikroTik",
    # Amazon (Echo, Kindle, Fire)
    "40:B4:CD": "Amazon",  "74:C2:46": "Amazon",  "FC:65:DE": "Amazon",
    "A4:08:F5": "Amazon",  "00:FC:8B": "Amazon",
    # VMware (VMs on the network)
    "00:0C:29": "VMware",  "00:50:56": "VMware",  "00:05:69": "VMware",
    # VirtualBox
    "08:00:27": "VirtualBox",
    # Realtek (common NIC chipset)
    "00:E0:4C": "Realtek", "52:54:00": "QEMU/KVM",
    # Generic / IoT
    "00:1A:22": "Dell",    "AC:DE:48": "Private",
}

_FULL_OUI_PATH = Path("/var/lib/phalanx/oui.txt")
_FULL_OUI_URL  = "https://standards-oui.ieee.org/oui/oui.txt"
_full_db: dict[str, str] = {}
_full_loaded = False


def _normalise_mac_prefix(mac: str) -> str:
    """Return uppercase colon-separated 3-byte prefix, e.g. 'AA:BB:CC'."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) < 6:
        return ""
    return ":".join(clean[i:i+2].upper() for i in range(0, 6, 2))


def _try_load_full_db():
    global _full_db, _full_loaded
    if _full_loaded:
        return
    _full_loaded = True
    if not _FULL_OUI_PATH.exists():
        return
    try:
        for line in _FULL_OUI_PATH.read_text(errors="replace").splitlines():
            # Format: "AA-BB-CC   (hex)\t\tVendor Name"
            m = re.match(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line)
            if m:
                key = m.group(1).replace("-", ":")
                _full_db[key] = m.group(2).strip()
    except Exception:
        pass


def fetch_oui_database() -> bool:
    """Download the full IEEE OUI database. Call once during setup."""
    try:
        _FULL_OUI_PATH.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(_FULL_OUI_URL, str(_FULL_OUI_PATH))

        global _full_loaded
        _full_loaded = False   # force reload
        lookup.cache_clear()   # avoid stale "Unknown" entries from before the fetch
        return True
    except Exception as e:
        print(f"[oui] Could not fetch OUI database: {e}")
        return False


@lru_cache(maxsize=4096)
def lookup(mac: str) -> str:
    """
    Return manufacturer name for a MAC address.
    Falls back through: common table → full IEEE DB → 'Unknown'.
    """
    prefix = _normalise_mac_prefix(mac)
    if not prefix:
        return "Unknown"

    # 1. Common embedded table (fast path)
    if prefix in _COMMON_OUI:
        return _COMMON_OUI[prefix]

    # 2. Full IEEE database (if downloaded)
    _try_load_full_db()
    if prefix in _full_db:
        return _full_db[prefix]

    return "Unknown"


def device_type_hint(manufacturer: str) -> str:
    """
    Coarse device-type guess from manufacturer name.
    Used for grouping and display only — not security decisions.
    """
    m = manufacturer.lower()
    if any(x in m for x in ("apple",)):
        return "Apple device"
    if any(x in m for x in ("samsung", "xiaomi", "huawei", "oneplus", "oppo")):
        return "Android device"
    if any(x in m for x in ("raspberry",)):
        return "Raspberry Pi"
    if any(x in m for x in ("vmware", "virtualbox", "qemu")):
        return "Virtual machine"
    if any(x in m for x in ("cisco", "meraki", "ubiquiti", "mikrotik", "tp-link")):
        return "Network device"
    if any(x in m for x in ("intel", "realtek", "qualcomm", "broadcom")):
        return "PC / laptop"
    if any(x in m for x in ("amazon",)):
        return "Amazon device"
    if any(x in m for x in ("dell", "hp", "lenovo", "microsoft", "asus", "acer")):
        return "PC / laptop"
    return "Unknown"
