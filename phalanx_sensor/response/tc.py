"""
tc (traffic control) actuator — rate-limit a device by MAC.

Uses htb (Hierarchical Token Bucket) and a u32 filter on ether saddr.
Soft response: we don't disconnect the device, we throttle it to a
ceiling kbit/s that makes exfil or DDoS painfully slow.

Each rate-limited MAC gets its own htb class. Class IDs allocated
sequentially as 1:101, 1:102, ... We track mac → classid in state so
unlimit() can clean up.

Requires tc (iproute2) and knowledge of the LAN interface. On a typical
Pi-router this is br0; on a gateway VM with two NICs this is the
internal-network adapter.
"""
from __future__ import annotations
import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("response.tc")


class TcActuator:
    HTB_HANDLE        = "1:"
    DEFAULT_CEIL_KBIT = 64

    def __init__(self, iface: str):
        self._iface       = iface
        self._available   = shutil.which("tc") is not None
        self._next_class  = 101
        self._mac_to_cid: dict[str, str] = {}

        if not self._available:
            log.warning("tc not in PATH; rate-limit actuator disabled")
            return
        if not Path(f"/sys/class/net/{iface}").exists():
            log.warning("interface %s not found", iface)
            self._available = False
            return
        self._install_qdisc()

    @property
    def available(self) -> bool:
        return self._available

    def _install_qdisc(self):
        try:
            res = subprocess.run(
                ["tc", "qdisc", "show", "dev", self._iface],
                capture_output=True, text=True, timeout=3,
            )
            if "htb" in res.stdout and self.HTB_HANDLE in res.stdout:
                return
            subprocess.run(
                ["tc", "qdisc", "add", "dev", self._iface,
                 "root", "handle", "1:", "htb", "default", "1"],
                check=False, capture_output=True,
            )
            subprocess.run(
                ["tc", "class", "add", "dev", self._iface,
                 "parent", "1:", "classid", "1:1",
                 "htb", "rate", "1000mbit"],
                check=False, capture_output=True,
            )
        except Exception as e:
            log.warning("qdisc install: %s", e)

    # ── public ─────────────────────────────────────────────────────────────

    def rate_limit(self, mac: str, kbit: int | None = None) -> bool:
        if not self._available: return False
        mac = mac.lower()
        kbit = kbit or self.DEFAULT_CEIL_KBIT

        if mac in self._mac_to_cid:
            cid = self._mac_to_cid[mac]
            return self._run([
                "tc", "class", "change", "dev", self._iface,
                "parent", "1:", "classid", cid,
                "htb", "rate", f"{kbit}kbit", "ceil", f"{kbit}kbit",
            ])

        cid = f"1:{self._next_class}"
        if not self._run([
            "tc", "class", "add", "dev", self._iface,
            "parent", "1:", "classid", cid,
            "htb", "rate", f"{kbit}kbit", "ceil", f"{kbit}kbit",
        ]):
            return False

        mac_bytes = mac.replace(":", "")
        if len(mac_bytes) != 12:
            log.warning("malformed MAC %s", mac)
            self._run(["tc", "class", "del", "dev", self._iface, "classid", cid])
            return False
        hi = mac_bytes[0:8]
        lo = mac_bytes[8:12]

        if not self._run([
            "tc", "filter", "add", "dev", self._iface, "protocol", "all",
            "parent", "1:", "prio", "1", "u32",
            "match", "u32", f"0x{hi}", "0xffffffff", "at", "-12",
            "match", "u16", f"0x{lo}", "0xffff",     "at", "-8",
            "flowid", cid,
        ]):
            self._run(["tc", "class", "del", "dev", self._iface, "classid", cid])
            return False

        self._mac_to_cid[mac] = cid
        self._next_class += 1
        return True

    def unlimit(self, mac: str) -> bool:
        if not self._available: return False
        mac = mac.lower()
        cid = self._mac_to_cid.get(mac)
        if not cid: return True
        if self._run(["tc", "class", "del", "dev", self._iface, "classid", cid]):
            del self._mac_to_cid[mac]
            return True
        return False

    def list_limited(self) -> dict[str, str]:
        return dict(self._mac_to_cid)

    def _run(self, argv: list[str]) -> bool:
        try:
            res = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                log.warning("tc %s failed: %s", " ".join(argv[1:3]), res.stderr.strip())
                return False
            return True
        except Exception as e:
            log.warning("tc exec: %s", e)
            return False
