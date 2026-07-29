"""
DHCP watcher — captures DHCP traffic to detect new devices immediately.

DHCP is the first thing a device does when it joins a network.
Before it has an IP, before it makes any DNS query — it sends a DHCP Discover.
This gives us: MAC address, requested hostname, vendor class (OS hint),
parameter request list (another OS fingerprint), and the IP it's assigned.

No agent needed. Works on every device that uses DHCP (which is everything).
"""

from __future__ import annotations
import datetime
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable


# ─────────────────────────────────────────────────────────────────────────────
# DHCP message parser
# ─────────────────────────────────────────────────────────────────────────────

# DHCP option numbers
OPT_SUBNET          = 1
OPT_ROUTER          = 3
OPT_DNS             = 6
OPT_HOSTNAME        = 12
OPT_VENDOR_CLASS    = 60
OPT_REQUESTED_IP    = 50
OPT_MSG_TYPE        = 53
OPT_SERVER_ID       = 54
OPT_PARAM_LIST      = 55
OPT_LEASE_TIME      = 51
OPT_END             = 255

# Message type values
DHCP_DISCOVER = 1
DHCP_OFFER    = 2
DHCP_REQUEST  = 3
DHCP_DECLINE  = 4
DHCP_ACK      = 5
DHCP_NAK      = 6
DHCP_RELEASE  = 7
DHCP_INFORM   = 8

DHCP_TYPE_NAMES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}


def _is_valid_ipv4_header(raw: bytes, offset: int) -> bool:
    """Validate the IPv4 header before trusting offsets from it."""
    if len(raw) < offset + 20:
        return False
    if (raw[offset] >> 4) != 4:
        return False

    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20:
        return False
    if len(raw) < offset + ihl:
        return False

    try:
        ip_len = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
    except struct.error:
        return False

    return ip_len >= ihl and len(raw) >= offset + ip_len


def _parse_dhcp(payload: bytes) -> dict | None:
    """
    Parse a DHCP message from raw UDP payload.
    DHCP header is 236 bytes + options.
    """
    if len(payload) < 240:
        return None

    try:
        op, htype, hlen, hops = struct.unpack("BBBB", payload[:4])
        xid      = struct.unpack("!I", payload[4:8])[0]
        secs     = struct.unpack("!H", payload[8:10])[0]
        flags    = struct.unpack("!H", payload[10:12])[0]
        ciaddr   = socket.inet_ntoa(payload[12:16])   # client IP (if renewing)
        yiaddr   = socket.inet_ntoa(payload[16:20])   # your (offered) IP
        siaddr   = socket.inet_ntoa(payload[20:24])   # server IP
        giaddr   = socket.inet_ntoa(payload[24:28])   # relay agent IP

        # Client MAC (first hlen bytes of chaddr field, which is 16 bytes)
        chaddr   = payload[28:28 + min(hlen, 16)]
        mac      = ":".join(f"{b:02X}" for b in chaddr[:6])
    except Exception:
        return None

    # Magic cookie must be 0x63825363
    if payload[236:240] != b"\x63\x82\x53\x63":
        return None

    # Parse options
    opts: dict[int, bytes] = {}
    i = 240
    while i < len(payload):
        opt_code = payload[i]
        if opt_code == OPT_END:
            break
        if opt_code == 0:   # pad
            i += 1
            continue
        if i + 1 >= len(payload):
            break
        opt_len = payload[i + 1]
        if i + 2 + opt_len > len(payload):
            break

        # Zero-length options are valid; don't assume a first byte exists.
        opts[opt_code] = payload[i + 2:i + 2 + opt_len]
        i += 2 + opt_len

    # Extract key fields
    msg_type_data = opts.get(OPT_MSG_TYPE, b"")
    msg_type = msg_type_data[0] if msg_type_data else 0
    hostname    = opts.get(OPT_HOSTNAME, b"").decode("ascii", errors="replace")
    vendor_cls  = opts.get(OPT_VENDOR_CLASS, b"").decode("ascii", errors="replace")
    param_list  = list(opts.get(OPT_PARAM_LIST, b""))
    requested_ip = ""
    if OPT_REQUESTED_IP in opts and len(opts[OPT_REQUESTED_IP]) == 4:
        requested_ip = socket.inet_ntoa(opts[OPT_REQUESTED_IP])
    lease_time = 0
    if OPT_LEASE_TIME in opts and len(opts[OPT_LEASE_TIME]) == 4:
        lease_time = struct.unpack("!I", opts[OPT_LEASE_TIME])[0]

    return {
        "op":           op,         # 1=request, 2=reply
        "xid":          xid,
        "mac":          mac,
        "ciaddr":       ciaddr,
        "yiaddr":       yiaddr,     # offered IP
        "siaddr":       siaddr,
        "giaddr":       giaddr,
        "msg_type":     msg_type,
        "msg_type_str": DHCP_TYPE_NAMES.get(msg_type, str(msg_type)),
        "hostname":     hostname,
        "vendor_class": vendor_cls,
        "param_list":   param_list,
        "requested_ip": requested_ip,
        "lease_time":   lease_time,
    }


# ─────────────────────────────────────────────────────────────────────────────
# OS fingerprinting from DHCP parameter request list
# ─────────────────────────────────────────────────────────────────────────────
# The parameter request list (option 55) is the list of DHCP options
# the client wants the server to include in the offer. Different OS
# implementations request different options in different orders.
# This is surprisingly accurate.

# (frozenset_of_params, os_family, confidence)
_DHCP_OS_SIGS: list[tuple[frozenset, str, float]] = [
    (frozenset({1, 3, 6, 15, 119, 95, 252, 44, 46, 47}),
     "Windows 10/11", 0.88),
    (frozenset({1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252}),
     "Windows 7/8", 0.82),
    (frozenset({1, 121, 3, 6, 15, 119, 252}),
     "macOS", 0.90),
    (frozenset({1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42}),
     "Linux (dhclient)", 0.85),
    (frozenset({1, 3, 6, 12, 15, 28, 40, 41, 42}),
     "Linux (udhcpc/BusyBox)", 0.82),
    (frozenset({1, 3, 6, 15, 119, 95, 252, 44}),
     "iOS", 0.86),
    (frozenset({1, 3, 6, 15, 26, 28, 51, 58, 59}),
     "Android", 0.84),
    (frozenset({1, 3, 6, 12, 44, 46, 47}),
     "Windows XP", 0.80),
]


def fingerprint_dhcp_params(param_list: list[int]) -> tuple[str, float]:
    """Returns (os_guess, confidence) from DHCP option 55."""
    if not param_list:
        return "Unknown", 0.0

    pset     = frozenset(param_list)
    best_os  = "Unknown"
    best_conf = 0.0

    for (sig, os_name, conf) in _DHCP_OS_SIGS:
        overlap = len(sig & pset) / len(sig) if sig else 0
        score   = conf * overlap
        if score > best_conf:
            best_conf = score
            best_os   = os_name

    return best_os, round(best_conf, 2)


# Vendor class string → OS hint
_VENDOR_CLASS_HINTS: list[tuple[str, str]] = [
    ("MSFT 5.0",        "Windows"),
    ("android-dhcp",    "Android"),
    ("dhcpcd",          "Linux"),
    ("udhcp",           "Linux (BusyBox)"),
    ("iPhone",          "iOS"),
    ("iPad",            "iOS"),
    ("Apple",           "macOS/iOS"),
    ("Cisco",           "Cisco device"),
    ("Raspberry",       "Raspberry Pi"),
    ("OpenWrt",         "OpenWrt router"),
]


def fingerprint_vendor_class(vendor_cls: str) -> str:
    for (pattern, os_name) in _VENDOR_CLASS_HINTS:
        if pattern.lower() in vendor_cls.lower():
            return os_name
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# DHCP event
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DhcpEvent:
    timestamp:    float
    mac:          str
    msg_type:     str
    assigned_ip:  str
    requested_ip: str
    hostname:     str
    vendor_class: str
    os_guess:     str
    os_confidence: float
    lease_time:   int
    agent_id:     str
    sensor_host:  str

    def to_event(self) -> dict:
        ts = datetime.datetime.utcfromtimestamp(self.timestamp).isoformat() + "Z"
        return {
            "@timestamp": ts,
            "event": {
                "id":       str(uuid.uuid4()),
                "kind":     "event",
                "category": ["network"],
                "type":     ["connection"],
                "action":   f"dhcp_{self.msg_type.lower()}",
                "dataset":  "phalanx.sensor.dhcp",
            },
            "agent": {"id": self.agent_id, "type": "phalanx-sensor-node"},
            "host":  {"hostname": self.sensor_host},
            "source": {
                "mac":      self.mac,
                "ip":       self.assigned_ip or self.requested_ip,
            },
            "dhcp": {
                "msg_type":      self.msg_type,
                "assigned_ip":   self.assigned_ip,
                "requested_ip":  self.requested_ip,
                "hostname":      self.hostname,
                "vendor_class":  self.vendor_class,
                "lease_time":    self.lease_time,
                "os_guess":      self.os_guess,
                "os_confidence": self.os_confidence,
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# DHCP watcher
# ─────────────────────────────────────────────────────────────────────────────

class DhcpWatcher:
    """
    Captures DHCP traffic on the given interface.

    On DHCP DISCOVER/REQUEST: immediately registers the device (MAC → hostname)
    On DHCP ACK: records the assigned IP and OS guess

    Usage:
        watcher = DhcpWatcher("br0", agent_id="...", sensor_host="node-1")
        watcher.on_event(lambda ev: ...)
        watcher.start()
    """

    def __init__(self, interface: str, agent_id: str, sensor_host: str):
        self._iface       = interface
        self._agent_id    = agent_id
        self._sensor_host = sensor_host
        self._callbacks:  list[Callable[[DhcpEvent], None]] = []
        self._running     = False
        self._thread:     threading.Thread | None = None

        # xid → partial info (for matching DISCOVER→ACK)
        self._pending: dict[int, dict] = {}

    def on_event(self, cb: Callable[[DhcpEvent], None]):
        self._callbacks.append(cb)

    def _emit(self, ev: DhcpEvent):
        for cb in self._callbacks:
            try:
                cb(ev)
            except Exception:
                pass

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._capture_loop, daemon=True,
                                          name="dhcp-watcher")
        self._thread.start()

    def stop(self):
        self._running = False

    def _capture_loop(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0800))
            sock.bind((self._iface, 0))
            sock.settimeout(1.0)
        except PermissionError:
            print("[dhcp-watcher] ERROR: root / CAP_NET_RAW required")
            return
        except OSError as e:
            print(f"[dhcp-watcher] ERROR binding to {self._iface}: {e}")
            return

        print(f"[dhcp-watcher] Listening on {self._iface}")

        while self._running:
            try:
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                continue
            self._process_packet(raw, time.time())

        sock.close()

    def _process_packet(self, raw: bytes, ts: float):
        if len(raw) < 42:
            return

        # Ethernet
        ethertype = struct.unpack("!H", raw[12:14])[0]
        if ethertype != 0x0800:
            return

        # IP
        ip_start  = 14
        if not _is_valid_ipv4_header(raw, ip_start):
            return

        ip_ihl    = (raw[ip_start] & 0x0F) * 4
        ip_proto  = raw[ip_start + 9]
        if ip_proto != 17:    # UDP only
            return

        # UDP
        udp_start = ip_start + ip_ihl
        if len(raw) < udp_start + 8:
            return

        udp_len = struct.unpack("!H", raw[udp_start + 4:udp_start + 6])[0]
        if udp_len < 8:
            return

        ip_total_len = struct.unpack("!H", raw[ip_start + 2:ip_start + 4])[0]
        if udp_len > ip_total_len - ip_ihl:
            return

        src_port, dst_port = struct.unpack("!HH", raw[udp_start:udp_start + 2] +
                                            raw[udp_start + 2:udp_start + 4])

        # DHCP runs on UDP 67 (server) / 68 (client)
        if dst_port not in (67, 68) and src_port not in (67, 68):
            return

        dhcp_payload = raw[udp_start + 8:udp_start + udp_len]
        parsed       = _parse_dhcp(dhcp_payload)
        if not parsed:
            return

        msg_type = parsed["msg_type"]
        mac      = parsed["mac"]
        xid      = parsed["xid"]

        # OS fingerprinting
        os_guess, os_conf = fingerprint_dhcp_params(parsed["param_list"])
        if not os_guess or os_guess == "Unknown":
            vc_hint = fingerprint_vendor_class(parsed["vendor_class"])
            if vc_hint:
                os_guess = vc_hint
                os_conf  = 0.70

        # Store pending info on DISCOVER/REQUEST
        if msg_type in (DHCP_DISCOVER, DHCP_REQUEST):
            self._pending[xid] = {
                "mac":          mac,
                "hostname":     parsed["hostname"],
                "vendor_class": parsed["vendor_class"],
                "os_guess":     os_guess,
                "os_conf":      os_conf,
            }

        # Emit event for interesting message types
        if msg_type in (DHCP_DISCOVER, DHCP_REQUEST, DHCP_ACK, DHCP_RELEASE):
            # For ACK, merge with pending
            pending = self._pending.pop(xid, {})
            hostname     = parsed["hostname"] or pending.get("hostname", "")
            vendor_class = parsed["vendor_class"] or pending.get("vendor_class", "")
            if not os_guess or os_guess == "Unknown":
                os_guess = pending.get("os_guess", "Unknown")
                os_conf  = pending.get("os_conf",  0.0)

            ev = DhcpEvent(
                timestamp     = ts,
                mac           = mac,
                msg_type      = parsed["msg_type_str"],
                assigned_ip   = parsed["yiaddr"] if parsed["yiaddr"] != "0.0.0.0" else "",
                requested_ip  = parsed["requested_ip"],
                hostname      = hostname,
                vendor_class  = vendor_class,
                os_guess      = os_guess,
                os_confidence = os_conf,
                lease_time    = parsed["lease_time"],
                agent_id      = self._agent_id,
                sensor_host   = self._sensor_host,
            )
            self._emit(ev)
