"""
DNS sniffer — captures every DNS query and response from every device.

Uses raw AF_PACKET socket (Linux) or pcap. No agent needed on endpoints.
Parses DNS wire format directly — no external library required.

Emits per-query events including:
  - Which device asked (MAC + IP)
  - What domain was queried
  - Query type (A, AAAA, MX, TXT, etc.)
  - Response IPs (if captured)
  - DGA score (is this domain algorithmically generated?)
  - DNS tunnelling indicators
"""

from __future__ import annotations
import datetime
import math
import re
import socket
import struct
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable


# ─────────────────────────────────────────────────────────────────────────────
# DNS wire format parser
# ─────────────────────────────────────────────────────────────────────────────

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
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


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name with pointer compression. Returns (name, new_offset)."""
    labels = []
    visited = set()

    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)

        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Pointer compression.
            # A pointer can appear after one or more real labels, e.g.
            # "www." + pointer-to-"example.com", so append the pointed-to name
            # to the labels we already collected instead of replacing them.
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr >= len(data):
                break

            pointed_name, _ = _parse_name(data, ptr)
            if pointed_name:
                labels.append(pointed_name)

            # The caller should continue after the pointer in the current name.
            offset += 2
            break
        else:
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

    return ".".join(labels), offset


def _parse_dns(payload: bytes) -> dict | None:
    """
    Parse a DNS message from raw UDP payload.
    Returns a dict with query/response details, or None if parse fails.
    """
    if len(payload) < 12:
        return None
    try:
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])
    except struct.error:
        return None

    qr     = (flags >> 15) & 1      # 0=query, 1=response
    opcode = (flags >> 11) & 0xF
    rcode  = flags & 0xF

    offset  = 12
    questions = []
    answers   = []

    # Parse questions
    for _ in range(qdcount):
        if offset >= len(payload):
            break
        try:
            name, offset = _parse_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])
            offset += 4
            questions.append({
                "name":  name,
                "type":  QTYPE_NAMES.get(qtype, str(qtype)),
                "class": qclass,
            })
        except Exception:
            break

    # Parse answers (responses only)
    if qr == 1:
        for _ in range(ancount):
            if offset >= len(payload):
                break
            try:
                name, offset = _parse_name(payload, offset)
                if offset + 10 > len(payload):
                    break
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", payload[offset:offset + 10])
                offset += 10
                if offset + rdlen > len(payload):
                    break

                rdata = payload[offset:offset + rdlen]
                offset += rdlen

                answer: dict = {
                    "name": name,
                    "type": QTYPE_NAMES.get(rtype, str(rtype)),
                    "ttl":  ttl,
                }
                if rtype == 1 and rdlen == 4:      # A record
                    answer["ip"] = socket.inet_ntoa(rdata)
                elif rtype == 28 and rdlen == 16:   # AAAA record
                    answer["ip"] = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype == 5:                    # CNAME
                    cname, _ = _parse_name(payload, offset - rdlen)
                    answer["cname"] = cname

                answers.append(answer)
            except Exception:
                break

    return {
        "txid":      txid,
        "qr":        qr,
        "rcode":     RCODE_NAMES.get(rcode, str(rcode)),
        "questions": questions,
        "answers":   answers,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DGA detection — domain generation algorithm scoring
# ─────────────────────────────────────────────────────────────────────────────

# Known legitimate high-entropy domains (whitelisted)
_WHITELIST_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    "microsoft.com", "windows.com", "live.com", "microsoftonline.com",
    "apple.com", "icloud.com", "akamai.net", "akamaiedge.net",
    "cloudflare.com", "fastly.net", "cdn.net",
    "ubuntu.com", "debian.org", "github.com", "githubusercontent.com",
}

def _domain_entropy(domain: str) -> float:
    """Shannon entropy of the subdomain label (higher = more random)."""
    label = domain.split(".")[0] if "." in domain else domain
    if not label:
        return 0.0
    freq = defaultdict(int)
    for c in label:
        freq[c] += 1
    total = len(label)
    return -sum((v / total) * math.log2(v / total) for v in freq.values())


def _consonant_ratio(s: str) -> float:
    consonants = sum(1 for c in s.lower() if c in "bcdfghjklmnpqrstvwxyz")
    return consonants / len(s) if s else 0.0


def dga_score(domain: str) -> float:
    """
    Returns 0.0 (definitely legit) to 1.0 (almost certainly DGA).
    Combines: entropy, consonant ratio, digit ratio, length, n-gram analysis.
    """
    # Strip to registrable domain (last two labels)
    parts = domain.rstrip(".").lower().split(".")
    if len(parts) >= 2:
        tld         = parts[-1]
        registrable = parts[-2]
    else:
        registrable = parts[0]
        tld         = ""

    # Whitelist
    base = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    if base in _WHITELIST_DOMAINS:
        return 0.0

    label  = registrable
    length = len(label)

    if length < 6:
        return 0.0    # too short to be DGA

    # Feature scores
    ent      = _domain_entropy(label)        # DGA typically > 3.5
    cons     = _consonant_ratio(label)       # DGA typically > 0.65
    digit_r  = sum(c.isdigit() for c in label) / length   # DGA often high
    has_nums = any(c.isdigit() for c in label)

    # Common DGA patterns
    looks_random = (
        ent > 3.5 and
        cons > 0.60 and
        length > 10 and
        not re.search(r"(news|mail|shop|store|blog|app|api|cdn|img|static)", label)
    )

    score = 0.0
    if ent > 4.0:          score += 0.35
    elif ent > 3.5:        score += 0.20
    if cons > 0.70:        score += 0.20
    elif cons > 0.60:      score += 0.10
    if length > 20:        score += 0.15
    elif length > 15:      score += 0.08
    if digit_r > 0.3:      score += 0.10
    if looks_random:       score += 0.20

    return min(1.0, score)


# ─────────────────────────────────────────────────────────────────────────────
# DNS tunnelling detection
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _TunnelTracker:
    query_count:  int   = 0
    last_reset:   float = field(default_factory=time.time)
    total_labels: int   = 0   # sum of label lengths — tunnelling uses very long labels
    txt_count:    int   = 0   # TXT queries can carry data


def _is_tunnelling(label: str, qtype: str, tracker: _TunnelTracker) -> bool:
    """
    Heuristics for DNS tunnelling (iodine, dnscat2, etc.)
    - Very long subdomain labels (>40 chars)
    - High rate of TXT queries
    - Base32/Base64-looking labels
    - Many queries per second to the same domain
    """
    tracker.query_count += 1
    tracker.total_labels += len(label)
    if qtype == "TXT":
        tracker.txt_count += 1

    avg_label_len = tracker.total_labels / max(1, tracker.query_count)

    # Reset counters every 60 seconds
    now = time.time()
    if now - tracker.last_reset > 60:
        tracker.query_count  = 0
        tracker.total_labels = 0
        tracker.txt_count    = 0
        tracker.last_reset   = now
        return False

    if len(label) > 50:
        return True
    if avg_label_len > 35 and tracker.query_count > 10:
        return True
    if tracker.txt_count > 20 and tracker.query_count > 30:
        return True
    if re.match(r"^[a-z2-7]{20,}$", label.lower()):   # base32
        return True
    if re.match(r"^[a-zA-Z0-9+/]{30,}$", label):       # base64-like
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# DNS event
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DnsEvent:
    timestamp:   float
    src_mac:     str
    src_ip:      str
    dst_ip:      str
    domain:      str
    qtype:       str
    qr:          int          # 0=query, 1=response
    txid:        int
    answers:     list[dict]
    rcode:       str
    dga_score:   float
    is_tunnel:   bool
    agent_id:    str
    sensor_host: str

    def to_event(self) -> dict:
        ts = datetime.datetime.utcfromtimestamp(self.timestamp).isoformat() + "Z"
        flags = []
        if self.dga_score > 0.6:
            flags.append(f"dga_score:{self.dga_score:.2f}")
        if self.is_tunnel:
            flags.append("dns_tunnel")

        return {
            "@timestamp": ts,
            "event": {
                "id":       str(uuid.uuid4()),
                "kind":     "event",
                "category": ["network"],
                "type":     ["connection"],
                "action":   "dns_query" if self.qr == 0 else "dns_response",
                "dataset":  "phalanx.sensor.dns",
                "flags":    flags,
            },
            "agent":   {"id": self.agent_id, "type": "phalanx-sensor-node"},
            "host":    {"hostname": self.sensor_host},
            "source":  {"ip": self.src_ip, "mac": self.src_mac},
            "destination": {"ip": self.dst_ip, "port": 53},
            "dns": {
                "type":     "query" if self.qr == 0 else "answer",
                "question": {"name": self.domain, "type": self.qtype},
                "answers":  self.answers,
                "rcode":    self.rcode,
                "txid":     self.txid,
                "dga_score": self.dga_score,
                "is_tunnel": self.is_tunnel,
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# DNS sniffer
# ─────────────────────────────────────────────────────────────────────────────

class DnsSniffer:
    """
    Captures DNS traffic using a raw socket bound to the given interface.
    Works in both inline (bridge) and passive (listen-only) modes.

    Usage:
        sniffer = DnsSniffer("br0", agent_id="...", sensor_host="sensor-1")
        sniffer.on_event(lambda ev: ship(ev))
        sniffer.on_event(lambda ev: registry.update_dns_fingerprint(ev.src_mac, ev.domain))
        sniffer.start()
    """

    def __init__(self, interface: str, agent_id: str, sensor_host: str):
        self._iface       = interface
        self._agent_id    = agent_id
        self._sensor_host = sensor_host
        self._callbacks:  list[Callable[[DnsEvent], None]] = []
        self._running     = False
        self._thread:     threading.Thread | None = None

        # Per-domain tunnel trackers (domain → tracker)
        self._tunnel_trackers: dict[str, _TunnelTracker] = defaultdict(_TunnelTracker)

    def on_event(self, cb: Callable[[DnsEvent], None]):
        self._callbacks.append(cb)

    def _emit(self, ev: DnsEvent):
        for cb in self._callbacks:
            try:
                cb(ev)
            except Exception:
                pass

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._capture_loop, daemon=True,
                                          name="dns-sniffer")
        self._thread.start()

    def stop(self):
        self._running = False

    def _capture_loop(self):
        """
        Raw socket capture loop.
        ETH_P_IP = 0x0800. We filter for UDP port 53 in software.
        Requires root / CAP_NET_RAW.
        """
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0800))
            sock.bind((self._iface, 0))
            sock.settimeout(1.0)
        except PermissionError:
            print("[dns-sniffer] ERROR: root / CAP_NET_RAW required")
            return
        except OSError as e:
            print(f"[dns-sniffer] ERROR binding to {self._iface}: {e}")
            return

        print(f"[dns-sniffer] Listening on {self._iface}")

        while self._running:
            try:
                raw, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                continue

            self._process_packet(raw, time.time())

        sock.close()

    def _process_packet(self, raw: bytes, ts: float):
        """Parse Ethernet → IP → UDP → DNS."""
        # Ethernet header: 14 bytes (dst_mac 6 + src_mac 6 + ethertype 2)
        if len(raw) < 42:   # 14 eth + 20 ip + 8 udp = 42 minimum
            return

        # Source MAC
        src_mac_bytes = raw[6:12]
        src_mac = ":".join(f"{b:02X}" for b in src_mac_bytes)

        # EtherType must be IPv4 (0x0800)
        ethertype = struct.unpack("!H", raw[12:14])[0]
        if ethertype != 0x0800:
            return

        # IP header
        ip_start = 14
        if not _is_valid_ipv4_header(raw, ip_start):
            return

        ip_ihl     = (raw[ip_start] & 0x0F) * 4
        ip_proto   = raw[ip_start + 9]
        src_ip     = socket.inet_ntoa(raw[ip_start + 12:ip_start + 16])
        dst_ip     = socket.inet_ntoa(raw[ip_start + 16:ip_start + 20])

        # Must be UDP (17)
        if ip_proto != 17:
            return

        udp_start = ip_start + ip_ihl
        if len(raw) < udp_start + 8:
            return

        udp_len = struct.unpack("!H", raw[udp_start + 4:udp_start + 6])[0]
        if udp_len < 8:
            return

        ip_total_len = struct.unpack("!H", raw[ip_start + 2:ip_start + 4])[0]
        if udp_len > ip_total_len - ip_ihl:
            return

        src_port = struct.unpack("!H", raw[udp_start:udp_start + 2])[0]
        dst_port = struct.unpack("!H", raw[udp_start + 2:udp_start + 4])[0]

        # Must be DNS (port 53 either direction)
        if dst_port != 53 and src_port != 53:
            return

        dns_payload = raw[udp_start + 8:udp_start + udp_len]
        parsed      = _parse_dns(dns_payload)
        if not parsed or not parsed["questions"]:
            return

        q      = parsed["questions"][0]
        domain = q["name"].rstrip(".")
        qtype  = q["type"]

        # DGA analysis
        dgascore = dga_score(domain)

        # Tunnel detection
        label   = domain.split(".")[0] if "." in domain else domain
        base    = ".".join(domain.split(".")[-2:]) if "." in domain else domain
        tracker = self._tunnel_trackers[base]
        tunnel  = _is_tunnelling(label, qtype, tracker)

        ev = DnsEvent(
            timestamp   = ts,
            src_mac     = src_mac,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            domain      = domain,
            qtype       = qtype,
            qr          = parsed["qr"],
            txid        = parsed["txid"],
            answers     = parsed["answers"],
            rcode       = parsed["rcode"],
            dga_score   = dgascore,
            is_tunnel   = tunnel,
            agent_id    = self._agent_id,
            sensor_host = self._sensor_host,
        )
        self._emit(ev)
