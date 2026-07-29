"""
Passive OS fingerprinting — no packets sent to the target.

Three methods, combined for confidence:
  1. TCP/IP stack fingerprinting (p0f-style) — TTL, window size, TCP options
  2. DNS behaviour fingerprinting — query patterns unique to each OS
  3. JA3 TLS fingerprinting — cipher suite combinations identify client library

Results are probabilistic. Confidence is 0.0–1.0.
"""

from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OsGuess:
    os_family:   str   = "Unknown"      # Windows | Linux | macOS | iOS | Android
    os_version:  str   = ""             # e.g. "10/11", "Ubuntu 22.x", "iOS 16/17"
    device_type: str   = "Unknown"      # Laptop | Phone | Server | Router | IoT
    confidence:  float = 0.0            # 0.0 – 1.0
    method:      str   = ""             # tcp | dns | ja3 | combined

    def __str__(self) -> str:
        ver  = f" {self.os_version}" if self.os_version else ""
        conf = f" ({int(self.confidence*100)}%)"
        return f"{self.os_family}{ver}{conf}"


@dataclass
class DeviceFingerprint:
    """Accumulated fingerprint evidence for one IP address."""
    ip: str
    tcp_guess:  OsGuess | None = None
    dns_guess:  OsGuess | None = None
    ja3_guess:  OsGuess | None = None

    # Raw evidence
    ttl_samples:        list[int]        = field(default_factory=list)
    window_sizes:       list[int]        = field(default_factory=list)
    tcp_options_seen:   list[str]        = field(default_factory=list)
    dns_queries:        list[str]        = field(default_factory=list)
    ja3_hashes:         list[str]        = field(default_factory=list)
    user_agents:        list[str]        = field(default_factory=list)

    def combined(self) -> OsGuess:
        """Merge all evidence into a single best guess."""
        guesses = [g for g in (self.tcp_guess, self.dns_guess, self.ja3_guess) if g]
        if not guesses:
            return OsGuess()

        # Weight: ja3 > dns > tcp for family detection
        weights = {"ja3": 0.5, "dns": 0.35, "tcp": 0.15}
        family_scores: dict[str, float] = {}
        for g in guesses:
            w = weights.get(g.method, 0.2)
            s = family_scores.get(g.os_family, 0.0)
            family_scores[g.os_family] = s + g.confidence * w

        best_family = max(family_scores, key=lambda k: family_scores[k])
        # Pick version from the guess that identified this family
        best_guess  = next((g for g in guesses if g.os_family == best_family), guesses[0])

        total_conf = min(1.0, sum(g.confidence for g in guesses) / len(guesses) * 1.2)
        return OsGuess(
            os_family   = best_family,
            os_version  = best_guess.os_version,
            device_type = best_guess.device_type,
            confidence  = round(total_conf, 2),
            method      = "combined",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Method 1 — TCP/IP stack fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

# Each signature: (ttl_range, window_size_range, must_have_options, os_family, version, device, confidence)
_TCP_SIGNATURES: list[tuple] = [
    # Windows — TTL 128, large window, MSS+NOP+WS+NOP+NOP+SACK ordering
    (120, 135, 60000, 70000, {"MSS","NOP","WS","SACK"}, "Windows", "10/11", "Laptop", 0.88),
    (120, 135, 8192,  16384, {"MSS","NOP"},             "Windows", "XP/7",  "Laptop", 0.70),
    (120, 135, 65535, 65535, {"MSS","WS","SACK"},       "Windows", "10/11", "Laptop", 0.85),

    # macOS / iOS — TTL 64, window 65535, MSS+NOP+WS+SACK+TS
    (60,  68,  65535, 65535, {"MSS","NOP","WS","SACK","TS"}, "macOS",   "12+",    "Laptop", 0.91),
    (60,  68,  65535, 65535, {"MSS","WS","SACK","TS"},       "macOS",   "10-11",  "Laptop", 0.85),
    (60,  68,  65535, 65535, {"MSS","NOP","WS","SACK"},      "iOS",     "15+",    "Phone",  0.82),

    # Linux — TTL 64, various window sizes, MSS+SACK+TS+NOP+WS
    (60,  68,  29200, 29200, {"MSS","SACK","TS","NOP","WS"},  "Linux", "4.x-6.x","Laptop",0.89),
    (60,  68,  14600, 14600, {"MSS","SACK","TS","NOP","WS"},  "Linux", "3.x",    "Server",0.80),
    (60,  68,  5840,  8192,  {"MSS","SACK","TS"},             "Linux", "2.6.x",  "Server",0.72),
    (60,  68,  65535, 65535, {"MSS","SACK","TS","WS"},        "Linux", "5.x-6.x","Server",0.85),

    # Android — TTL 64, window 65535, close to iOS but slightly different options
    (60,  68,  65535, 65535, {"MSS","SACK","TS","WS"},        "Android","10+",   "Phone", 0.78),
    (60,  68,  14480, 14480, {"MSS","SACK","TS","NOP","WS"},  "Android","8-9",   "Phone", 0.75),

    # Network devices — TTL 255 (Cisco IOS default)
    (250, 255, 4096,  8192,  {"MSS"},                         "Cisco IOS","",    "Router",0.82),
    (250, 255, 16384, 65535, {"MSS","SACK"},                  "Router/AP","",    "Router",0.65),

    # FreeBSD (pfSense, OPNsense) — TTL 64, window 65535
    (60,  68,  65535, 65535, {"MSS","NOP","WS","SACK","TS"},  "FreeBSD","13+",  "Router", 0.80),
]


def fingerprint_tcp(ttl: int, window: int, options: set[str]) -> OsGuess:
    """
    Identify OS from a SYN or SYN-ACK packet's IP/TCP headers.

    Args:
        ttl:     IP Time-To-Live field
        window:  TCP window size
        options: set of TCP option names present, e.g. {'MSS','NOP','WS','SACK','TS'}
    """
    best    = OsGuess(method="tcp")
    best_score = 0.0

    for (ttl_lo, ttl_hi, win_lo, win_hi, must_opts,
         family, version, device, base_conf) in _TCP_SIGNATURES:

        if not (ttl_lo <= ttl <= ttl_hi):
            continue
        if not (win_lo <= window <= win_hi):
            continue

        match_ratio = len(must_opts & options) / len(must_opts) if must_opts else 1.0
        score       = base_conf * match_ratio

        if score > best_score:
            best_score = score
            best = OsGuess(
                os_family   = family,
                os_version  = version,
                device_type = device,
                confidence  = round(score, 2),
                method      = "tcp",
            )

    return best


# ─────────────────────────────────────────────────────────────────────────────
# Method 2 — DNS behaviour fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

# Domains that are queried automatically by each OS/platform at startup
# or periodically. The device didn't open a browser — the OS did.
_DNS_SIGNATURES: list[tuple[set[str], str, str, str, float]] = [
    # (domain_patterns, os_family, version, device_type, confidence)

    # Windows — NCSI (Network Connectivity Status Indicator)
    ({"msftconnecttest.com", "msftncsi.com", "ipv6.msftncsi.com"},
     "Windows", "8+", "Laptop", 0.97),
    ({"settings-win.data.microsoft.com", "fe3.delivery.mp.microsoft.com"},
     "Windows", "10/11", "Laptop", 0.92),
    ({"windowsupdate.com", "update.microsoft.com"},
     "Windows", "", "Laptop", 0.75),
    ({"login.live.com", "login.microsoftonline.com"},
     "Windows", "", "Laptop", 0.65),
    ({"time.windows.com"},
     "Windows", "", "Laptop", 0.60),

    # macOS — captive portal check + Apple push + update
    ({"captive.apple.com", "www.apple.com"},
     "macOS", "", "Laptop", 0.95),
    ({"mesu.apple.com", "gdmf.apple.com"},
     "macOS", "11+", "Laptop", 0.92),
    ({"configuration.apple.com", "xp.apple.com"},
     "macOS", "10.15+", "Laptop", 0.88),

    # iOS — same Apple domains but combined with mobile-specific
    ({"captive.apple.com", "gsp1.apple.com"},
     "iOS", "14+", "Phone", 0.93),
    ({"push.apple.com", "api.push.apple.com"},
     "iOS", "", "Phone", 0.90),
    ({"ocsp.apple.com", "crl.apple.com"},
     "iOS/macOS", "", "Apple device", 0.70),

    # Android — Google connectivity check
    ({"connectivitycheck.gstatic.com", "connectivitycheck.android.com"},
     "Android", "5+", "Phone", 0.97),
    ({"android.clients.google.com", "play.googleapis.com"},
     "Android", "", "Phone", 0.90),
    ({"time.android.com"},
     "Android", "", "Phone", 0.85),

    # Ubuntu / Debian Linux
    ({"connectivity-check.ubuntu.com"},
     "Linux", "Ubuntu", "Laptop", 0.97),
    ({"security.ubuntu.com", "archive.ubuntu.com"},
     "Linux", "Ubuntu", "Server", 0.90),
    ({"deb.debian.org", "security.debian.org"},
     "Linux", "Debian", "Server", 0.90),

    # Fedora / RHEL / CentOS
    ({"fedoraproject.org", "download.fedoraproject.org"},
     "Linux", "Fedora", "Laptop", 0.88),
    ({"mirrorlist.centos.org"},
     "Linux", "CentOS/RHEL", "Server", 0.90),

    # Amazon Echo / Alexa
    ({"alexa.amazon.com", "avs-alexa-na.amazon.com"},
     "Amazon Echo", "", "IoT", 0.98),

    # Smart TVs — Samsung Tizen
    ({"samsungcloudsolution.com", "samsungelectronics.com"},
     "Samsung SmartTV", "", "IoT", 0.88),

    # Chromecast / Google TV
    ({"clients3.google.com", "eureka.gvt1.com"},
     "ChromeOS/Chromecast", "", "IoT", 0.90),

    # Roku
    ({"logs.roku.com", "manifest.roku.com"},
     "Roku", "", "IoT", 0.98),
]

# Domain suffix → platform hint (lower confidence, catch-all)
_DOMAIN_SUFFIX_HINTS: list[tuple[str, str, str, float]] = [
    ("apple.com",       "Apple device",  "",     0.55),
    ("microsoft.com",   "Windows",       "",     0.45),
    ("google.com",      "Android",       "",     0.40),
    ("gstatic.com",     "Android",       "",     0.55),
    ("amazonaws.com",   "AWS service",   "",     0.30),
]


def fingerprint_dns(queries: list[str]) -> OsGuess:
    """
    Identify OS from the set of DNS domains a device has queried.
    queries: list of domain names (not FQDNs — strip trailing dot first)
    """
    if not queries:
        return OsGuess(method="dns")

    query_set = {q.lower().rstrip(".") for q in queries}
    best       = OsGuess(method="dns")
    best_score = 0.0

    for (patterns, family, version, device, base_conf) in _DNS_SIGNATURES:
        hits  = len(patterns & query_set)
        if hits == 0:
            continue
        ratio = hits / len(patterns)
        score = base_conf * min(1.0, ratio * 1.5)   # partial match still counts
        if score > best_score:
            best_score = score
            best = OsGuess(
                os_family   = family,
                os_version  = version,
                device_type = device,
                confidence  = round(score, 2),
                method      = "dns",
            )

    # Suffix fallback if nothing matched
    if best_score < 0.3:
        for (suffix, family, version, conf) in _DOMAIN_SUFFIX_HINTS:
            if any(q.endswith(suffix) for q in query_set):
                if conf > best_score:
                    best_score = conf
                    best = OsGuess(
                        os_family   = family,
                        os_version  = version,
                        device_type = "Unknown",
                        confidence  = conf,
                        method      = "dns",
                    )
    return best


# ─────────────────────────────────────────────────────────────────────────────
# Method 3 — JA3 TLS fingerprinting
# ─────────────────────────────────────────────────────────────────────────────
# JA3 = MD5 of: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
# Computed from the TLS ClientHello — visible even in encrypted connections.

# Known JA3 hashes → (os_family, version, device_type, confidence)
# Sources: ja3er.com, salesforce JA3 research, Trisul fingerprints
_JA3_DB: dict[str, tuple[str, str, str, float]] = {
    # Chrome on Windows
    "cd08e31494f9531f560d64c695473da9": ("Windows", "Chrome 90+",  "Laptop", 0.88),
    "b32309a26951912be7dba376398abc3b": ("Windows", "Chrome 80+",  "Laptop", 0.85),
    "28a2c9bd18a11ef1227ae0b3b4c88787": ("Windows", "Chrome 72+",  "Laptop", 0.82),
    # Chrome on macOS
    "4d7a28d6f2263ed61de88ca66eb011e3": ("macOS",   "Chrome 90+",  "Laptop", 0.88),
    # Firefox on Windows
    "a0e9f5d64349fb13191bc781f81f42e1": ("Windows", "Firefox",     "Laptop", 0.85),
    "8a0b73a88e3b28e8af17bb20ff6cd4ef": ("Windows", "Firefox ESR", "Laptop", 0.80),
    # Firefox on Linux
    "3b5074b1b5d032e5620f69f9159d9fdf": ("Linux",   "Firefox",     "Laptop", 0.85),
    # Safari on macOS
    "773906b0efdefa24a7f2b8eb6985bf42": ("macOS",   "Safari 14+",  "Laptop", 0.92),
    "d187a52f5a5e8a71be9f27db4e668dce": ("macOS",   "Safari 12-13","Laptop", 0.88),
    # Safari on iOS
    "d9f3152e03d5c4e37b4530f7e1e6f2e2": ("iOS",     "Safari 14+",  "Phone",  0.91),
    "e6573e91e6eb777c0933c5b8f97f10cd": ("iOS",     "Safari 15+",  "Phone",  0.90),
    # Android Chrome
    "e46e5a1d0b8e44167d1f56f5d2e2a3d5": ("Android", "Chrome",      "Phone",  0.87),
    # curl (common on Linux servers and scripts)
    "13303773a44b9b4b73d4aaba97db3e64": ("Linux",   "curl",        "Server", 0.80),
    "c4a36a9ea40a8c5b9d4e6fc5e9e56555": ("Linux",   "curl",        "Server", 0.78),
    # Python requests
    "aaa43c811a8c1aeb1e65e8e0ef42f23e": ("Linux",   "Python",      "Server", 0.75),
    # Go net/http
    "b754e429ecdedbd18dfa68e3ea0b6b3b": ("Linux",   "Go",          "Server", 0.75),
    # Known malware / C2 frameworks
    "72a589da586844d7f0818ce684948eea": ("Unknown", "Cobalt Strike","Unknown",0.95),
    "b386946a5a44d1ddcc843bc75336dfce": ("Unknown", "Metasploit",  "Unknown", 0.93),
    "51c64c77e60f3980eea90869b68c58a8": ("Unknown", "Cobalt Strike","Unknown",0.97),
    "e7d705a3286e19ea42f587b344ee6865": ("Unknown", "Havoc C2",    "Unknown", 0.92),
}

_MALWARE_JA3: set[str] = {
    "72a589da586844d7f0818ce684948eea",
    "b386946a5a44d1ddcc843bc75336dfce",
    "51c64c77e60f3980eea90869b68c58a8",
    "e7d705a3286e19ea42f587b344ee6865",
}


def compute_ja3(tls_record: dict) -> str:
    """
    Compute the JA3 hash from a parsed TLS ClientHello record.

    tls_record keys:
        version         int   — TLS version (e.g. 771 for TLS 1.2)
        ciphers         list  — cipher suite IDs (ints), GREASE values stripped
        extensions      list  — extension type IDs (ints), GREASE stripped
        elliptic_curves list  — supported groups (ints)
        ec_point_formats list — EC point format IDs (ints)
    """
    def _strip_grease(lst: list[int]) -> list[int]:
        # GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa (every 0x1010 step)
        return [x for x in lst if not (x & 0x0f0f == 0x0a0a and x >> 8 == (x & 0xff))]

    ver     = str(tls_record.get("version", 0))
    ciphers = "-".join(str(c) for c in _strip_grease(tls_record.get("ciphers", [])))
    exts    = "-".join(str(e) for e in _strip_grease(tls_record.get("extensions", [])))
    curves  = "-".join(str(c) for c in tls_record.get("elliptic_curves", []))
    points  = "-".join(str(p) for p in tls_record.get("ec_point_formats", []))

    raw  = f"{ver},{ciphers},{exts},{curves},{points}"
    return hashlib.md5(raw.encode()).hexdigest()


def fingerprint_ja3(ja3_hash: str) -> OsGuess:
    """Look up a JA3 hash and return an OS guess."""
    if ja3_hash in _JA3_DB:
        family, version, device, conf = _JA3_DB[ja3_hash]
        return OsGuess(
            os_family   = family,
            os_version  = version,
            device_type = device,
            confidence  = conf,
            method      = "ja3",
        )
    return OsGuess(method="ja3")


def is_malicious_ja3(ja3_hash: str) -> bool:
    return ja3_hash in _MALWARE_JA3


# ─────────────────────────────────────────────────────────────────────────────
# User-Agent parsing (HTTP — bonus method)
# ─────────────────────────────────────────────────────────────────────────────

_UA_PATTERNS: list[tuple[str, str, str, str, float]] = [
    # Pattern, os_family, version_group, device_type, confidence
    (r"Windows NT 10\.0",      "Windows", "10/11",  "Laptop", 0.95),
    (r"Windows NT 6\.[23]",    "Windows", "8/8.1",  "Laptop", 0.92),
    (r"Windows NT 6\.1",       "Windows", "7",      "Laptop", 0.92),
    (r"iPhone.+OS (\d+)",      "iOS",     "",       "Phone",  0.98),
    (r"iPad.+OS (\d+)",        "iOS",     "",       "Tablet", 0.98),
    (r"Android (\d+)",         "Android", "",       "Phone",  0.97),
    (r"Mac OS X (\d+[._]\d+)", "macOS",   "",       "Laptop", 0.96),
    (r"Linux.*Ubuntu",         "Linux",   "Ubuntu", "Laptop", 0.88),
    (r"Linux.*Debian",         "Linux",   "Debian", "Laptop", 0.88),
    (r"CrOS",                  "ChromeOS","",       "Laptop", 0.97),
    (r"Dalvik/",               "Android", "",       "Phone",  0.90),
]


def fingerprint_user_agent(ua: str) -> OsGuess:
    """Parse a User-Agent string into an OS guess."""
    for pattern, family, version, device, conf in _UA_PATTERNS:
        m = re.search(pattern, ua)
        if m:
            ver = version or (m.group(1) if m.lastindex else "")
            return OsGuess(
                os_family   = family,
                os_version  = ver,
                device_type = device,
                confidence  = conf,
                method      = "ua",
            )
    return OsGuess(method="ua")
