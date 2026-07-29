#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Phalanx Sensor — Demo Setup Script
#
# Configures your laptop as a Wi-Fi hotspot that bridges to a MiFi/uplink,
# then starts the sensor daemon in demo mode.
#
# Requirements:
#   - Ubuntu 20.04+ or Debian 11+
#   - Two network interfaces (eth0/USB ethernet for MiFi + wlan0 for hotspot)
#   - hostapd, dnsmasq, bridge-utils installed (script installs them)
#   - Root / sudo
#
# Usage:
#   sudo bash setup_demo.sh                    # auto-detect interfaces
#   sudo bash setup_demo.sh eth0 wlan0         # explicit: uplink AP
#   sudo bash setup_demo.sh --server http://10.0.0.1:5038
#
# What it does:
#   1. Installs dependencies
#   2. Creates a Wi-Fi hotspot (SSID: PhalanxDemo)
#   3. Bridges hotspot → MiFi uplink (all demo devices get internet)
#   4. Starts dnsmasq as DHCP + DNS server on the bridge
#   5. Starts the Phalanx sensor daemon on the bridge interface
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
UPLINK_IF="${1:-}"         # eth0 or usb0 — connected to MiFi
AP_IF="${2:-}"             # wlan0 — will become the hotspot
BRIDGE_IF="br0"
SSID="PhalanxDemo"
PASSPHRASE="phalanx2024"
CHANNEL="6"
SERVER_URL="http://localhost:5038"
SENSOR_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="/var/lib/phalanx"

# Parse --server flag
for arg in "$@"; do
    if [[ "$arg" == --server=* ]]; then
        SERVER_URL="${arg#*=}"
    elif [[ "$arg" == --server ]]; then
        shift; SERVER_URL="$1"
    fi
done

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash setup_demo.sh"

echo -e "\n${BOLD}${BLUE}⬡ Phalanx Sensor Demo Setup${NC}\n"

# ── Auto-detect interfaces ────────────────────────────────────────────────────
info "Detecting network interfaces..."

if [[ -z "$UPLINK_IF" ]]; then
    # Find first wired/USB interface with a link
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        if [[ "$iface" != wlan* ]] && [[ "$iface" != br* ]]; then
            if [[ "$(cat /sys/class/net/$iface/operstate 2>/dev/null)" == "up" ]]; then
                UPLINK_IF="$iface"
                break
            fi
        fi
    done
    [[ -n "$UPLINK_IF" ]] || die "No uplink interface found. Plug in USB ethernet adapter and retry."
fi

if [[ -z "$AP_IF" ]]; then
    for iface in $(ls /sys/class/net/ | grep wlan); do
        AP_IF="$iface"
        break
    done
    [[ -n "$AP_IF" ]] || die "No Wi-Fi interface found."
fi

ok "Uplink  : $UPLINK_IF (connected to MiFi)"
ok "AP      : $AP_IF (will become '$SSID' hotspot)"
ok "Bridge  : $BRIDGE_IF"
ok "Server  : $SERVER_URL"

# ── Install dependencies ───────────────────────────────────────────────────────
info "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq hostapd dnsmasq bridge-utils python3-pip iproute2 >/dev/null
pip3 install -q psutil requests pyyaml
ok "Dependencies installed"

# ── Stop conflicting services ─────────────────────────────────────────────────
systemctl stop NetworkManager 2>/dev/null || true
systemctl stop hostapd        2>/dev/null || true
systemctl stop dnsmasq        2>/dev/null || true
rfkill unblock wifi 2>/dev/null || true

# ── Create bridge ─────────────────────────────────────────────────────────────
info "Creating bridge $BRIDGE_IF..."

ip link delete "$BRIDGE_IF" 2>/dev/null || true
ip link add name "$BRIDGE_IF" type bridge
ip link set "$UPLINK_IF" master "$BRIDGE_IF"
ip link set "$BRIDGE_IF" up
ip link set "$UPLINK_IF" up

# Get IP via DHCP on bridge (the MiFi gives us internet)
dhclient "$BRIDGE_IF" 2>/dev/null || true
ok "Bridge created and connected to MiFi"

# ── Configure Wi-Fi AP ────────────────────────────────────────────────────────
info "Configuring Wi-Fi hotspot ($SSID)..."

HOSTAPD_CONF="/tmp/phalanx_hostapd.conf"
cat > "$HOSTAPD_CONF" << HOSTAPD
interface=$AP_IF
bridge=$BRIDGE_IF
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$PASSPHRASE
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
HOSTAPD

# Start hostapd in background
hostapd "$HOSTAPD_CONF" -B -P /tmp/phalanx_hostapd.pid >/tmp/hostapd.log 2>&1
sleep 2

if ! kill -0 "$(cat /tmp/phalanx_hostapd.pid 2>/dev/null)" 2>/dev/null; then
    warn "hostapd failed to start. Check /tmp/hostapd.log"
    warn "Continuing without hotspot — sensor will listen on $BRIDGE_IF"
else
    ok "Hotspot '$SSID' running on $AP_IF (password: $PASSPHRASE)"
fi

# ── Configure dnsmasq (DHCP + DNS for hotspot clients) ───────────────────────
info "Starting DHCP/DNS server on bridge..."

DNSMASQ_CONF="/tmp/phalanx_dnsmasq.conf"
cat > "$DNSMASQ_CONF" << DNSMASQ
interface=$BRIDGE_IF
bind-interfaces
dhcp-range=10.88.0.10,10.88.0.250,255.255.255.0,12h
dhcp-option=3,10.88.0.1
dhcp-option=6,10.88.0.1
log-queries
log-facility=/tmp/phalanx_dns.log
DNSMASQ

# Set static IP on bridge for our DHCP server role
ip addr add 10.88.0.1/24 dev "$BRIDGE_IF" 2>/dev/null || true

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o "$UPLINK_IF" -j MASQUERADE 2>/dev/null || true

dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file=/tmp/phalanx_dnsmasq.pid 2>/dev/null
ok "DHCP server running (pool: 10.88.0.10 – 10.88.0.250)"

# ── Create state directory ────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}─────────────────────────────────────────────${NC}"
echo -e "${BOLD}Demo network ready${NC}"
echo -e "  Wi-Fi SSID     : ${GREEN}$SSID${NC}"
echo -e "  Password       : ${GREEN}$PASSPHRASE${NC}"
echo -e "  Gateway IP     : ${GREEN}10.88.0.1${NC}"
echo -e "  DHCP pool      : 10.88.0.10 – 10.88.0.250"
echo -e "  Sensor listens : $BRIDGE_IF"
echo -e "${BOLD}─────────────────────────────────────────────${NC}"
echo ""
echo -e "${YELLOW}Ask your supervisor to connect their device to '$SSID'${NC}"
echo -e "${YELLOW}You will see it appear in the console below${NC}"
echo ""

# ── Start sensor ──────────────────────────────────────────────────────────────
info "Starting Phalanx sensor (Ctrl+C to stop)..."
echo ""

exec python3 "$SENSOR_DIR/sensor.py" \
    --interface "$BRIDGE_IF" \
    --server    "$SERVER_URL" \
    --gateway   "10.88.0.1" \
    --state-dir "$STATE_DIR" \
    --demo
