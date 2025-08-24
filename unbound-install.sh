#!/usr/bin/env bash
set -euo pipefail

# ================== PARAM ==================
BIND_IP="${BIND_IP:-157.0.0.1}"   # override: BIND_IP=10.10.10.53 ./install-unbound-ip.sh
ALLOW_NETS=("127.0.0.0/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
ENABLE_IPV6="${ENABLE_IPV6:-no}"     # "yes" kalau mau v6 (butuh ip v6 aktif di host)
# ==========================================

echo "[0/10] Using BIND_IP=${BIND_IP}"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need_cmd apt-get; need_cmd systemctl; need_cmd timeout

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)."; exit 1; fi

echo "[1/10] Purge instalasi lama..."
systemctl stop unbound 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get purge -y unbound unbound-anchor unbound-host || true
DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true

echo "[2/10] Install paket..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates curl wget gnupg lsb-release \
  dnsutils net-tools coreutils iproute2 \
  unbound unbound-anchor unbound-host

echo "[3/10] Matikan DNSStubListener & set resolver sementara..."
RESOLVED_CONF="/etc/systemd/resolved.conf"
if grep -q '^#\?DNSStubListener=' "$RESOLVED_CONF"; then
  sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' "$RESOLVED_CONF"
else
  printf "\nDNSStubListener=no\n" >> "$RESOLVED_CONF"
fi
systemctl restart systemd-resolved

# resolv.conf sementara → publik (Cloudflare) sampai Unbound hidup
if [[ -L /etc/resolv.conf ]]; then rm -f /etc/resolv.conf; fi
printf "nameserver 1.1.1.1\noptions edns0\n" > /etc/resolv.conf

echo "[4/10] Siapkan user & direktori..."
id -u unbound >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /var/lib/unbound unbound
install -d -o unbound -g unbound -m 0750 /var/lib/unbound
install -d -o unbound -g unbound -m 0755 /run/unbound

echo "[5/10] Root trust-anchor (timeout + fallback)..."
rm -f /var/lib/unbound/root.key || true
if timeout 20s unbound-anchor -a /var/lib/unbound/root.key; then
  echo "  - anchor generated via unbound-anchor"
else
  echo "  - unbound-anchor timeout/fail, fallback to distro root.key"
  cp -f /usr/share/dns/root.key /var/lib/unbound/root.key
fi
chown unbound:unbound /var/lib/unbound/root.key
chmod 0640 /var/lib/unbound/root.key

echo "[6/10] Bersihin config lama & tulis /etc/unbound/unbound.conf ..."
mkdir -p /etc/unbound/unbound.conf.d
[[ -f /etc/unbound/unbound.conf ]] && cp -a /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak.$(date +%F-%H%M) || true
rm -f /etc/unbound/unbound.conf.d/* || true

# Optional: warning kalau IP belum ada di host
if ! ip -4 addr show | grep -qw "${BIND_IP}"; then
  echo "WARN: ${BIND_IP} belum ter-assign di host ini. Pastikan IP ada di interface."
fi

{
  echo "server:"
  echo "  username: \"unbound\""
  echo "  directory: \"/etc/unbound\""
  echo ""
  echo "  # Listen di IP publik & loopback (biar bisa query lokal tanpa REFUSED)"
  echo "  interface: ${BIND_IP}"
  echo "  interface: 127.0.0.1"
  if [[ "${ENABLE_IPV6}" == "yes" ]]; then
    echo "  interface: ::0"
    echo "  do-ip6: yes"
  else
    echo "  do-ip6: no"
  fi
  echo "  do-ip4: yes"
  echo "  do-udp: yes"
  echo "  do-tcp: yes"
  echo ""
  echo "  # Good defaults"
  echo "  qname-minimisation: yes"
  echo "  prefetch: yes"
  echo "  hide-identity: yes"
  echo "  hide-version: yes"
  echo "  cache-min-ttl: 60"
  echo "  cache-max-ttl: 86400"
  echo ""
  echo "  # ACL — izinkan IP server sendiri & LANs"
  echo "  access-control: ${BIND_IP}/32 allow"
  echo "  access-control: 127.0.0.0/8 allow"
  for a in "${ALLOW_NETS[@]}"; do
    [[ "$a" == "127.0.0.0/8" ]] && continue
    echo "  access-control: ${a} allow"
  done
  if [[ "${ENABLE_IPV6}" == "yes" ]]; then
    echo "  access-control: ::1 allow"
  fi
  echo "  # Default refuse publik (bukan open resolver)"
  echo "  access-control: 0.0.0.0/0 refuse"
  if [[ "${ENABLE_IPV6}" == "yes" ]]; then
    echo "  access-control: ::0/0 refuse"
  fi
  echo ""
  echo "  # DNSSEC trust anchor"
  echo "  auto-trust-anchor-file: \"/var/lib/unbound/root.key\""
  echo ""
  echo "remote-control:"
  echo "  control-enable: yes"
  echo "  control-interface: 127.0.0.1"
  if [[ "${ENABLE_IPV6}" == "yes" ]]; then
    echo "  control-interface: ::1"
  fi
  echo "  control-use-cert: no   # local-only; simple & anti drama"
  echo ""
  echo "include: \"/etc/unbound/unbound.conf.d/*.conf\""
} > /etc/unbound/unbound.conf

chmod 640 /etc/unbound/unbound.conf
chown root:unbound /etc/unbound/unbound.conf
chown root:unbound /etc/unbound
chmod 750 /etc/unbound

echo "[7/10] Validasi config..."
unbound-checkconf /etc/unbound/unbound.conf

echo "[8/10] Enable & start Unbound..."
systemctl enable unbound
systemctl restart unbound || { 
  echo "Start gagal, log terakhir:"; journalctl -u unbound -b --no-pager | tail -n 120; exit 1;
}

echo "[9/10] Arahkan resolv.conf ke IP ini (${BIND_IP})..."
printf "nameserver %s\noptions edns0\n" "${BIND_IP}" > /etc/resolv.conf

echo "[10/10] Tes query & status..."
dig @${BIND_IP} cloudflare.com A +short || true
systemctl status unbound --no-pager | tail -n 10

echo "✅ Selesai. Unbound listen di ${BIND_IP}:53 (IPv6: ${ENABLE_IPV6})."
echo "   Client LAN: arahkan DNS ke ${BIND_IP}."
echo "   Admin RC: local-only di 127.0.0.1 (tanpa TLS)."
