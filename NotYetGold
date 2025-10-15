#!/bin/bash
set -e

# Require root
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Use: sudo $0"
  exit 1
fi

echo "Updating system and installing packages..."
apt update && apt full-upgrade -y
apt install -y nftables dnsmasq jq curl git network-manager

echo "Enabling services..."
systemctl enable --now NetworkManager
systemctl enable --now nftables
systemctl enable --now dnsmasq

echo "Enabling IP forwarding persistently and immediately..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1

echo "Creating systemd service to force-enable IP forwarding..."

tee /etc/systemd/system/ip-forwarding.service > /dev/null <<EOF
[Unit]
Description=Enable IPv4 forwarding
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c "sysctl -w net.ipv4.ip_forward=1"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ip-forwarding.service
systemctl start ip-forwarding.service


echo "Configuring WAN interface (eth1)..."
nmcli con delete WAN || true
nmcli con add type ethernet ifname eth1 con-name WAN ipv4.method auto ipv6.method ignore
nmcli con modify WAN connection.autoconnect yes
nmcli con up WAN

echo "Waiting for WAN interface to obtain IP and default route..."
for i in {1..20}; do
  if ip route | grep -q '^default'; then
    echo "Default route is set."
    break
  fi
  echo "Waiting for default route (try $i)..."
  sleep 2
done

echo "Creating LAN bridge br0 with static IP 192.168.50.1/24..."
nmcli con delete LANBR || true
nmcli con add type bridge ifname br0 con-name LANBR ipv4.method manual ipv4.addresses 192.168.50.1/24 ipv6.method ignore
nmcli con modify LANBR connection.autoconnect yes
nmcli con up LANBR

echo "Adding eth2-eth4 to bridge br0..."
for iface in eth2 eth3 eth4; do
  nmcli con delete "$iface" || true
  nmcli con add type ethernet ifname "$iface" master br0 con-name "$iface"
  nmcli con modify "$iface" connection.autoconnect yes
  nmcli con up "$iface"
done

echo "Writing dnsmasq config..."
tee /etc/dnsmasq.d/lan.conf > /dev/null <<EODNS
interface=br0
bind-interfaces
dhcp-range=192.168.50.100,192.168.50.200,255.255.255.0,12h
dhcp-option=option:router,192.168.50.1
dhcp-option=option:dns-server,192.168.50.1
domain=lan
dhcp-authoritative

no-resolv
server=1.1.1.1
server=1.0.0.1
# log-queries  # Uncomment if debugging
EODNS

echo "Configuring dnsmasq to wait for network..."
mkdir -p /etc/systemd/system/dnsmasq.service.d
tee /etc/systemd/system/dnsmasq.service.d/wait-for-network.conf > /dev/null <<EOF
[Unit]
After=network-online.target
Wants=network-online.target
EOF

echo "Reloading systemd and restarting dnsmasq..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl restart dnsmasq

echo "Writing nftables config..."
tee /etc/nftables.conf > /dev/null <<'EONFT'
flush ruleset
define LAN = "br0"
define WAN = "eth1"

table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;
    iif lo accept
    ct state {established, related} accept
    iif $LAN udp dport {53,67,68} accept
    iif $LAN tcp dport {53,22} accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;
    iif $LAN oif $WAN ct state {new, established, related} accept
    iif $WAN oif $LAN ct state {established, related} accept
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat;
    oif $WAN masquerade
  }
}
EONFT

echo "Applying nftables config..."
nft -c -f /etc/nftables.conf
systemctl restart nftables

echo "Verifying NAT masquerade rule is present, adding if missing..."
if ! nft list chain ip nat postrouting | grep -q masquerade; then
  echo "NAT masquerade rule missing, adding it now..."
  nft add table ip nat || true
  nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; } || true
  nft add rule ip nat postrouting oif eth1 masquerade || true
fi

echo "Restarting nftables and dnsmasq to ensure settings apply..."
systemctl restart nftables
systemctl restart dnsmasq

echo "Setup complete. Please reboot now to test your router."
