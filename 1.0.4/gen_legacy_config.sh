#!/bin/bash
# Dedicated OpenVPN server configuration for legacy phones
CA_DIR="/etc/openvpn/legacy_pki"
PORT="1194"
PROTO="udp"

cat <<EOF > /etc/openvpn/legacy-server.conf
port ${PORT}
proto ${PROTO}
dev tun_legacy

ca ${CA_DIR}/ca.crt
cert ${CA_DIR}/server.crt
key ${CA_DIR}/server.key
dh ${CA_DIR}/dh.pem

server 10.9.0.0 255.255.255.0
keepalive 10 120

# Force Legacy Cipher & Protocol Compatibility for Yealink T28P
tls-version-min 1.0
data-ciphers AES-128-CBC:AES-256-CBC:BF-CBC
data-ciphers-fallback AES-128-CBC
auth SHA1
disable-dco

persist-key
persist-tun
status /var/log/openvpn/legacy-status.log
verb 3
EOF

# Ensure openvpn log dir exists
mkdir -p /var/log/openvpn