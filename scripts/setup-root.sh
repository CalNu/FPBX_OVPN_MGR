#!/bin/bash
#
# setup-root.sh - one-time privileged setup for the ovpn_mgr module.
#
# Run this yourself, once, from an SSH/console root shell:
#
#     sudo bash /path/to/admin/modules/ovpn_mgr/scripts/setup-root.sh
#
# It never runs as part of a web request and never sees a password typed
# into the browser. All it does:
#
#   1. Locks down ownership/permissions on scripts/ovpnctl (root:asterisk, 0750)
#   2. Installs a sudoers rule letting 'asterisk' run ONLY that exact
#      script, with no password prompt (NOPASSWD), nothing else.
#   3. Persists net.ipv4.ip_forward=1 across reboots via sysctl.d.
#   4. Installs a systemd unit that reapplies the VPN's NAT rule (and, on
#      standalone/non-Distro systems, its own 'ovpn_mgr' port-accept chain)
#      at boot - nothing else, it doesn't touch your OS's normal firewall.
#
# It is written to be distro-agnostic: it doesn't assume the FreePBX
# Distro, a script-installed Debian box, or Incredible PBX - only that
# systemd and sudo are present, which all three provide.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This must be run as root, e.g.: sudo bash $0" >&2
    exit 1
fi

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="${MODULE_DIR}/scripts/ovpnctl"
SUDOERS_FILE="/etc/sudoers.d/ovpn_mgr"
STATE_DIR="/etc/ovpn_mgr"
UNIT_FILE="/etc/systemd/system/ovpn-mgr-nat.service"

# This script lives at <AMPWEBROOT>/admin/modules/ovpn_mgr/scripts/setup-root.sh
AMPWEBROOT="$(cd "${MODULE_DIR}/../.." && pwd)"
if [ ! -d "${AMPWEBROOT}/admin/modules" ]; then
    AMPWEBROOT="/var/www/html"
fi
VPN_DATA_DIR="${AMPWEBROOT}/PhoneSettings/openvpn"

if [ ! -f "$WRAPPER" ]; then
    echo "Could not find $WRAPPER - is this the right module directory?" >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd (systemctl) was not found. This script currently only" >&2
    echo "supports systemd-based systems. NAT-rule persistence across" >&2
    echo "reboots will need to be set up manually on this system." >&2
fi

# --- 1. Lock down the wrapper ---
chown root:asterisk "$WRAPPER"
chmod 750 "$WRAPPER"

# --- 2. Sudoers rule, scoped to exactly this one script ---
TMP_SUDOERS="$(mktemp)"
echo "asterisk ALL=(root) NOPASSWD: ${WRAPPER}" > "$TMP_SUDOERS"

if ! visudo -cf "$TMP_SUDOERS" >/dev/null 2>&1; then
    echo "Generated sudoers rule failed validation, aborting." >&2
    rm -f "$TMP_SUDOERS"
    exit 1
fi

install -m 0440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_FILE"
rm -f "$TMP_SUDOERS"

# --- 3. Persist IP forwarding ---
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-ovpn-mgr.conf
sysctl -p /etc/sysctl.d/99-ovpn-mgr.conf >/dev/null

# --- 4. NAT-rule persistence via a systemd unit (portable across distros -
#     deliberately does not write into any distro-specific rules file) ---
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

if command -v systemctl >/dev/null 2>&1; then
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Reapply ovpn_mgr VPN NAT rule and (standalone-firewall) port rule
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${WRAPPER} nat-restore
ExecStart=${WRAPPER} port-restore
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE"
    systemctl daemon-reload
    systemctl enable ovpn-mgr-nat.service >/dev/null 2>&1 || true
    systemctl start ovpn-mgr-nat.service >/dev/null 2>&1 || true
fi

# --- Directory ownership for module-managed files ---
mkdir -p "${VPN_DATA_DIR}/logs" 2>/dev/null || true
chown -R asterisk:asterisk "${VPN_DATA_DIR}" 2>/dev/null || true

# --- Restart the daemon now that root access exists ---
# If OpenVPN was already limping along (e.g. started once without the
# tun/NAT setup it needed), a stop+start here - now with real privilege -
# is what actually creates a working tun interface, rather than leaving
# the admin to notice it's still broken and click Restart in the GUI.
echo "==> Restarting OpenVPN daemon so it comes up cleanly with the new privileges..."
"$WRAPPER" stop || true
sleep 1
"$WRAPPER" start || echo "    (start reported an error - check the module's log for details)"

echo "Done."
echo "  - ${WRAPPER} is now root:asterisk 0750"
echo "  - ${SUDOERS_FILE} grants 'asterisk' passwordless sudo on that script only"
echo "  - net.ipv4.ip_forward=1 persisted in /etc/sysctl.d/99-ovpn-mgr.conf"
echo "  - ovpn-mgr-nat.service will reapply the VPN's NAT rule (and, on standalone systems, the port-accept rule) on every boot"
echo "  - OpenVPN daemon restarted"
echo "Reload the OpenVPN Manager admin page - the setup banner should clear."
