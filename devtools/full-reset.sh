#!/bin/bash
#
# full-reset.sh - DEV/TESTING TOOL ONLY.
#
# Tears ovpn_mgr all the way back down to "never been set up" state so
# you can retest the fresh-install experience (the setup banner, the
# root-authorization flow, etc.) repeatedly. This is NOT part of normal
# operation and is not something an end user should ever need to run.
#
# It deletes: all generated VPN configs/keys/packages/logs, the sudoers
# rule, the persisted sysctl setting, the NAT-restore systemd unit and
# its saved state, the live NAT iptables rule, and then uninstalls and
# reinstalls the FreePBX module itself.
#
# Run as root:
#     sudo bash /path/to/admin/modules/ovpn_mgr/devtools/full-reset.sh
#
# Add --yes to skip the confirmation prompt (for scripted/repeated runs).

set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This must be run as root, e.g.: sudo bash $0" >&2
    exit 1
fi

SKIP_CONFIRM=0
[ "${1:-}" = "--yes" ] && SKIP_CONFIRM=1

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVPNCTL="${MODULE_DIR}/scripts/ovpnctl"

AMPWEBROOT="$(cd "${MODULE_DIR}/../.." && pwd)"
if [ ! -d "${AMPWEBROOT}/admin/modules" ]; then
    AMPWEBROOT="/var/www/html"
fi
VPN_DATA_DIR="${AMPWEBROOT}/PhoneSettings/openvpn"
PKG_DIR="${AMPWEBROOT}/PhoneSettings/vpnkeys"

SUDOERS_FILE="/etc/sudoers.d/ovpn_mgr"
SYSCTL_FILE="/etc/sysctl.d/99-ovpn-mgr.conf"
NAT_STATE_DIR="/etc/ovpn_mgr"
NAT_UNIT_FILE="/etc/systemd/system/ovpn-mgr-nat.service"

echo "This will:"
echo "  - stop the OpenVPN daemon this module started"
echo "  - delete ${VPN_DATA_DIR} and ${PKG_DIR} (all VPN configs, keys, packages, logs)"
echo "  - remove ${SUDOERS_FILE}, ${SYSCTL_FILE}, ${NAT_UNIT_FILE}, ${NAT_STATE_DIR}"
echo "  - remove the module's NAT iptables rule, if present"
echo "  - reset ${OVPNCTL} to asterisk:asterisk 0755"
echo "  - run: fwconsole ma uninstall ovpn_mgr && fwconsole ma install ovpn_mgr"
echo
echo "Every client certificate and provisioning package will be gone."
echo

if [ "$SKIP_CONFIRM" -ne 1 ]; then
    read -r -p "Type RESET to continue: " confirm
    if [ "$confirm" != "RESET" ]; then
        echo "Aborted, nothing changed."
        exit 1
    fi
fi

echo "==> Stopping OpenVPN..."
if [ -x "$OVPNCTL" ]; then
    sudo -n "$OVPNCTL" stop 2>/dev/null || true
fi
pkill -f 'legacy-vpn' 2>/dev/null || true

echo "==> Removing NAT iptables rule (if any)..."
if command -v iptables >/dev/null 2>&1; then
    while iptables -t nat -C POSTROUTING -j MASQUERADE -m comment --comment OVPN_MGR_NAT 2>/dev/null; do
        iptables -t nat -D POSTROUTING -j MASQUERADE -m comment --comment OVPN_MGR_NAT
    done
fi

echo "==> Disabling and removing the NAT-restore systemd unit..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now ovpn-mgr-nat.service >/dev/null 2>&1 || true
fi
rm -f "$NAT_UNIT_FILE"
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload

echo "==> Removing sudoers rule, sysctl drop-in, and NAT state..."
rm -f "$SUDOERS_FILE"
rm -f "$SYSCTL_FILE"
rm -rf "$NAT_STATE_DIR"

echo "==> Turning ip_forward back off (kernel runtime only, until reboot)..."
sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

echo "==> Resetting ovpnctl ownership/permissions to a fresh-install state..."
if [ -f "$OVPNCTL" ]; then
    chown asterisk:asterisk "$OVPNCTL"
    chmod 755 "$OVPNCTL"
fi

echo "==> Deleting generated VPN data..."
rm -rf "$VPN_DATA_DIR"
rm -rf "$PKG_DIR"

echo "==> Reinstalling the module (runs install.php/uninstall.php)..."
if command -v fwconsole >/dev/null 2>&1; then
    fwconsole ma uninstall ovpn_mgr
    fwconsole ma install ovpn_mgr
else
    echo "fwconsole not found in PATH - reinstall the module manually" >&2
fi

echo
echo "Done. The module should now be in a fresh-install state:"
echo "  - no sudoers rule, no systemd unit, no generated keys/packages"
echo "  - GUI should show the 'One-Time Root Setup Required' banner"
