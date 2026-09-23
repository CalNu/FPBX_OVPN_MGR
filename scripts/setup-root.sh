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
#   4. Adds the OpenVPN client pool to Fail2Ban's DEFAULT ignoreip list.
#   5. Installs a systemd unit that reapplies the VPN's NAT rule at boot
#      (nothing else - it doesn't touch your OS's normal firewall setup).
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
OPENVPN_UNIT_FILE="/etc/systemd/system/ovpn-mgr-openvpn.service"
FIXPERMS_UNIT_FILE="/etc/systemd/system/ovpn-mgr-fixperms.service"

# This script lives at <AMPWEBROOT>/admin/modules/ovpn_mgr/scripts/setup-root.sh
AMPWEBROOT="$(cd "${MODULE_DIR}/../.." && pwd)"
if [ ! -d "${AMPWEBROOT}/admin/modules" ]; then
    AMPWEBROOT="/var/www/html"
fi
# Matches install.php/ovpnctl: this module's data lives under
# PhoneSettings/openvpn, wherever PhoneSettings currently resolves to.
PHONE_SETTINGS_DIR="${AMPWEBROOT}/PhoneSettings"
if [ -L "$PHONE_SETTINGS_DIR" ]; then
    echo "Refusing to configure ovpn_mgr: $PHONE_SETTINGS_DIR is a symlink. Convert it to a real directory first so VPN state is not stored in /tftpboot." >&2
    exit 1
fi
VPN_DATA_DIR="${PHONE_SETTINGS_DIR}/openvpn"
if [ -d /tftpboot/openvpn ] && [ ! -d "$VPN_DATA_DIR" ]; then
    echo "Legacy VPN data found at /tftpboot/openvpn; migrate it to $VPN_DATA_DIR before setup." >&2
    exit 1
fi

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

# --- 1b. Tell FreePBX's own "fwconsole chown" about this file, instead of ---
#     fighting it. FreePBX periodically re-chowns everything under
#     admin/modules back to asterisk:asterisk, which silently undid the
#     chown/chmod above (and every attempt to work around it from outside
#     fwconsole - e.g. a systemd unit racing it at boot - is unreliable,
#     since chown can also run later via cron/GUI actions, not just at
#     boot). FreePBX reads /etc/asterisk/freepbx_chown.conf and honors a
#     [custom] section that pins an exact owner/group/mode for a path, so
#     fwconsole chown itself will (re)apply root:asterisk 0750 to $WRAPPER
#     every time it runs, from any trigger.
CHOWN_CONF="/etc/asterisk/freepbx_chown.conf"
CHOWN_LINE="file = ${WRAPPER},0750,root,asterisk"
TMP_CHOWN_CONF="$(mktemp)"
if [ -f "$CHOWN_CONF" ]; then
    cp -p "$CHOWN_CONF" "$TMP_CHOWN_CONF"
else
    : > "$TMP_CHOWN_CONF"
fi
# Drop any pre-existing [custom] "file" entry for this exact path (from a
# prior run of this script, possibly with different perms) so we don't
# duplicate it; it's re-added below with the current, correct values.
awk -v path="$WRAPPER" '
    {
        stripped = $0
        gsub(/^[ \t]+/, "", stripped)
        if (stripped ~ /^file[ \t]*=/) {
            eq = index(stripped, "=")
            rest = substr(stripped, eq + 1)
            gsub(/^[ \t]+/, "", rest)
            n = split(rest, fields, ",")
            if (n >= 1 && fields[1] == path) next
        }
        print
    }
' "$TMP_CHOWN_CONF" > "${TMP_CHOWN_CONF}.clean"
mv "${TMP_CHOWN_CONF}.clean" "$TMP_CHOWN_CONF"

if grep -q '^\[custom\]' "$TMP_CHOWN_CONF"; then
    awk -v newline="$CHOWN_LINE" '
        { print }
        /^\[custom\]/ && !added { print newline; added=1 }
    ' "$TMP_CHOWN_CONF" > "${TMP_CHOWN_CONF}.2"
    mv "${TMP_CHOWN_CONF}.2" "$TMP_CHOWN_CONF"
else
    printf '\n[custom]\n%s\n' "$CHOWN_LINE" >> "$TMP_CHOWN_CONF"
fi
install -m 0644 -o root -g root "$TMP_CHOWN_CONF" "$CHOWN_CONF"
rm -f "$TMP_CHOWN_CONF"
echo "==> Registered ${WRAPPER} with fwconsole chown (${CHOWN_CONF})"
if command -v fwconsole >/dev/null 2>&1; then
    fwconsole chown >/dev/null 2>&1 || true
fi
# Re-apply directly too, in case fwconsole isn't on PATH or the version in
# use predates [custom] support in freepbx_chown.conf.
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

# --- 3. Whitelist the OpenVPN client pool in Fail2Ban ---
# This runs only from this root-only setup script, never from a web request.
# The helper derives the exact pool from legacy-vpn.conf and appends it
# idempotently to [DEFAULT] ignoreip while preserving existing entries.
FAIL2BAN_HELPER="${MODULE_DIR}/scripts/fail2ban-whitelist.py"
OPENVPN_CONF="${VPN_DATA_DIR}/legacy-vpn.conf"
if command -v fail2ban-client >/dev/null 2>&1; then
    if [ -f "$OPENVPN_CONF" ]; then
        F2B_LOCAL="/etc/fail2ban/jail.local"
        F2B_PREEXISTED=0
        F2B_SNAPSHOT="$(mktemp)"
        if [ -f "$F2B_LOCAL" ]; then
            F2B_PREEXISTED=1
            cp -p "$F2B_LOCAL" "$F2B_SNAPSHOT"
        fi
        F2B_OUTPUT="$(python3 "$FAIL2BAN_HELPER" "$OPENVPN_CONF" "$F2B_LOCAL")"
        echo "$F2B_OUTPUT" | sed '$d'
        if fail2ban-client -t >/dev/null 2>&1; then
            rm -f "$F2B_SNAPSHOT"
            if systemctl is-active --quiet fail2ban 2>/dev/null; then
                if ! fail2ban-client reload; then
                    echo "WARNING: Fail2Ban whitelist was saved, but reload failed. Check /etc/fail2ban/jail.local and Fail2Ban logs." >&2
                fi
            else
                echo "Fail2Ban is not active; the whitelist will apply when the service starts."
            fi
        else
            if [ "$F2B_PREEXISTED" -eq 1 ]; then
                cp -p "$F2B_SNAPSHOT" "$F2B_LOCAL"
            else
                rm -f "$F2B_LOCAL"
            fi
            rm -f "$F2B_SNAPSHOT"
            echo "WARNING: Fail2Ban config test failed; the attempted whitelist change was rolled back. Inspect Fail2Ban configuration before retrying." >&2
        fi
    else
        echo "WARNING: $OPENVPN_CONF not found; skipping Fail2Ban whitelist. Install ovpn_mgr first, then rerun setup-root.sh." >&2
    fi
else
    echo "Fail2Ban not detected; skipping VPN subnet whitelist."
fi

# --- 3b. Add the OpenVPN pool to FreePBX SIP Settings NAT Local Networks ---
# This is the supported Sipsettings BMO/KVStore setting, not a direct edit to
# generated sip.conf/pjsip.conf. The helper preserves existing Local Networks.
SIP_LOCALNET_HELPER="${MODULE_DIR}/scripts/sip-localnet-sync.php"
if [ -f "$OPENVPN_CONF" ] && [ -f "$SIP_LOCALNET_HELPER" ] && command -v php >/dev/null 2>&1; then
    SIP_SYNC_OUTPUT="$(php "$SIP_LOCALNET_HELPER" "$OPENVPN_CONF" 2>&1)"
    SIP_SYNC_RC=$?
    # Print helper output without interpreting its status as the sole signal:
    # FreePBX may emit a shutdown warning after setConfig/reload succeeded.
    printf '%s\n' "$SIP_SYNC_OUTPUT" | sed '/^SIP_LOCALNET_SYNC_OK$/d'
    if printf '%s\n' "$SIP_SYNC_OUTPUT" | grep -qx 'SIP_LOCALNET_SYNC_OK'; then
        if [ "$SIP_SYNC_RC" -ne 0 ]; then
            echo "SIP Settings Local Networks sync completed; PHP returned status ${SIP_SYNC_RC} after the successful save/reload marker."
        fi
    else
        echo "WARNING: Could not confirm the VPN subnet was synced into FreePBX SIP Settings Local Networks (helper exit ${SIP_SYNC_RC}). Review the message above and retry setup-root.sh." >&2
    fi
else
    echo "WARNING: OpenVPN config or SIP Local Networks helper unavailable; skipping FreePBX SIP Settings sync." >&2
fi

# --- 4. Persist IP forwarding ---
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-ovpn-mgr.conf
sysctl -p /etc/sysctl.d/99-ovpn-mgr.conf >/dev/null

# --- 5. NAT-rule persistence via a systemd unit (portable across distros -
#     deliberately does not write into any distro-specific rules file) ---
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

if command -v systemctl >/dev/null 2>&1; then
    # FreePBX periodically re-normalizes ownership/perms across the whole
    # admin/modules tree back to asterisk:asterisk (dirs 775, files 664),
    # including at boot. That silently undoes step 1 above (root:asterisk
    # 0750 on $WRAPPER), which is why the wrapper would go back to being
    # non-executable and the admin UI would ask you to rerun this whole
    # script after every reboot. Fix: reapply step 1 automatically, late in
    # boot, ordered after whatever FreePBX unit does that chown pass.
    FREEPBX_UNIT="$(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -im1 '^freepbx.*\.service$' || true)"
    FIXPERMS_AFTER="network-online.target"
    if [ -n "$FREEPBX_UNIT" ]; then
        FIXPERMS_AFTER="network-online.target ${FREEPBX_UNIT}"
    fi
    cat > "$FIXPERMS_UNIT_FILE" <<EOF
[Unit]
Description=Reapply ovpn_mgr ovpnctl ownership/permissions
After=${FIXPERMS_AFTER}
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'chown root:asterisk "${WRAPPER}" && chmod 750 "${WRAPPER}"'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$FIXPERMS_UNIT_FILE"

    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Reapply ovpn_mgr VPN NAT rule
After=network-online.target firewalld.service nftables.service netfilter-persistent.service iptables.service ovpn-mgr-fixperms.service
Requires=ovpn-mgr-fixperms.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${WRAPPER} nat-restore
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE"
    # OpenVPN itself must also be managed by systemd. Previously setup-root
    # started it interactively, but no enabled boot unit brought it back after
    # reboot; users had to rerun this entire setup script.
    cat > "$OPENVPN_UNIT_FILE" <<EOF
[Unit]
Description=ovpn_mgr OpenVPN server
After=network-online.target ovpn-mgr-nat.service
Wants=network-online.target
Requires=ovpn-mgr-nat.service

[Service]
Type=forking
PIDFile=${VPN_DATA_DIR}/openvpn.pid
ExecStart=${WRAPPER} start
ExecStop=${WRAPPER} stop
TimeoutStartSec=30
TimeoutStopSec=15
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE" "$OPENVPN_UNIT_FILE"
    systemctl daemon-reload
    systemctl enable ovpn-mgr-fixperms.service >/dev/null 2>&1 || true
    systemctl enable ovpn-mgr-nat.service >/dev/null 2>&1 || true
    systemctl enable ovpn-mgr-openvpn.service >/dev/null 2>&1 || true
    # Perms first, then NAT restored after network/firewall setup, then OpenVPN starts.
    if ! systemctl restart ovpn-mgr-fixperms.service; then
        echo "WARNING: ovpn-mgr-fixperms.service failed; ${WRAPPER} may not be root:asterisk 0750. Inspect: systemctl status ovpn-mgr-fixperms.service" >&2
    fi
    if ! systemctl restart ovpn-mgr-nat.service; then
        echo "WARNING: ovpn-mgr NAT restore service failed; inspect: systemctl status ovpn-mgr-nat.service" >&2
    fi
fi

# --- Directory ownership for module-managed files ---
mkdir -p "${VPN_DATA_DIR}/logs" 2>/dev/null || true
chown -R asterisk:asterisk "${VPN_DATA_DIR}" 2>/dev/null || true

# --- Start/restart OpenVPN under systemd so it also starts after reboot ---
echo "==> Enabling and restarting the OpenVPN systemd service..."
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl enable ovpn-mgr-openvpn.service >/dev/null 2>&1; then
        echo "WARNING: Could not enable ovpn-mgr-openvpn.service." >&2
    fi
    if ! systemctl restart ovpn-mgr-openvpn.service; then
        echo "WARNING: OpenVPN service did not start cleanly. Inspect: systemctl status ovpn-mgr-openvpn.service" >&2
        echo "         Recent logs: journalctl -u ovpn-mgr-openvpn.service -n 80 --no-pager" >&2
    fi
else
    "$WRAPPER" stop || true
    sleep 1
    "$WRAPPER" start || echo "    (start reported an error - check the module's log for details)"
fi

echo "Done."
echo "  - ${WRAPPER} is now root:asterisk 0750"
echo "  - ovpn-mgr-fixperms.service reapplies that ownership/mode on every boot,"
echo "    after FreePBX's own permission sweep runs, so this no longer needs to"
echo "    be re-run manually after a reboot"
echo "  - ${SUDOERS_FILE} grants 'asterisk' passwordless sudo on that script only"
echo "  - net.ipv4.ip_forward=1 persisted in /etc/sysctl.d/99-ovpn-mgr.conf"
echo "  - ovpn-mgr-nat.service will reapply the VPN's NAT rule on every boot"
echo "  - ovpn-mgr-openvpn.service is enabled to start OpenVPN on every boot"
echo "Reload the OpenVPN Manager admin page - the setup banner should clear."
