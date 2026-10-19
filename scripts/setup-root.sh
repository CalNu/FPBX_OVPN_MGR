#!/bin/bash
#
# setup-root.sh - one-time privileged setup for the ovpn_mgr module.
#
# Run this yourself, once, from an SSH/console root shell:
#
#     sudo bash /path/to/admin/modules/ovpn_mgr/scripts/setup-root.sh
#
# Add --restart-vpn to also restart the OpenVPN daemon (drops connected
# phones). Without it a healthy running daemon is left alone.
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
#   6. Grants 'asterisk' read-only ACL access to the web server's access
#      log (httpd/apache2/nginx), so the Yealink EPM subnet scanner can
#      learn MACs of phones behind a routed OpenVPN tunnel.
#
# It is written to be distro-agnostic: it doesn't assume the FreePBX
# Distro, a script-installed Debian box, or Incredible PBX - only that
# systemd and sudo are present, which all three provide.

set -euo pipefail

# Re-running this script no longer restarts a healthy OpenVPN daemon (which
# drops every connected phone). Pass --restart-vpn to force a restart, e.g.
# after an upgrade whose changelog says the daemon must be restarted.
FORCE_RESTART=0
OVPN_UNIT_CHANGED=1
for arg in "$@"; do
    [ "$arg" = "--restart-vpn" ] && FORCE_RESTART=1
done

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
# Second ("modern") OpenVPN instance: its own unit, and a root-owned shim
# that runs ovpnctl against it. The shim lives OUTSIDE the module directory
# on purpose: the module directory is writable by the web user, a sudo-able
# script there would be a root escalation. /usr/local/sbin is root-only.
MODERN_UNIT_FILE="/etc/systemd/system/ovpn-mgr-openvpn-modern.service"
MODERN_SHIM="/usr/local/sbin/ovpn_mgr-ctl-modern"
FIXPERMS_UNIT_FILE="/etc/systemd/system/ovpn-mgr-fixperms.service"
FIXPERMS_WATCH_UNIT_FILE="/etc/systemd/system/ovpn-mgr-fixperms-watch.service"
FIXPERMS_PATH_UNIT_FILE="/etc/systemd/system/ovpn-mgr-fixperms.path"
FIXPERMS_HELPER="/etc/ovpn_mgr/fixperms.sh"

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
MODERN_CONF="${VPN_DATA_DIR}/modern-vpn.conf"
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
# Apply the perms directly instead of shelling out to `fwconsole chown` here:
# that command does a full recursive rescan/rechown of admin/modules and can
# take a minute or more, and it buys us nothing extra right now since the
# direct chown/chmod below produces the identical end state immediately.
# The [custom] entry we just wrote is what matters going forward - any
# *future* fwconsole chown run (cron, GUI actions, or our own
# ovpn-mgr-fixperms.service at boot) will already honor it.
chown root:asterisk "$WRAPPER"
chmod 750 "$WRAPPER"

# --- 1b. Root-owned shim for the modern OpenVPN instance ---
# ovpnctl addresses an instance through an optional last argument. The shim
# fixes that argument to "modern", so the web GUI can drive the second daemon
# through a plain script path.
mkdir -p "$(dirname "$MODERN_SHIM")"
cat > "$MODERN_SHIM" <<SHIM_EOF
#!/bin/bash
exec "${WRAPPER}" "\$@" modern
SHIM_EOF
chown root:asterisk "$MODERN_SHIM"
chmod 750 "$MODERN_SHIM"
echo "==> Installed ${MODERN_SHIM} (root:asterisk 0750)"

# --- 2. Sudoers rule, scoped to exactly these two scripts ---
TMP_SUDOERS="$(mktemp)"
echo "asterisk ALL=(root) NOPASSWD: ${WRAPPER}, ${MODERN_SHIM}" > "$TMP_SUDOERS"

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
FAIL2BAN_HELPER="${MODULE_DIR}/scripts/fail2ban-whitelist.php"
OPENVPN_CONF="${VPN_DATA_DIR}/legacy-vpn.conf"
if ! command -v php >/dev/null 2>&1; then
    echo "WARNING: php not found; skipping Fail2Ban whitelist." >&2
elif command -v fail2ban-client >/dev/null 2>&1; then
    if [ -f "$OPENVPN_CONF" ]; then
        F2B_LOCAL="/etc/fail2ban/jail.local"
        F2B_PREEXISTED=0
        F2B_SNAPSHOT="$(mktemp)"
        if [ -f "$F2B_LOCAL" ]; then
            F2B_PREEXISTED=1
            cp -p "$F2B_LOCAL" "$F2B_SNAPSHOT"
        fi
        # Capture the helper's exit code without letting `set -e` abort the
        # rest of the setup (SIP sync, ip_forward, systemd units) if it fails.
        F2B_RC=0
        F2B_OUTPUT="$(php "$FAIL2BAN_HELPER" "$OPENVPN_CONF" "$F2B_LOCAL" 2>&1)" || F2B_RC=$?
        if [ "$F2B_RC" -ne 0 ]; then
            rm -f "$F2B_SNAPSHOT"
            echo "WARNING: Fail2Ban whitelist helper failed (exit ${F2B_RC}); skipping the whitelist. ${F2B_OUTPUT}" >&2
            F2B_OUTPUT=""
        else
            echo "$F2B_OUTPUT" | sed '$d'
        fi
        if [ "$F2B_RC" -ne 0 ]; then
            :
        elif fail2ban-client -t >/dev/null 2>&1; then
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

# --- 3a. Same whitelist for the modern instance's pool (if it exists) ---
if [ -f "$MODERN_CONF" ] && command -v php >/dev/null 2>&1 && command -v fail2ban-client >/dev/null 2>&1; then
    F2B_LOCAL="/etc/fail2ban/jail.local"
    F2B_SNAP_M="$(mktemp)"
    F2B_HAD_M=0
    if [ -f "$F2B_LOCAL" ]; then F2B_HAD_M=1; cp -p "$F2B_LOCAL" "$F2B_SNAP_M"; fi
    if php "$FAIL2BAN_HELPER" "$MODERN_CONF" "$F2B_LOCAL" >/dev/null 2>&1; then
        if fail2ban-client -t >/dev/null 2>&1; then
            systemctl is-active --quiet fail2ban 2>/dev/null && { fail2ban-client reload >/dev/null 2>&1 || true; }
            echo "Whitelisted the modern VPN pool in Fail2Ban."
        else
            if [ "$F2B_HAD_M" -eq 1 ]; then cp -p "$F2B_SNAP_M" "$F2B_LOCAL"; else rm -f "$F2B_LOCAL"; fi
            echo "WARNING: Fail2Ban config test failed; the modern pool whitelist was rolled back." >&2
        fi
    else
        echo "WARNING: could not add the modern VPN pool to the Fail2Ban whitelist." >&2
    fi
    rm -f "$F2B_SNAP_M"
fi

# --- 3b. Add the OpenVPN pool to FreePBX SIP Settings NAT Local Networks ---
# This is the supported Sipsettings BMO/KVStore setting, not a direct edit to
# generated sip.conf/pjsip.conf. The helper preserves existing Local Networks.
SIP_LOCALNET_HELPER="${MODULE_DIR}/scripts/sip-localnet-sync.php"
if [ -f "$OPENVPN_CONF" ] && [ -f "$SIP_LOCALNET_HELPER" ] && command -v php >/dev/null 2>&1; then
    # The php helper can legitimately exit non-zero even after it already
    # succeeded (e.g. a FreePBX shutdown-function warning fired after
    # setConfig/reload went through) - that's exactly why the
    # SIP_LOCALNET_SYNC_OK marker check below exists. But a plain
    # VAR="$(cmd)" assignment where cmd exits non-zero trips `set -e`
    # immediately, killing the whole script right here - before the marker
    # check ever runs, and silently (nothing printed, since the output is
    # inside the command substitution). That silently skipped every step
    # after this one on every run where the helper returned non-zero,
    # including persisting net.ipv4.ip_forward and installing/starting the
    # systemd units. Capture the exit code without letting it abort us.
    SIP_SYNC_RC=0
    SIP_SYNC_OUTPUT="$(php "$SIP_LOCALNET_HELPER" "$OPENVPN_CONF" 2>&1)" || SIP_SYNC_RC=$?
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

# --- 3b2. Same SIP Local Networks entry for the modern instance's pool ---
if [ -f "$MODERN_CONF" ] && [ -f "$SIP_LOCALNET_HELPER" ] && command -v php >/dev/null 2>&1; then
    SIP_M_OUT="$(php "$SIP_LOCALNET_HELPER" "$MODERN_CONF" 2>&1)" || true
    if printf '%s\n' "$SIP_M_OUT" | grep -qx 'SIP_LOCALNET_SYNC_OK'; then
        echo "Synced the modern VPN pool into FreePBX SIP Settings Local Networks."
    else
        echo "WARNING: Could not confirm the modern VPN pool was synced into SIP Settings Local Networks: ${SIP_M_OUT}" >&2
    fi
fi

# --- 3c. Grant 'asterisk' read access to the web server's access log -------
# A routed OpenVPN tunnel never puts the phone's MAC in the PBX's ARP table,
# so the Yealink EPM module's subnet scanner learns those MACs the only way
# it can: by reading the phone's own provisioning request (".../<mac>.cfg")
# out of the web server's access log. That log is owned by the web server,
# not 'asterisk', so without an explicit grant is_readable() fails and the
# scanner reports every routed-tunnel client as unresolved.
#
# A POSIX ACL is used instead of `usermod -aG <log-group> asterisk` for two
# reasons: it takes effect immediately (group membership only applies to
# processes started after the change, so PHP-FPM/Apache/Nginx would need a
# restart), and it grants read on just this one log rather than every log
# owned by that group. A *default* ACL is also set on the directory so
# logs recreated later by logrotate inherit the same read grant automatically
# - this script does not need to be rerun after every rotation.
ACCESS_LOG_DIRS=(/var/log/httpd /var/log/apache2 /var/log/nginx)
if ! command -v setfacl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y acl >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y acl >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y acl >/dev/null 2>&1 || true
    fi
fi
if command -v setfacl >/dev/null 2>&1; then
    ACL_GRANTED=0
    for dir in "${ACCESS_LOG_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        if setfacl -m u:asterisk:rx "$dir" 2>/dev/null && setfacl -d -m u:asterisk:r "$dir" 2>/dev/null; then
            # Cover logs that already exist (including already-rotated ones),
            # not just ones logrotate creates from here on.
            find "$dir" -maxdepth 1 -type f -iname '*access*' -print0 2>/dev/null \
                | xargs -0 -r setfacl -m u:asterisk:r 2>/dev/null || true
            ACL_GRANTED=1
            echo "==> Granted 'asterisk' read access to $dir (ACL; future rotated logs are covered too)"
        else
            echo "WARNING: setfacl failed on $dir - the filesystem may not support ACLs (needs the 'acl' mount option, default on modern ext4/xfs). Grant $dir read access to 'asterisk' manually." >&2
        fi
    done
    if [ "$ACL_GRANTED" -eq 0 ]; then
        echo "WARNING: No web server access log directory found among: ${ACCESS_LOG_DIRS[*]}. The subnet scanner won't resolve phones behind a routed VPN tunnel until one exists; rerun this script once the web server is installed." >&2
    fi
else
    echo "WARNING: 'setfacl' not found and could not be installed automatically (install your distro's 'acl' package, then rerun this script). Until then the subnet scanner can't read the web server's access log, so it won't resolve phones behind a routed VPN tunnel." >&2
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

    # Module upgrades/re-uploads replace scripts/ovpnctl with a fresh copy that
    # is asterisk:asterisk 0644 (not executable), which breaks the sudo rule
    # until this script is re-run. The helper below lives OUTSIDE the module
    # directory (root-only /etc/ovpn_mgr) so root never executes a file the
    # web user can write. It is a no-op when the wrapper is already correct,
    # which also keeps the path unit from retriggering itself on its own chown.
    cat > "$FIXPERMS_HELPER" <<EOF
#!/bin/bash
W="${WRAPPER}"
[ -e "\$W" ] || exit 0
if [ -L "\$W" ]; then
    echo "ovpn_mgr: \$W is a symlink; refusing to change it" >&2
    exit 1
fi
[ "\$(stat -c '%U:%G:%a' "\$W")" = "root:asterisk:750" ] && exit 0
chown root:asterisk "\$W" && chmod 750 "\$W"
EOF
    chown root:root "$FIXPERMS_HELPER"
    chmod 700 "$FIXPERMS_HELPER"

    cat > "$FIXPERMS_WATCH_UNIT_FILE" <<EOF
[Unit]
Description=Re-lock ovpn_mgr ovpnctl after a module upgrade

[Service]
Type=oneshot
ExecStart=${FIXPERMS_HELPER}
EOF
    cat > "$FIXPERMS_PATH_UNIT_FILE" <<EOF
[Unit]
Description=Watch ovpn_mgr ovpnctl for replacement (module upgrade)

[Path]
PathChanged=${WRAPPER}
Unit=ovpn-mgr-fixperms-watch.service

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$FIXPERMS_WATCH_UNIT_FILE" "$FIXPERMS_PATH_UNIT_FILE"

    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Reapply ovpn_mgr VPN NAT and firewall-port rules
After=network-online.target firewalld.service nftables.service netfilter-persistent.service iptables.service ovpn-mgr-fixperms.service
Requires=ovpn-mgr-fixperms.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${WRAPPER} nat-restore
ExecStart=${WRAPPER} port-restore
ExecStart=${WRAPPER} nat-restore modern
ExecStart=${WRAPPER} port-restore modern
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE"
    # OpenVPN itself must also be managed by systemd. Previously setup-root
    # started it interactively, but no enabled boot unit brought it back after
    # reboot; users had to rerun this entire setup script.
    OLD_OVPN_UNIT_SUM="$(cksum < "$OPENVPN_UNIT_FILE" 2>/dev/null || echo none)"
    cat > "$OPENVPN_UNIT_FILE" <<EOF
[Unit]
Description=ovpn_mgr OpenVPN server
After=network-online.target ovpn-mgr-nat.service
Wants=network-online.target
# Ordering only (no Requires= on ovpn-mgr-nat.service): at boot the NAT unit is
# enabled on its own and runs first; a GUI Start must not drag it in and
# re-run nat-restore/port-restore every time.
# Don't retry forever if the daemon can't start (e.g. missing TUN device).
# ovpnctl start clears this with reset-failed before a manual/GUI start.
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=forking
PIDFile=${VPN_DATA_DIR}/openvpn.pid
# The unit calls start-daemon/stop-daemon (the real launch/stop). The plain
# "start"/"stop" commands are what the web GUI calls via sudo: they delegate
# to this unit so the daemon runs here, outside php-fpm's sandbox
# (PrivateDevices, read-only /etc, cgroup), instead of as a child of PHP.
ExecStart=${WRAPPER} start-daemon
ExecStop=${WRAPPER} stop-daemon
TimeoutStartSec=30
TimeoutStopSec=15
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE" "$OPENVPN_UNIT_FILE"
    # Second daemon, same shape: only the pid file and the instance argument differ.
    cat > "$MODERN_UNIT_FILE" <<EOF
[Unit]
Description=ovpn_mgr OpenVPN server (modern instance)
After=network-online.target ovpn-mgr-nat.service
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=forking
PIDFile=${VPN_DATA_DIR}/openvpn-modern.pid
ExecStart=${WRAPPER} start-daemon modern
ExecStop=${WRAPPER} stop-daemon modern
TimeoutStartSec=30
TimeoutStopSec=15
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$MODERN_UNIT_FILE"
    if [ "$OLD_OVPN_UNIT_SUM" = "$(cksum < "$OPENVPN_UNIT_FILE")" ]; then
        OVPN_UNIT_CHANGED=0
    fi
    systemctl daemon-reload
    systemctl enable ovpn-mgr-fixperms.service >/dev/null 2>&1 || true
    systemctl enable ovpn-mgr-fixperms.path >/dev/null 2>&1 || true
    systemctl enable ovpn-mgr-nat.service >/dev/null 2>&1 || true
    systemctl enable ovpn-mgr-openvpn.service >/dev/null 2>&1 || true
    if [ -f "$MODERN_CONF" ]; then
        systemctl enable ovpn-mgr-openvpn-modern.service >/dev/null 2>&1 || true
    fi
    # Perms first, then NAT restored after network/firewall setup, then OpenVPN starts.
    if ! systemctl restart ovpn-mgr-fixperms.service; then
        echo "WARNING: ovpn-mgr-fixperms.service failed; ${WRAPPER} may not be root:asterisk 0750. Inspect: systemctl status ovpn-mgr-fixperms.service" >&2
    fi
    if ! systemctl restart ovpn-mgr-fixperms.path; then
        echo "WARNING: ovpn-mgr-fixperms.path failed; module upgrades will need setup-root.sh or fwconsole chown. Inspect: systemctl status ovpn-mgr-fixperms.path" >&2
    fi
    if ! systemctl restart ovpn-mgr-nat.service; then
        echo "WARNING: ovpn-mgr NAT restore service failed; inspect: systemctl status ovpn-mgr-nat.service" >&2
    fi
fi

# --- Directory ownership for module-managed files ---
mkdir -p "${VPN_DATA_DIR}/logs-legacy" 2>/dev/null || true
chown -R asterisk:asterisk "${VPN_DATA_DIR}" 2>/dev/null || true

# --- Start/restart OpenVPN under systemd so it also starts after reboot ---
echo "==> Enabling the OpenVPN systemd service (restarting only if needed)..."
if command -v systemctl >/dev/null 2>&1; then
    if [ "$FORCE_RESTART" != "1" ] && [ "$OVPN_UNIT_CHANGED" = "0" ] \
       && systemctl is-active --quiet ovpn-mgr-openvpn.service; then
        # Already running under an unchanged unit: leave it alone so phones
        # stay connected. (Enable is idempotent and doesn't touch the process.)
        systemctl enable ovpn-mgr-openvpn.service >/dev/null 2>&1 || true
        echo "    OpenVPN is already running under systemd; leaving it (and its"
        echo "    connected clients) untouched. Use --restart-vpn to restart it."
    else
        # Clear any daemon that was launched outside the unit (older versions
        # started it from the web GUI, i.e. inside php-fpm's cgroup) so the
        # unit owns the process from here on.
        "$WRAPPER" stop-daemon || true
        if ! systemctl enable ovpn-mgr-openvpn.service >/dev/null 2>&1; then
            echo "WARNING: Could not enable ovpn-mgr-openvpn.service." >&2
        fi
        if ! systemctl restart ovpn-mgr-openvpn.service; then
            echo "WARNING: OpenVPN service did not start cleanly. Inspect: systemctl status ovpn-mgr-openvpn.service" >&2
            echo "         Recent logs: journalctl -u ovpn-mgr-openvpn.service -n 80 --no-pager" >&2
        fi
    fi
else
    "$WRAPPER" stop || true
    sleep 1
    "$WRAPPER" start || echo "    (start reported an error - check the module's log for details)"
fi

# --- Modern instance: run it under its own unit (once install has created it) ---
if [ -f "$MODERN_CONF" ] && command -v systemctl >/dev/null 2>&1; then
    echo "==> Enabling the modern OpenVPN instance (udp/$(awk '$1=="port"{print $2; exit}' "$MODERN_CONF" 2>/dev/null))..."
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ "$FORCE_RESTART" != "1" ] && systemctl is-active --quiet ovpn-mgr-openvpn-modern.service && [ -f "${VPN_DATA_DIR}/openvpn-modern.pid" ]; then
        systemctl enable ovpn-mgr-openvpn-modern.service >/dev/null 2>&1 || true
        echo "    Already running under systemd; leaving it (and its clients) untouched."
    else
        "$WRAPPER" stop-daemon modern || true
        systemctl enable ovpn-mgr-openvpn-modern.service >/dev/null 2>&1 || true
        if ! systemctl restart ovpn-mgr-openvpn-modern.service; then
            echo "WARNING: The modern OpenVPN service did not start cleanly. Inspect: systemctl status ovpn-mgr-openvpn-modern.service" >&2
            echo "         Recent logs: journalctl -u ovpn-mgr-openvpn-modern.service -n 80 --no-pager" >&2
        fi
    fi
fi

# --- FreePBX Firewall: register both instances (port service, trusted subnet, descriptions) ---
# Done here, with the daemons up, so a fresh install is complete without a Restart from the GUI.
echo "==> Registering the OpenVPN instances with FreePBX Firewall..."
"$WRAPPER" fw-register || echo "    (firewall registration reported an error - a Restart from the GUI will retry it)"

echo "Done."
echo "  - ${MODERN_SHIM} lets 'asterisk' drive the modern instance (root:asterisk 0750, same sudoers rule)"
echo "  - ${WRAPPER} is now root:asterisk 0750"
echo "  - ovpn-mgr-fixperms.service reapplies that ownership/mode on every boot,"
echo "    after FreePBX's own permission sweep runs, so this no longer needs to"
echo "    be re-run manually after a reboot"
echo "  - ovpn-mgr-fixperms.path re-applies it automatically after a module upgrade"
echo "  - ${SUDOERS_FILE} grants 'asterisk' passwordless sudo on that script only"
echo "  - net.ipv4.ip_forward=1 persisted in /etc/sysctl.d/99-ovpn-mgr.conf"
echo "  - ovpn-mgr-nat.service will reapply the VPN's NAT rule, and (on hosts"
echo "    without FreePBX's own Firewall module) its UDP port rule, on every boot"
echo "  - ovpn-mgr-openvpn.service is enabled to start OpenVPN on every boot"
echo "  - 'asterisk' was granted read-only ACL access to the web server's access"
echo "    log (see warnings above if that could not be completed), so the Yealink"
echo "    EPM subnet scanner can resolve phones behind a routed VPN tunnel"
echo "Reload the OpenVPN Manager admin page - the setup banner should clear."