<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

$ampWebRoot  = rtrim($amp_conf['AMPWEBROOT'] ?? '/var/www/html', '/');
$phoneSettingsDir = "{$ampWebRoot}/PhoneSettings";
// Matches install.php: this module's data lives under
// PhoneSettings/openvpn and PhoneSettings/vpnkeys, wherever
// PhoneSettings currently resolves to.
$baseDir     = "{$phoneSettingsDir}/openvpn";
$pkgDir      = "{$phoneSettingsDir}/vpnkeys";
$moduleDir   = __DIR__;
$ovpnctl     = "{$moduleDir}/scripts/ovpnctl";
$sudoersFile = '/etc/sudoers.d/ovpn_mgr';
$sysctlFile  = '/etc/sysctl.d/99-ovpn-mgr.conf';
$natStateDir = '/etc/ovpn_mgr';
$natUnitFile = '/etc/systemd/system/ovpn-mgr-nat.service';
$vpnUnitFile = '/etc/systemd/system/ovpn-mgr-openvpn.service';
$fixpermsUnitFile = '/etc/systemd/system/ovpn-mgr-fixperms.service';

// This uninstaller intentionally never deletes anything under
// PhoneSettings - not the CA, not client keys, not built packages, not
// PhoneSettings itself. Uninstalling the module removes the module's
// own code and its root-level hooks (sudoers rule, systemd units,
// module signature); it does not touch data. If you want that data
// gone, remove it yourself:
//   rm -rf /var/www/html/PhoneSettings/openvpn
//   rm -rf /var/www/html/PhoneSettings/vpnkeys

// 1. Stop the daemon via the scoped helper, if it was ever set up. This
//    only works if the admin ran setup-root.sh; if not, there is nothing
//    running as root for this module in the first place, so there is
//    nothing to escalate to stop it - a plain, unprivileged attempt to
//    signal our own pidfile-tracked process is enough in that case.
if (file_exists($ovpnctl)) {
    exec('sudo -n ' . escapeshellarg($ovpnctl) . ' stop 2>&1');
}
$pidFile = "{$baseDir}/openvpn.pid";
if (file_exists($pidFile)) {
    $pid = intval(trim((string)@file_get_contents($pidFile)));
    if ($pid > 0) {
        @posix_kill($pid, SIGTERM);
    }
    @unlink($pidFile);
}

// 2. We cannot remove root-owned artifacts ourselves - only root can,
//    same as installing them required root. This is a deliberate
//    manual step, not an oversight:
//
//      # stop and disable the module's three systemd units first
//      sudo systemctl disable --now ovpn-mgr-openvpn.service \
//                                   ovpn-mgr-nat.service \
//                                   ovpn-mgr-fixperms.service 2>/dev/null
//      sudo rm -f /etc/sudoers.d/ovpn_mgr \
//                 /etc/sysctl.d/99-ovpn-mgr.conf \
//                 /etc/systemd/system/ovpn-mgr-openvpn.service \
//                 /etc/systemd/system/ovpn-mgr-nat.service \
//                 /etc/systemd/system/ovpn-mgr-fixperms.service
//      sudo rm -rf /etc/ovpn_mgr
//      sudo systemctl daemon-reload
//      sudo systemctl reset-failed 'ovpn-mgr-*' 2>/dev/null
//
//    ($sudoersFile, $sysctlFile, $vpnUnitFile, $natUnitFile,
//    $fixpermsUnitFile, $natStateDir above list the exact paths for
//    reference.)
//
//    Optional, only if you also want the rest of setup-root.sh's changes
//    gone (none of these touch PhoneSettings, keys or packages):
//      - the "file = .../scripts/ovpnctl,0750,root,asterisk" line that
//        setup-root.sh added to /etc/asterisk/freepbx_chown.conf
//      - the VPN pool added to Fail2Ban's ignoreip (/etc/fail2ban/jail.local)
//      - the iptables rules commented OVPN_MGR_NAT / OVPN_MGR_PORT
//        (iptables -t nat -S POSTROUTING | grep OVPN_MGR_NAT, and
//        iptables -S INPUT | grep OVPN_MGR_PORT; they vanish on reboot
//        unless saved by your firewall tooling)
//      - the read-only ACL for 'asterisk' on the web server log directory
//        (setfacl -x u:asterisk <dir> and setfacl -k <dir>)
//
//    PhoneSettings/ is deliberately left alone: other modules (e.g. the
//    Yealink EPM) use it too, and the CA, client keys and built packages
//    live there. Deleting those is a separate, manual decision.

// 3. Remove module signature.
if (file_exists("{$moduleDir}/module.sig")) {
    @unlink("{$moduleDir}/module.sig");
}

// 4. Restore terminal TTY state if uninstalled via CLI/fwconsole.
if (php_sapi_name() === 'cli' && function_exists('posix_isatty') && defined('STDOUT') && posix_isatty(STDOUT)) {
    system('stty sane 2>/dev/null');
}

clearstatcache();
