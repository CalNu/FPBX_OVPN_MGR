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

// This uninstaller intentionally never deletes anything under
// PhoneSettings - not the CA, not client keys, not built packages, not
// PhoneSettings itself. Uninstalling the module removes the module's
// own code and its root-level hooks (sudoers rule, systemd unit,
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
//    one-line manual step, not an oversight:
//
//      sudo rm -f /etc/sudoers.d/ovpn_mgr \
//                 /etc/sysctl.d/99-ovpn-mgr.conf \
//                 /etc/systemd/system/ovpn-mgr-nat.service
//      sudo rm -rf /etc/ovpn_mgr
//      sudo systemctl disable ovpn-mgr-nat.service 2>/dev/null
//      sudo systemctl daemon-reload
//
//    ($sudoersFile, $sysctlFile, $natUnitFile, $natStateDir above list
//    the exact paths for reference.)

// 3. Remove module signature.
if (file_exists("{$moduleDir}/module.sig")) {
    @unlink("{$moduleDir}/module.sig");
}

// 4. Restore terminal TTY state if uninstalled via CLI/fwconsole.
if (php_sapi_name() === 'cli' && function_exists('posix_isatty') && defined('STDOUT') && posix_isatty(STDOUT)) {
    system('stty sane 2>/dev/null');
}

clearstatcache();
