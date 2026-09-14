<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

$baseDir = '/var/www/html/PhoneSettings/openvpn';
$pkgDir = '/var/www/html/PhoneSettings/vpnkeys';
$pidFile = "{$baseDir}/openvpn.pid";
$sudoersFile = '/etc/sudoers.d/openvpn_mgr';

// Helper to run elevated non-interactive commands cleanly
function safe_sudo_exec($cmd) {
    exec("sudo -n {$cmd} </dev/null >/dev/null 2>&1");
}

// Helper function to recursively delete directories and contents
function removeDirectoryRecursive($dir) {
    if (!is_dir($dir)) {
        return;
    }
    
    $items = scandir($dir);
    if ($items === false) {
        return;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $path = $dir . '/' . $item;
        if (is_dir($path) && !is_link($path)) {
            removeDirectoryRecursive($path);
        } else {
            @unlink($path);
        }
    }

    @rmdir($dir);
}

// 1. Terminate running OpenVPN processes
if (file_exists($pidFile)) {
    $pid = intval(trim((string)@file_get_contents($pidFile)));
    if ($pid > 0) {
        safe_sudo_exec("/bin/kill -9 {$pid}");
        safe_sudo_exec("/usr/bin/kill -9 {$pid}");
    }
}

safe_sudo_exec("/usr/bin/fuser -k -9 1194/udp");
safe_sudo_exec("/usr/bin/pkill -9 -f 'legacy-vpn'");
safe_sudo_exec("/usr/bin/pkill -9 -x openvpn");

// 2. Remove elevated sudoers authorizations
if (file_exists($sudoersFile)) {
    safe_sudo_exec("/bin/rm -f " . escapeshellarg($sudoersFile));
}

// 3. Remove generated VPN keys, packages, configs, and logs
if (is_dir($pkgDir)) {
    removeDirectoryRecursive($pkgDir);
}

if (is_dir($baseDir)) {
    removeDirectoryRecursive($baseDir);
}

// 4. Remove module signature and local devtools remnants
$moduleDir = '/var/www/html/admin/modules/ovpn_mgr';
if (file_exists("{$moduleDir}/module.sig")) {
    @unlink("{$moduleDir}/module.sig");
}

// 5. Unmask systemd OpenVPN services
safe_sudo_exec("/bin/systemctl unmask openvpn openvpn@* openvpn-server@*");

// 6. Restore terminal TTY state if uninstalled via CLI/fwconsole
if (php_sapi_name() === 'cli' && function_exists('posix_isatty') && defined('STDOUT') && posix_isatty(STDOUT)) {
    system('stty sane 2>/dev/null');
}

clearstatcache();