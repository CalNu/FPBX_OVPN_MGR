<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

$baseDir = '/var/www/html/PhoneSettings/openvpn';
$pidFile = "{$baseDir}/openvpn.pid";
$sudoersFile = '/etc/sudoers.d/openvpn_mgr';
$pkgDir = '/var/www/html/PhoneSettings/vpnkeys';

// Helper to run elevated non-interactive commands without disrupting TTY echo or line discipline
function safe_sudo_exec($cmd) {
    exec("sudo -n {$cmd} </dev/null >/dev/null 2>&1");
}

// Helper function to recursively delete module storage directory and files
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

if (is_dir($pkgDir)) {
    removeDirectoryRecursive($pkgDir);
}

// 1. Terminate any running OpenVPN processes started by the module
if (file_exists($pidFile)) {
    $pid = intval(trim((string)@file_get_contents($pidFile)));
    if ($pid > 0) {
        safe_sudo_exec("/bin/kill -9 {$pid}");
        safe_sudo_exec("/usr/bin/kill -9 {$pid}");
    }
}

// Global fallback process cleanup
safe_sudo_exec("/usr/bin/fuser -k -9 1194/udp");
safe_sudo_exec("/usr/bin/pkill -9 -f 'legacy-vpn'");
safe_sudo_exec("/usr/bin/pkill -9 -x openvpn");

// 2. Remove the elevated sudoers rule created by the module
if (file_exists($sudoersFile)) {
    safe_sudo_exec("/bin/rm -f " . escapeshellarg($sudoersFile));
}

// Clean up all generated configs, keys, logs, and provisioning archives
if (is_dir($baseDir)) {
    removeDirectoryRecursive($baseDir);
}

// 3. Unmask openvpn systemd services if masked on Debian/FreePBX 17
safe_sudo_exec("/bin/systemctl unmask openvpn openvpn@*");

// 4. Restore terminal echo AND fix shifted column alignment (stty sane)
if (function_exists('posix_isatty') && posix_isatty(STDOUT)) {
    system('stty sane 2>/dev/null');
}

clearstatcache();