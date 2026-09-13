<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

$baseDir = '/var/www/html/PhoneSettings/openvpn';
$pidFile = "{$baseDir}/openvpn.pid";
$sudoersFile = '/etc/sudoers.d/openvpn_mgr';

// 1. Terminate any running OpenVPN processes started by the module
if (file_exists($pidFile)) {
    $pid = intval(trim((string)@file_get_contents($pidFile)));
    if ($pid > 0) {
        exec("sudo /bin/kill -9 {$pid} >/dev/null 2>&1");
        exec("sudo /usr/bin/kill -9 {$pid} >/dev/null 2>&1");
    }
}

// Global fallback process cleanup
exec("sudo /usr/bin/fuser -k -9 1194/udp >/dev/null 2>&1");
exec("sudo /usr/bin/pkill -9 -f 'legacy-vpn' >/dev/null 2>&1");
exec("sudo /usr/bin/pkill -9 -x openvpn >/dev/null 2>&1");

// 2. Remove the elevated sudoers rule created by the module
if (file_exists($sudoersFile)) {
    exec("sudo /bin/rm -f " . escapeshellarg($sudoersFile) . " >/dev/null 2>&1");
}

// 3. Helper function to recursively delete module storage directory and files
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

// Clean up all generated configs, keys, logs, and provisioning archives
if (is_dir($baseDir)) {
    removeDirectoryRecursive($baseDir);
}

// 4. Unmask openvpn systemd services if masked on Debian/FreePBX 17
exec("sudo /bin/systemctl unmask openvpn openvpn@* >/dev/null 2>&1");

clearstatcache();