<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

$ampWebRoot  = rtrim($amp_conf['AMPWEBROOT'] ?? '/var/www/html', '/');
$tftpDir     = '/tftpboot';
$phoneSettingsDir = "{$ampWebRoot}/PhoneSettings";
// OpenVPN state is deliberately stored in the real web-root PhoneSettings
// directory. Never alias PhoneSettings to /tftpboot: doing so would put
// private PKI material in the TFTP tree (e.g. /tftpboot/openvpn).
if (is_link($phoneSettingsDir)) {
    die('ovpn_mgr: ' . htmlspecialchars($phoneSettingsDir) . ' is a symlink. This module requires a real PhoneSettings directory so OpenVPN data stays out of /tftpboot. Back up and migrate PhoneSettings/openvpn to the canonical web-root path, convert PhoneSettings to a real directory, then rerun module install.');
}
$baseDir     = "{$phoneSettingsDir}/openvpn";
if (is_dir("{$tftpDir}/openvpn") && !is_dir($baseDir)) {
    die('ovpn_mgr: Found legacy data at /tftpboot/openvpn but no canonical ' . htmlspecialchars($baseDir) . '. Back up and move the existing openvpn directory to the canonical PhoneSettings path before reinstalling; the installer will not move private keys automatically.');
}
$pkgDir      = "{$phoneSettingsDir}/vpnkeys";
$pkiDir      = "{$baseDir}/legacy_pki";
$serverConf  = "{$baseDir}/legacy-vpn.conf";
$logDir      = "{$baseDir}/logs";
$logFile     = "{$logDir}/openvpn.log";
$module_name = 'ovpn_mgr';
$module_root = __DIR__;

// This install script intentionally does NOT:
//   - prompt for or handle a root password
//   - write /etc/sudoers.d entries
//   - chown/symlink anything outside this module's own directories
// Everything that needs real root privilege (starting the daemon,
// touching iptables/sysctl) is done later via scripts/ovpnctl, which is
// only usable after the admin runs scripts/setup-root.sh once via SSH.
// See that script for details.

// 0. Directory initialization (all owned by the web/asterisk user this
//    installer itself runs as - no elevated privilege required).
// deploy_module_symlink() is always non-destructive: if $target already
// exists as a real (non-symlink) directory, it does nothing and returns
// false rather than deleting/replacing it. It only ever replaces an
// existing symlink (with an equivalent or updated one - never touching
// the real data at whatever that symlink points to) or creates a new
// symlink where nothing existed before.
if (!function_exists('deploy_module_symlink')) {
    function deploy_module_symlink($source, $target) {
        if (!file_exists($source) && !is_link($source)) {
            return false;
        }
        if (is_link($target) || file_exists($target)) {
            if (is_dir($target) && !is_link($target)) {
                return false;
            }
            @unlink($target);
        }
        if (@symlink($source, $target)) {
            @chown($target, 'asterisk');
            @chgrp($target, 'asterisk');
            return true;
        }
        return false;
    }
}

// Ensure PhoneSettings itself is a real directory. Do not create a
// PhoneSettings -> /tftpboot symlink; VPN private keys must never land
// in /tftpboot/openvpn.
if (!is_dir($phoneSettingsDir)) {
    @mkdir($phoneSettingsDir, 0775, true);
}

$directories = [
    $phoneSettingsDir,
    $tftpDir,
    $baseDir,
    $pkgDir,
    $pkiDir,
    "{$pkiDir}/private",
    "{$pkiDir}/issued",
    $logDir,
];

foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    @chown($dir, 'asterisk');
    @chgrp($dir, 'asterisk');
}

if (!file_exists($logFile)) {
    @touch($logFile);
}
@chown($logFile, 'asterisk');
@chgrp($logFile, 'asterisk');
@chmod($logFile, 0664);

// 0.1 Convenience cross-links for module access and provisioning. VPN
//     state itself is not linked into /tftpboot.
//     No touching of other modules' own directories - the old code used
//     to hijack admin/modules/yealink_epm here, which has been removed.
deploy_module_symlink($tftpDir, $module_root . '/tftpboot');            // module/tftpboot -> /tftpboot
deploy_module_symlink($phoneSettingsDir, $module_root . '/PhoneSettings'); // module/PhoneSettings -> PhoneSettings
deploy_module_symlink($module_root, $phoneSettingsDir . '/' . $module_name); // PhoneSettings/ovpn_mgr -> module
deploy_module_symlink($tftpDir, $phoneSettingsDir . '/tftpboot');       // PhoneSettings/tftpboot -> /tftpboot
deploy_module_symlink($module_root, $tftpDir . '/' . $module_name);    // tftpboot/ovpn_mgr -> module
deploy_module_symlink($phoneSettingsDir, $tftpDir . '/PhoneSettings'); // tftpboot/PhoneSettings -> PhoneSettings

// 1. Prevent directory browsing of the web-served phone-provisioning dirs.
foreach ([$baseDir, $pkgDir] as $webDir) {
    $htaccessFile = "{$webDir}/.htaccess";
    $htaccessContent = "Options -Indexes\n";
    if (!file_exists($htaccessFile) || file_get_contents($htaccessFile) !== $htaccessContent) {
        @file_put_contents($htaccessFile, $htaccessContent);
        @chmod($htaccessFile, 0644);
    }
    $indexFile = "{$webDir}/index.html";
    if (!file_exists($indexFile)) {
        @file_put_contents($indexFile, '<!-- Directory browsing disabled -->');
        @chmod($indexFile, 0644);
    }
}

// 2. Initialize PKI assets. Kept at rsa:1024/sha1 for compatibility with
//    old Yealink firmware (e.g. T28P) that cannot negotiate anything
//    stronger - this is a deliberate device-compatibility trade-off, not
//    an oversight, and is unrelated to the privilege-model fixes below.
if (!file_exists("{$pkiDir}/ca.crt") || !file_exists("{$pkiDir}/private/ca.key")) {
    exec("openssl req -x509 -new -nodes -sha1 -days 3650 -newkey rsa:1024 -keyout " . escapeshellarg("{$pkiDir}/private/ca.key") . " -out " . escapeshellarg("{$pkiDir}/ca.crt") . " -subj '/CN=Legacy-VPN-CA/' 2>&1");
}

if (!file_exists("{$pkiDir}/server.crt") || !file_exists("{$pkiDir}/private/server.key")) {
    exec("openssl req -new -nodes -sha1 -newkey rsa:1024 -keyout " . escapeshellarg("{$pkiDir}/private/server.key") . " -out " . escapeshellarg("{$pkiDir}/server.csr") . " -subj '/CN=legacy-vpn-server/' 2>&1");
    exec("openssl x509 -req -days 3650 -sha1 -in " . escapeshellarg("{$pkiDir}/server.csr") . " -CA " . escapeshellarg("{$pkiDir}/ca.crt") . " -CAkey " . escapeshellarg("{$pkiDir}/private/ca.key") . " -set_serial 1 -out " . escapeshellarg("{$pkiDir}/server.crt") . " 2>&1");
    @unlink("{$pkiDir}/server.csr");
}

if (!file_exists("{$pkiDir}/dh.pem")) {
    exec("openssl dhparam -dsaparam -out " . escapeshellarg("{$pkiDir}/dh.pem") . " 1024 2>&1");
}

@chmod("{$pkiDir}/private/server.key", 0600);

// 3. Generate legacy-vpn.conf
$rawServerIp = '';
exec("ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}'", $ipOut);
if (!empty($ipOut[0]) && filter_var(trim($ipOut[0]), FILTER_VALIDATE_IP)) {
    $rawServerIp = trim($ipOut[0]);
}
if (empty($rawServerIp) || strpos($rawServerIp, '127.') === 0) {
    $rawServerIp = $_SERVER['SERVER_ADDR'] ?? '192.168.1.1';
}

$serverSubnet = '255.255.255.0';
$longIp = ip2long($rawServerIp);
$longMask = ip2long($serverSubnet);
$serverLanNet = ($longIp !== false && $longMask !== false)
    ? long2ip($longIp & $longMask)
    : '192.168.1.0';

if (!file_exists($serverConf)) {
    // "tls-cert-profile insecure" and "providers legacy default" are
    // OpenSSL-3-only directives - OpenVPN linked against OpenSSL 1.1
    // (still the case on some CentOS7/FreePBX-Distro and older Debian
    // installs) will refuse to start with an "unknown option" error if
    // these are present. Only emit them when they'll actually be understood.
    $opensslVersionOutput = '';
    exec('openssl version 2>&1', $opensslVersionOutputLines);
    if (!empty($opensslVersionOutputLines[0])) {
        $opensslVersionOutput = $opensslVersionOutputLines[0];
    }
    
    // Parse major and minor version numbers (e.g., 1.0 from "1.0.2k", 1.1, 3.0)
    $opensslMajor = 0;
    $opensslMinor = 0;
    if (preg_match('/OpenSSL\s+(\d+)\.(\d+)\./i', $opensslVersionOutput, $mOssl)) {
        $opensslMajor = intval($mOssl[1]);
        $opensslMinor = intval($mOssl[2]);
    }

    if ($opensslMajor >= 3) {
        // OpenSSL 3.x (FreePBX 17 / Debian 12)
        $legacyTlsLines = "tls-cert-profile insecure\ntls-cipher \"DEFAULT\"\nproviders legacy default\n";
    } elseif ($opensslMajor === 1 && $opensslMinor >= 1) {
        // OpenSSL 1.1.x (Supports @SECLEVEL)
        $legacyTlsLines = "tls-cipher \"DEFAULT:@SECLEVEL=0\"\n";
    } else {
        // OpenSSL 1.0.x (FreePBX 16 / CentOS 7 - @SECLEVEL is invalid syntax)
        $legacyTlsLines = "tls-cipher \"DEFAULT\"\n";
    }

    $serverConfigContent = <<<CONF
port 1194
proto udp
dev tun
ca {$pkiDir}/ca.crt
cert {$pkiDir}/server.crt
key {$pkiDir}/private/server.key
dh {$pkiDir}/dh.pem
server 10.1.0.0 255.255.255.0
push "route {$rawServerIp} 255.255.255.255"
keepalive 10 120

cipher AES-128-CBC
auth SHA1
data-ciphers AES-128-CBC
data-ciphers-fallback AES-128-CBC

tls-version-min 1.0
{$legacyTlsLines}
duplicate-cn
topology subnet
persist-key
persist-tun
status {$logDir}/openvpn-status.log 1
log {$logFile}
verb 3
CONF;
    file_put_contents($serverConf, $serverConfigContent);
}

// 4. Ownership/permissions within our own directories only.
@exec("chown -R asterisk:asterisk " . escapeshellarg($baseDir) . " " . escapeshellarg($pkgDir) . " " . escapeshellarg($module_root) . " 2>&1");
@exec("chmod -R 775 " . escapeshellarg($baseDir) . " " . escapeshellarg($pkgDir) . " 2>&1");
@chown($logFile, 'asterisk');
@chmod($logFile, 0664);

// 5. Module signature (no elevated privilege needed - module dir is
//    already owned by the web user).
$signerScript = "{$module_root}/devtools/signer.php";
if (file_exists($signerScript)) {
    @chmod($signerScript, 0755);
    exec("/usr/bin/php " . escapeshellarg($signerScript) . " " . escapeshellarg($module_root) . " >/dev/null 2>&1");
}

// 6. Prepare (but do not activate) the privileged helper(s). Left owned
//    by the web user with mode 0755 so they can be inspected/used
//    directly as-is (generate_client.sh doesn't itself need elevated
//    privilege); running setup-root.sh as root additionally re-chowns
//    them to root:asterisk 0750 and installs a matching sudoers rule,
//    needed only if an external caller invokes them with "sudo".
//    Nothing here writes to /etc/sudoers.d or requires a root password.
$ovpnctl = "{$module_root}/scripts/ovpnctl";
$genClient = "{$module_root}/scripts/generate_client.sh";
$setupScript = "{$module_root}/scripts/setup-root.sh";
if (file_exists($ovpnctl)) {
    @chmod($ovpnctl, 0755);
}
if (file_exists($genClient)) {
    @chmod($genClient, 0755);
}
if (file_exists($setupScript)) {
    @chmod($setupScript, 0755);
}

// ============================================================================
// 7. Isolated Directory Overrides (Prevents 403 Forbidden)
// ============================================================================
// Directory listing is enabled for provisioning/admin convenience on the LAN,
// but access is restricted to private (RFC1918) address space plus loopback so
// these folders (which contain MAC-named cfg files with SIP secrets) are never
// reachable from outside the intranet, even if this host is ever dual-homed or
// accidentally port-forwarded. Adjust the ranges below if your LAN uses a
// different scheme (e.g. add more specific subnets, or remove ranges you don't use).
$htaccess_content = <<<EOT
Options +Indexes
DirectoryIndex disabled

<IfModule mod_authz_core.c>
    Require ip 127.0.0.1
    Require ip ::1
    Require ip 10.0.0.0/8
    Require ip 172.16.0.0/12
    Require ip 192.168.0.0/16
    Require ip fc00::/7
</IfModule>
<IfModule !mod_authz_core.c>
    Order deny,allow
    Deny from all
    Allow from 127.0.0.1
    Allow from 10.0.0.0/8
    Allow from 172.16.0.0/12
    Allow from 192.168.0.0/16
</IfModule>

IndexIgnore openvpn ovpn_mgr vpnkeys yealink_epm ovpn_mgr_backup_*.tar.gz

EOT;

// Written to the canonical web-root PhoneSettings directory. This is
// intentionally not /tftpboot and must not be a symlink to it.
$htaccess_path = "{$phoneSettingsDir}/.htaccess";
if (!file_exists($htaccess_path) || file_get_contents($htaccess_path) !== $htaccess_content) {
    @file_put_contents($htaccess_path, $htaccess_content);
    @chown($htaccess_path, 'asterisk');
    @chmod($htaccess_path, 0644);
}


