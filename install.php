<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

$baseDir = '/var/www/html/PhoneSettings/openvpn';
$pkgDir = '/var/www/html/PhoneSettings/vpnkeys';
$pkiDir = "{$baseDir}/legacy_pki";
$tftpDir = '/tftpboot';
$serverConf = "{$baseDir}/legacy-vpn.conf";

//  Add Simlinks for Related Folders
deploy_module_symlink('/tftpboot', $module_root . '/tftpboot');
deploy_module_symlink('../../../PhoneSettings', $module_root . '/PhoneSettings');
deploy_module_symlink('../yealink_epm', $module_root . '/yealink_epm');

// 1. Create Web & Provisioning Directories
$directories = [$baseDir, $pkgDir, $pkiDir, "{$pkiDir}/private", "{$pkiDir}/issued", $tftpDir, "{$baseDir}/logs"];
foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
}

// 2. Prevent Directory Browsing in Web Directories (.htaccess & index.html fallbacks)
$webProtectedDirs = [$baseDir, $pkgDir];
foreach ($webProtectedDirs as $webDir) {
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

// 3. Initialize 1024-bit Legacy PKI
if (!file_exists("{$pkiDir}/ca.crt") || !file_exists("{$pkiDir}/private/ca.key")) {
    exec("openssl req -x509 -new -nodes -sha1 -days 3650 -newkey rsa:1024 -keyout {$pkiDir}/private/ca.key -out {$pkiDir}/ca.crt -subj '/CN=Legacy-VPN-CA/' 2>&1");
}

if (!file_exists("{$pkiDir}/server.crt") || !file_exists("{$pkiDir}/private/server.key")) {
    exec("openssl req -new -nodes -sha1 -newkey rsa:1024 -keyout {$pkiDir}/private/server.key -out {$pkiDir}/server.csr -subj '/CN=legacy-vpn-server/' 2>&1");
    exec("openssl x509 -req -days 3650 -sha1 -in {$pkiDir}/server.csr -CA {$pkiDir}/ca.crt -CAkey {$pkiDir}/private/ca.key -set_serial 1 -out {$pkiDir}/server.crt 2>&1");
    @unlink("{$pkiDir}/server.csr");
}

if (!file_exists("{$pkiDir}/dh.pem")) {
    exec("openssl dhparam -out {$pkiDir}/dh.pem 1024 2>&1");
}

// Restrict private key permissions to silence OpenVPN warning
@chmod("{$pkiDir}/private/server.key", 0600);

// 4. Generate legacy-vpn.conf
$serverConfigContent = <<<CONF
port 1194
proto udp
dev tun
ca {$pkiDir}/ca.crt
cert {$pkiDir}/server.crt
key {$pkiDir}/private/server.key
dh {$pkiDir}/dh.pem
server 10.8.0.0 255.255.255.0
keepalive 10 120

# Legacy Ciphers & Hash
cipher AES-128-CBC
auth SHA1
data-ciphers AES-128-CBC
data-ciphers-fallback AES-128-CBC

# Legacy OpenSSL 3.0 & TLS 1.0 Interop
tls-version-min 1.0
tls-cert-profile insecure
tls-cipher "DEFAULT"
providers legacy default

duplicate-cn
topology subnet
persist-key
persist-tun
status {$baseDir}/logs/openvpn-status.log 1
log {$baseDir}/logs/openvpn.log
verb 3
CONF;

file_put_contents($serverConf, $serverConfigContent);

// 5. Set Permissions
@exec("chown -R asterisk:asterisk " . escapeshellarg($baseDir) . " " . escapeshellarg($pkgDir) . " " . escapeshellarg($tftpDir) . " 2>&1");
@exec("chmod -R 775 " . escapeshellarg($baseDir) . " " . escapeshellarg($pkgDir) . " " . escapeshellarg($tftpDir) . " 2>&1");

// 6. Launch OpenVPN daemon safely
exec("pkill -f 'legacy-vpn.conf' 2>&1");
$launchCmd = "OPENSSL_CONF=/etc/ssl/openssl.cnf OPENSSL_CIPHER_LIST=DEFAULT:@SECLEVEL=0 openvpn --config " . escapeshellarg($serverConf) . " --writepid {$baseDir}/openvpn.pid --daemon 2>&1";
exec($launchCmd);

