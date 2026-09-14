<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

// ============================================================================
// SYSTEM SIGN, DEVTOOLS INSTALL & DEBUG LOGIC
// ============================================================================
$signError = '';
$debugOutput = '';

// Sign Custom Module Action Handler
if (isset($_POST['action']) && $_POST['action'] === 'resign_custom_module_with_pass') {
    $rootPass = $_POST['sudo_password'] ?? '';
    $moduleDir = '/var/www/html/admin/modules/ovpn_mgr';
    $signerScript = "{$moduleDir}/devtools/signer.php";

    if (!empty($rootPass)) {
        $pyScript = implode("\n", [
            "import pty, os, sys, time, select",
            "password = sys.argv[1] if len(sys.argv) > 1 else ''",
            "module_path = sys.argv[2] if len(sys.argv) > 2 else ''",
            "signer_path = sys.argv[3] if len(sys.argv) > 3 else ''",
            "pid, fd = pty.fork()",
            "if pid == 0:",
            '    cmd_chain = (',
            '        "chown -R asterisk:asterisk " + module_path + "; "',
            '        "chmod +x " + signer_path + "; "',
            '        "php " + signer_path + " " + module_path + " 2>&1; "',
            '        "echo \'SUCCESS_NATIVE_SIGNED\'"',
            '    )',
            '    os.execvp("su", ["su", "-", "root", "-c", cmd_chain])',
            "else:",
            "    output = ''",
            "    pw_sent = False",
            "    start_time = time.time()",
            "    while time.time() - start_time < 30.0:",
            "        r, _, _ = select.select([fd], [], [], 0.2)",
            "        if r:",
            "            try:",
            "                data = os.read(fd, 1024).decode('utf-8', errors='ignore')",
            "                if not data: break",
            "                output += data",
            "                if 'password' in output.lower() and not pw_sent:",
            "                    os.write(fd, (password + '\\n').encode())",
            "                    pw_sent = True",
            "                if 'SUCCESS_NATIVE_SIGNED' in output or 'incorrect' in output.lower() or 'failure' in output.lower():",
            "                    break",
            "            except Exception:",
            "                break",
            "    print(output.strip())"
        ]);

        $cmd = "python3 -c " . escapeshellarg($pyScript) . " " . escapeshellarg($rootPass) . " " . escapeshellarg($moduleDir) . " " . escapeshellarg($signerScript) . " 2>&1";
        exec("which python3", $py3Check);
        if (empty($py3Check)) {
            $cmd = "python -c " . escapeshellarg($pyScript) . " " . escapeshellarg($rootPass) . " " . escapeshellarg($moduleDir) . " " . escapeshellarg($signerScript) . " 2>&1";
        }

        $debugOutput = shell_exec($cmd);
        clearstatcache();

        if (strpos($debugOutput, 'SUCCESS_NATIVE_SIGNED') !== false) {
            header("Location: config.php?display=ovpn_mgr");
            exit();
        } else {
            $signError = "Signing failed. Check output logs below.";
        }
    } else {
        $signError = "Root password is required.";
    }
}

$baseDir = '/var/www/html/PhoneSettings/openvpn';
$pkgDir = '/var/www/html/PhoneSettings/vpnkeys';
$pkiDir = "{$baseDir}/legacy_pki";
$logFile = "{$baseDir}/logs/openvpn.log";
$serverConf = "{$baseDir}/legacy-vpn.conf";
$crlFile = "{$pkiDir}/crl.pem";
$pidFile = "{$baseDir}/openvpn.pid";
$serverKey = "{$pkiDir}/private/server.key";

if (!function_exists('getOpenVpnVersion')) {
    function getOpenVpnVersion() {
        $openvpnBin = file_exists('/usr/sbin/openvpn') ? '/usr/sbin/openvpn' : '/usr/local/sbin/openvpn';
        exec("sudo -n {$openvpnBin} --version 2>&1", $output);

        if (!empty($output[0]) && preg_match('/OpenVPN\s+([0-9]+\.[0-9]+\.[0-9]+)/i', $output[0], $matches)) {
            return $matches[1];
        }
        return '2.4.0';
    }
}

if (!function_exists('netmaskToCidr')) {
    function netmaskToCidr($netmask) {
        $long = ip2long($netmask);
        $base = ip2long('255.255.255.255');
        return 32 - log(($long ^ $base) + 1, 2);
    }
}

if (!function_exists('cidrToNetmask')) {
    function cidrToNetmask($cidr) {
        return long2ip(-1 << (32 - (int)$cidr));
    }
}

if (!function_exists('getActiveServerSettings')) {
    function getActiveServerSettings($serverConf) {
        $ip = $_SERVER['SERVER_ADDR'] ?? '127.0.0.1';
        $port = '1194';
        $hostIp = '10.8.0.1';
        $cidr = 24;
        
        if (file_exists($serverConf)) {
            $content = (string)@file_get_contents($serverConf);
            if (preg_match('/^port (\d+)/m', $content, $mPort)) {
                $port = trim($mPort[1]);
            }
            if (preg_match('/^# client-remote-host (.+)/m', $content, $mIp)) {
                $ip = trim($mIp[1]);
            }
            if (preg_match('/^server\s+([\d\.]+)\s+([\d\.]+)/m', $content, $mSubnet)) {
                $netIp = ip2long(trim($mSubnet[1]));
                $maskStr = trim($mSubnet[2]);
                $cidr = netmaskToCidr($maskStr);
                $hostIp = long2ip($netIp + 1);
            }
        }
        return ['ip' => $ip, 'port' => $port, 'host_ip' => $hostIp, 'cidr' => $cidr];
    }
}

function startOpenVpnServer($serverConf, $baseDir, $serverKey) {
    $logDir = "{$baseDir}/logs";
    $logFile = "{$logDir}/openvpn.log";
    $pkiDir = "{$baseDir}/legacy_pki";
    $crlFile = "{$pkiDir}/crl.pem";

    if (!file_exists($logDir)) {
        @mkdir($logDir, 0775, true);
    }

    if (file_exists($logFile) && filesize($logFile) > 5242880) {
        exec("sudo -n /usr/bin/tail -n 2000 " . escapeshellarg($logFile) . " > " . escapeshellarg("{$logFile}.tmp"));
        @rename("{$logFile}.tmp", $logFile);
        exec("sudo -n /bin/chmod 644 " . escapeshellarg($logFile));
    }

    if (!file_exists($crlFile)) {
        if (file_exists("{$pkiDir}/ca.crt") && file_exists("{$pkiDir}/private/ca.key")) {
            if (!file_exists("{$pkiDir}/index.txt")) { @touch("{$pkiDir}/index.txt"); }
            if (!file_exists("{$pkiDir}/crlnumber")) { @file_put_contents("{$pkiDir}/crlnumber", "01\n"); }

            $tmpCnf = "{$pkiDir}/crl_openssl.cnf";
            $cnfData = "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {$pkiDir}\ndefault_md = sha256\n";
            @file_put_contents($tmpCnf, $cnfData);

            exec("OPENSSL_CONF={$tmpCnf} openssl ca -gencrl -keyfile {$pkiDir}/private/ca.key -cert {$pkiDir}/ca.crt -out {$crlFile} -config {$tmpCnf} 2>&1");
            @unlink($tmpCnf);
        }
    }

    $installedVersion = getOpenVpnVersion();
    $isLegacy = version_compare($installedVersion, '2.5.0', '<');

    if (file_exists($serverConf)) {
        $lines = explode("\n", (string)@file_get_contents($serverConf));
        $cleanLines = [];

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if (strpos($trimmed, 'crl-verify') === 0 && !file_exists($crlFile)) {
                continue;
            }

            if ($isLegacy) {
                if (
                    strpos($trimmed, 'data-ciphers') === 0 || 
                    strpos($trimmed, 'data-ciphers-fallback') === 0 || 
                    strpos($trimmed, 'providers') === 0 ||
                    strpos($trimmed, 'ignore-unknown-option') === 0
                ) {
                    continue;
                }
            } else {
                if (strpos($trimmed, 'ncp-disable') === 0) {
                    continue;
                }
            }

            $cleanLines[] = $line;
        }

        $cleanContent = implode("\n", $cleanLines);

        if ($isLegacy) {
            if (strpos($cleanContent, 'cipher ') === false) {
                $cleanContent .= "\ncipher AES-128-CBC\n";
            }
        } else {
            if (strpos($cleanContent, 'data-ciphers ') === false) {
                $cleanContent .= "\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305\n";
            }
        }

        if (strpos($cleanContent, 'verb ') === false) {
            $cleanContent .= "\nverb 3\n";
        }

        @file_put_contents($serverConf, $cleanContent);
    }

    $openvpnBin = file_exists('/usr/sbin/openvpn') ? '/usr/sbin/openvpn' : '/usr/local/sbin/openvpn';
    
    if (file_exists($serverKey)) {
        exec("sudo -n /bin/chmod 600 " . escapeshellarg($serverKey) . " 2>&1");
    }

    exec("sudo -n /usr/sbin/setcap cap_net_admin+ep {$openvpnBin} 2>&1");

    $cmd = "OPENSSL_CONF=/etc/ssl/openssl.cnf OPENSSL_CIPHER_LIST=DEFAULT:@SECLEVEL=0 sudo -n {$openvpnBin} --config " . escapeshellarg($serverConf) . " --writepid {$baseDir}/openvpn.pid --log-append " . escapeshellarg($logFile) . " --daemon";
    
    $output = [];
    exec($cmd, $output, $returnCode);

    if ($returnCode !== 0 && !empty($output)) {
        @file_put_contents($logFile, "\n[GUI START ATTEMPT Exit Code: {$returnCode}]\n" . implode("\n", $output) . "\n", FILE_APPEND);
    }

    exec("sudo -n /bin/chmod 644 " . escapeshellarg($logFile) . " 2>&1");
}

function stopOpenVpnServer($pidFile, $serverConf) {
    exec("sudo -n /bin/systemctl stop openvpn openvpn@* openvpn-server@* openvpn-server@legacy-vpn 2>&1");
    exec("sudo -n /usr/bin/systemctl stop openvpn openvpn@* openvpn-server@* openvpn-server@legacy-vpn 2>&1");
    exec("sudo -n /bin/systemctl disable openvpn openvpn@* openvpn-server@* openvpn-server@legacy-vpn 2>&1");
    exec("sudo -n /usr/bin/systemctl disable openvpn openvpn@* openvpn-server@* openvpn-server@legacy-vpn 2>&1");

    if (file_exists($pidFile)) {
        $pid = intval(trim((string)@file_get_contents($pidFile)));
        if ($pid > 0) {
            exec("sudo -n /bin/kill -9 {$pid} 2>&1");
            exec("sudo -n /usr/bin/kill -9 {$pid} 2>&1");
            exec("kill -9 {$pid} 2>&1");
        }
        @unlink($pidFile);
    }

    $port = '1194';
    if (file_exists($serverConf)) {
        $content = (string)@file_get_contents($serverConf);
        if (preg_match('/^port (\d+)/m', $content, $mPort)) {
            $port = trim($mPort[1]);
        }
    }
    exec("sudo -n /usr/bin/fuser -k -9 {$port}/udp 2>&1");
    exec("sudo -n /bin/fuser -k -9 {$port}/udp 2>&1");

    exec("sudo -n /usr/bin/pkill -9 -f 'openvpn' 2>&1");
    exec("sudo -n /bin/pkill -9 -f 'openvpn' 2>&1");
    exec("sudo -n /sbin/ip link delete tun0 >/dev/null 2>&1");

    clearstatcache();
}

// 0. Live Log Endpoint, Line Break Endpoint & Public IP Endpoint
if (isset($_REQUEST['action'])) {
    if ($_REQUEST['action'] === 'fetch_log') {
        if (ob_get_level()) { ob_end_clean(); }
        header('Content-Type: text/plain; charset=utf-8');
        if (file_exists($logFile)) {
            $rawContent = shell_exec("sudo -n /usr/bin/tail -n 200 " . escapeshellarg($logFile) . " 2>&1");
            $lines = explode("\n", $rawContent);
            $cleanLines = [];
            foreach ($lines as $line) {
                if (strpos($line, 'global-message-banner') === false && strpos($line, 'Unsigned Module') === false) {
                    $cleanLines[] = strip_tags($line);
                }
            }
            echo trim(implode("\n", $cleanLines));
        } else {
            echo 'No log output available.';
        }
        exit();
    }
    if ($_REQUEST['action'] === 'add_page_break') {
        if (ob_get_level()) { ob_end_clean(); }
        if (file_exists($logFile)) {
            $dividerText = "\n#############################################\n--- SEPARATOR (" . date('Y-m-d H:i:s') . ") ---\n#############################################\n";
            $written = @file_put_contents($logFile, $dividerText, FILE_APPEND);
            exec("sudo -n /bin/chmod 644 " . escapeshellarg($logFile) . " 2>&1");
            if ($written !== false) { echo "success"; } else { echo "error_write"; }
        } else { echo "error_nofile"; }
        exit();
    }
    if ($_REQUEST['action'] === 'fetch_public_ip') {
        if (ob_get_level()) { ob_end_clean(); }
        header('Content-Type: text/plain; charset=utf-8');
        $publicIp = @file_get_contents('https://api.ipify.org');
        echo $publicIp ? trim($publicIp) : $_SERVER['SERVER_ADDR'];
        exit();
    }
}

require_once __DIR__ . '/ovpn_mgr.class.php';
$freepbxObj = \FreePBX::create();
$ovpn_mgr = new \FreePBX\modules\Ovpn_mgr($freepbxObj);

// 1. Service Control Actions
if (isset($_POST['action']) && $_POST['action'] === 'manage_service') {
    $serviceAction = $_POST['service_cmd'] ?? '';
    if ($serviceAction === 'start') {
        @unlink("{$baseDir}/.stopped");
        stopOpenVpnServer($pidFile, $serverConf);
        sleep(1);
        startOpenVpnServer($serverConf, $baseDir, $serverKey);
    } elseif ($serviceAction === 'stop') {
        @touch("{$baseDir}/.stopped");
        stopOpenVpnServer($pidFile, $serverConf);
    } elseif ($serviceAction === 'restart') {
        @unlink("{$baseDir}/.stopped");
        stopOpenVpnServer($pidFile, $serverConf);
        sleep(1);
        startOpenVpnServer($serverConf, $baseDir, $serverKey);
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// Check for Sign Module Button Visibility
$show_ovpn_resign_button = false;
if (class_exists('FreePBX')) {
    $notifications = \FreePBX::Notifications();
    if (
        $notifications->exists('core', 'SIGNATURE_NOT_VALID') || 
        $notifications->exists('framework', 'TAMPERED_FILES') ||
        (function_exists('posix_getpwuid') && !file_exists('/var/www/html/admin/modules/ovpn_mgr/module.sig'))
    ) {
        $show_ovpn_resign_button = true;
    }
}

// 3. Save Server Settings
if (isset($_POST['action']) && $_POST['action'] === 'update_server_settings') {
    $newPort = intval($_POST['ovpn_port']);
    $newIp = trim($_POST['server_ip']);
    $hostIpStr = trim($_POST['host_ip']);
    $cidr = intval($_POST['client_cidr']);

    if ($newPort > 0 && $newPort < 65535 && !empty($newIp) && filter_var($hostIpStr, FILTER_VALIDATE_IP) && $cidr >= 8 && $cidr <= 30) {
        $netmask = cidrToNetmask($cidr);
        $hostIpLong = ip2long($hostIpStr);
        $maskLong = ip2long($netmask);
        $networkIpLong = $hostIpLong & $maskLong;
        $broadcastIpLong = $networkIpLong | (~$maskLong & 0xFFFFFFFF);

        if ($hostIpLong !== $networkIpLong && $hostIpLong !== $broadcastIpLong) {
            $networkIp = long2ip($networkIpLong);
            $confContent = (string)@file_get_contents($serverConf);
            $confContent = preg_replace('/^port \d+/m', "port {$newPort}", $confContent);
            
            if (preg_match('/^# client-remote-host .*/m', $confContent)) {
                $confContent = preg_replace('/^# client-remote-host .*/m', "# client-remote-host {$newIp}", $confContent);
            } else {
                $confContent .= "\n# client-remote-host {$newIp}";
            }

            if (preg_match('/^server .*/m', $confContent)) {
                $confContent = preg_replace('/^server .*/m', "server {$networkIp} {$netmask}", $confContent);
            } else {
                $confContent .= "\nserver {$networkIp} {$netmask}";
            }

            @file_put_contents($serverConf, $confContent);

            if (!file_exists("{$baseDir}/.stopped")) {
                stopOpenVpnServer($pidFile, $serverConf);
                sleep(1);
                startOpenVpnServer($serverConf, $baseDir, $serverKey);
            }
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// 4. Handle Package Generation
if (isset($_POST['action']) && $_POST['action'] === 'generate_package') {
    $ext = preg_replace('/[^0-9]/', '', $_POST['ext']);
    $mac = strtolower(preg_replace('/[^a-fA-F0-9]/', '', $_POST['mac']));

    $settings = getActiveServerSettings($serverConf);
    $serverIp = $settings['ip'];
    $port = $settings['port'];

    if (!empty($ext) && !empty($mac)) {
        if (!file_exists($pkgDir)) {
            @mkdir($pkgDir, 0775, true);
        }

        $clientKey = "{$pkiDir}/private/{$ext}.key";
        $clientCrt = "{$pkiDir}/issued/{$ext}.crt";
        $clientCsr = "{$pkiDir}/{$ext}.csr";

        if (!file_exists($clientCrt)) {
            exec("openssl req -new -nodes -sha1 -newkey rsa:1024 -keyout {$clientKey} -out {$clientCsr} -subj '/CN={$ext}/' 2>&1");
            exec("openssl x509 -req -days 3650 -sha1 -in {$clientCsr} -CA {$pkiDir}/ca.crt -CAkey {$pkiDir}/private/ca.key -set_serial " . rand(100, 99999) . " -out {$clientCrt} 2>&1");
            @unlink($clientCsr);
        }

        $buildDir = "{$baseDir}/build_{$ext}";
        $keysSubDir = "{$buildDir}/keys";
        @mkdir($keysSubDir, 0775, true);

        copy("{$pkiDir}/ca.crt", "{$buildDir}/ca.crt");
        copy($clientCrt, "{$buildDir}/client.crt");
        copy($clientKey, "{$buildDir}/client.key");

        copy("{$pkiDir}/ca.crt", "{$keysSubDir}/ca.crt");
        copy($clientCrt, "{$keysSubDir}/client.crt");
        copy($clientKey, "{$keysSubDir}/client.key");

        $vpnCnf = "client\nnobind\nremote {$serverIp} {$port}\nproto udp\ndev tun\nca /config/openvpn/keys/ca.crt\ncert /config/openvpn/keys/client.crt\nkey /config/openvpn/keys/client.key\ncipher AES-128-CBC\nauth SHA1\nverb 3\n";
        @file_put_contents("{$buildDir}/vpn.cnf", $vpnCnf);

        $tarPath = "{$pkgDir}/{$mac}_{$ext}_ovpn.tar";
        exec("tar -cvf {$tarPath} -C {$buildDir} ca.crt client.crt client.key keys vpn.cnf 2>&1");
        exec("chmod 644 " . escapeshellarg($tarPath) . " 2>&1");
        
        exec("rm -rf " . escapeshellarg($buildDir));
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// 5. Handle Certificate Revocation
if (isset($_GET['revoke_ext'])) {
    $revokeExt = preg_replace('/[^0-9]/', '', $_GET['revoke_ext']);
    $targetCrt = "{$pkiDir}/issued/{$revokeExt}.crt";
    $targetKey = "{$pkiDir}/private/{$revokeExt}.key";

    if (file_exists($targetCrt)) {
        $tmpCnf = "{$pkiDir}/crl_openssl.cnf";
        $cnfData = "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {$pkiDir}\ndefault_md = sha256\n";
        @file_put_contents($tmpCnf, $cnfData);

        if (!file_exists("{$pkiDir}/index.txt")) { touch("{$pkiDir}/index.txt"); }
        if (!file_exists("{$pkiDir}/crlnumber")) { @file_put_contents("{$pkiDir}/crlnumber", "01\n"); }

        exec("OPENSSL_CONF={$tmpCnf} openssl ca -revoke {$targetCrt} -keyfile {$pkiDir}/private/ca.key -cert {$pkiDir}/ca.crt -config {$tmpCnf} 2>&1");
        exec("OPENSSL_CONF={$tmpCnf} openssl ca -gencrl -keyfile {$pkiDir}/private/ca.key -cert {$pkiDir}/ca.crt -out {$crlFile} -config {$tmpCnf} 2>&1");

        @unlink($tmpCnf);

        $confContent = (string)@file_get_contents($serverConf);
        if (strpos($confContent, 'crl-verify') === false) {
            $confContent .= "\ncrl-verify {$crlFile}\n";
            @file_put_contents($serverConf, $confContent);
        }

        @unlink($targetCrt);
        @unlink($targetKey);

        foreach (glob("{$pkgDir}/*_{$revokeExt}_ovpn.tar") as $matchingTar) { @unlink($matchingTar); }
        foreach (glob("{$pkgDir}/*_{$revokeExt}_keys.tar") as $matchingTar) { @unlink($matchingTar); }
        foreach (glob("{$pkgDir}/{$revokeExt}-*-keys.tar") as $matchingTar) { @unlink($matchingTar); }
        foreach (glob("{$pkgDir}/keys_{$revokeExt}_*.tar") as $matchingTar) { @unlink($matchingTar); }

        if (!file_exists("{$baseDir}/.stopped")) {
            stopOpenVpnServer($pidFile, $serverConf);
            sleep(1);
            startOpenVpnServer($serverConf, $baseDir, $serverKey);
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// 6. Handle Package Deletion & Key Revocation
if (isset($_GET['delete_pkg'])) {
    $targetPkg = basename($_GET['delete_pkg']);
    $fullPath = "{$pkgDir}/{$targetPkg}";

    if (file_exists($fullPath) && (strpos($targetPkg, '_ovpn.tar') !== false || strpos($targetPkg, '_keys.tar') !== false || strpos($targetPkg, '-keys.tar') !== false || strpos($targetPkg, 'keys_') === 0)) {
        $revokeExt = '';

        if (preg_match('/^[a-f0-9]+_(\d+)_(ovpn|keys)\.tar$/i', $targetPkg, $m)) {
            $revokeExt = $m[1];
        } elseif (preg_match('/^keys_(\d+)_/i', $targetPkg, $m) || preg_match('/^(\d+)-/i', $targetPkg, $m)) {
            $revokeExt = $m[1];
        }

        @unlink($fullPath);

        if (!empty($revokeExt)) {
            $targetCrt = "{$pkiDir}/issued/{$revokeExt}.crt";
            $targetKey = "{$pkiDir}/private/{$revokeExt}.key";

            if (file_exists($targetCrt)) {
                $tmpCnf = "{$pkiDir}/crl_openssl.cnf";
                $cnfData = "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {$pkiDir}\ndefault_md = sha256\n";
                @file_put_contents($tmpCnf, $cnfData);

                if (!file_exists("{$pkiDir}/index.txt")) { touch("{$pkiDir}/index.txt"); }
                if (!file_exists("{$pkiDir}/crlnumber")) { @file_put_contents("{$pkiDir}/crlnumber", "01\n"); }

                exec("OPENSSL_CONF={$tmpCnf} openssl ca -revoke {$targetCrt} -keyfile {$pkiDir}/private/ca.key -cert {$pkiDir}/ca.crt -config {$tmpCnf} 2>&1");
                exec("OPENSSL_CONF={$tmpCnf} openssl ca -gencrl -keyfile {$pkiDir}/private/ca.key -cert {$pkiDir}/ca.crt -out {$crlFile} -config {$tmpCnf} 2>&1");

                @unlink($tmpCnf);

                $confContent = (string)@file_get_contents($serverConf);
                if (strpos($confContent, 'crl-verify') === false) {
                    $confContent .= "\ncrl-verify {$crlFile}\n";
                    @file_put_contents($serverConf, $confContent);
                }

                @unlink($targetCrt);
                @unlink($targetKey);

                foreach (glob("{$pkgDir}/*_{$revokeExt}_ovpn.tar") as $matchingTar) { @unlink($matchingTar); }
                foreach (glob("{$pkgDir}/*_{$revokeExt}_keys.tar") as $matchingTar) { @unlink($matchingTar); }
                foreach (glob("{$pkgDir}/{$revokeExt}-*-keys.tar") as $matchingTar) { @unlink($matchingTar); }
                foreach (glob("{$pkgDir}/keys_{$revokeExt}_*.tar") as $matchingTar) { @unlink($matchingTar); }

                if (!file_exists("{$baseDir}/.stopped")) {
                    stopOpenVpnServer($pidFile, $serverConf);
                    sleep(1);
                    startOpenVpnServer($serverConf, $baseDir, $serverKey);
                }
            }
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

clearstatcache();

$activeSettings = getActiveServerSettings($serverConf);
$currentPort = $activeSettings['port'];
$currentServerIp = $activeSettings['ip'];

$logContent = '';
if (file_exists($logFile)) {
    $logContent = (string)@shell_exec("sudo -n /usr/bin/tail -n 200 " . escapeshellarg($logFile) . " 2>&1");
}

$hasTunError = (strpos($logContent, 'Cannot ioctl TUNSETIFF') !== false || strpos($logContent, 'Exiting due to fatal error') !== false);

$pids = [];
if (!file_exists("{$baseDir}/.stopped")) {
    if (file_exists($pidFile)) {
        $savedPid = intval(trim((string)@file_get_contents($pidFile)));
        if ($savedPid > 0 && file_exists("/proc/{$savedPid}")) {
            $pids[] = $savedPid;
        } else {
            @unlink($pidFile);
        }
    }

    if (empty($pids) && !empty($currentPort)) {
        exec("sudo -n /usr/bin/fuser {$currentPort}/udp 2>/dev/null", $fuserOut);
        if (!empty($fuserOut[0])) {
            $foundPid = intval(trim($fuserOut[0]));
            if ($foundPid > 0) {
                $pids[] = $foundPid;
            }
        }
    }

    if (empty($pids)) {
        exec("pgrep -f 'legacy-vpn'", $rawPids);
        foreach ($rawPids as $rawPid) {
            $cleanPid = intval(trim($rawPid));
            if ($cleanPid > 0) {
                $pids[] = $cleanPid;
            }
        }
    }
}

$isRunning = !empty($pids) && !$hasTunError;

exec("sudo -n /usr/sbin/openvpn --version 2>&1", $sudoCheckOut, $sudoCheckCode);
$hasSudoRule = ($sudoCheckCode === 0 || strpos(implode(' ', $sudoCheckOut), 'OpenVPN') !== false);

$createdPackages = glob("{$pkgDir}/*.tar");
$issuedCertFiles = glob("{$pkiDir}/issued/*.crt");

$connectedClients = [];
if (file_exists($logFile)) {
    $logData = (string)@file_get_contents($logFile);
    exec("ip neighbor show dev tun0 2>/dev/null", $neighOutput);
    
    foreach ($neighOutput as $line) {
        if (preg_match('/^(\d+\.\d+\.\d+\.\d+)\s+dev\s+tun0\s+lladdr\s+([0-9a-f:]+)/i', $line, $m)) {
            $virtIp = $m[1];
            $mac = $m[2];
            $realIp = 'Active Peer';
            $activeCipher = 'Negotiated';

            if (preg_match_all('/Peer Connection Initiated with \[AF_INET\]([\d\.]+:\d+)/i', $logData, $peerMatches)) {
                $realIp = end($peerMatches[1]);
            }

            if (preg_match_all('/Data Channel.*[C|c]ipher [\'"]?([A-Za-z0-9\-]+)[\'"]?/i', $logData, $cipherMatches)) {
                $activeCipher = end($cipherMatches[1]);
            }

            $connectedClients[] = [
                'virtual_ip'    => $virtIp,
                'mac'           => $mac,
                'real_ip'       => $realIp,
                'active_cipher' => $activeCipher
            ];
        }
    }
}
?>

<div class="container-fluid">
    <h1>OpenVPN Manager</h1>
    <hr>

    <?php if (!empty($debugOutput)): ?>
        <div class="panel panel-info">
            <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-terminal"></i> Execution Debug Output</h3></div>
            <div class="panel-body">
                <textarea readonly style="width: 100%; height: 250px; font-family: monospace; font-size: 11px; background: #222; color: #00ff00; padding: 10px; border-radius: 4px;"><?php echo htmlspecialchars($debugOutput); ?></textarea>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($signError)): ?>
        <div class="alert alert-danger">
            <i class="fa fa-exclamation-triangle"></i> <?php echo htmlspecialchars($signError); ?>
        </div>
    <?php endif; ?>

    <!-- Status Banner -->
    <div class="alert alert-<?php echo $isRunning ? 'success' : 'danger'; ?>" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
        <div>
            <strong>OpenVPN Server Status:</strong> 
            <?php echo $isRunning ? '<span class="label label-success">RUNNING (PID: ' . implode(', ', $pids) . ')</span>' : '<span class="label label-danger">STOPPED</span>'; ?>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
            <form method="post" action="config.php?display=ovpn_mgr" style="display: inline-block; margin: 0;">
                <input type="hidden" name="action" value="manage_service">
                <?php if ($isRunning): ?>
                    <button type="submit" name="service_cmd" value="stop" class="btn btn-danger btn-sm" style="background-color: #db001a; border-color: #6b000d;" onclick="return confirm('Stop OpenVPN service? Remote clients will disconnect.');">
                        <i class="fa fa-stop"></i> Stop
                    </button>
                    <button type="submit" name="service_cmd" value="restart" class="btn btn-warning btn-sm">
                        <i class="fa fa-refresh"></i> Restart
                    </button>
                <?php else: ?>
                    <button type="submit" name="service_cmd" value="start" class="btn btn-success btn-sm">
                        <i class="fa fa-play"></i> Start
                    </button>
                <?php endif; ?>
            </form>
            <button type="button" class="btn btn-info btn-sm" data-toggle="modal" data-target="#logModal">
                <i class="fa fa-file-text-o"></i> View Live Logs
            </button>

            <?php if ($show_ovpn_resign_button): ?>
                <button type="button" class="btn btn-danger btn-sm" style="margin: 0; font-weight: bold; background-color: #db001a; border-color: #6b000d; box-shadow: 0 0 6px rgba(220,53,69,0.4);" data-toggle="modal" data-target="#signModal">
                    <i class="fa fa-key"></i> Sign Module
                </button>
            <?php endif; ?>
        </div>
    </div>

    <!-- Top Layout Grid: Server Settings & Connected Clients -->
    <div class="row">
        <!-- Left Column: Server Configuration -->
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-cogs"></i> OpenVPN Server Settings</h3></div>
                <div class="panel-body">
                    <form method="post" action="config.php?display=ovpn_mgr">
                        <input type="hidden" name="action" value="update_server_settings">
                        
                        <div style="display: flex; align-items: flex-end; gap: 5px; margin-bottom: 15px; flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="server_ip" style="font-size: 11px; display: block; margin-bottom: 5px;">Server Public IP / Host</label>
                                <input type="text" class="form-control" id="server_ip" name="server_ip" value="<?php echo htmlspecialchars($currentServerIp); ?>" required style="width: 135px; height: 34px;">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; visibility: hidden; display: block; margin-bottom: 5px;">Action</label>
                                <button type="button" class="btn btn-default btn-sm" onclick="setPrivateIp()" style="width: 95px; height: 34px; padding: 4px 6px; font-size: 13px;" title="Auto-fill Local LAN IP">
                                    <i class="fa fa-sitemap"></i> Private IP
                                </button>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; visibility: hidden; display: block; margin-bottom: 5px;">Action</label>
                                <button type="button" class="btn btn-default btn-sm" onclick="fetchPublicIp()" style="width: 95px; height: 34px; padding: 4px 6px; font-size: 13px;" title="Auto-fill WAN IP">
                                    <i class="fa fa-globe"></i> Public IP
                                </button>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="ovpn_port" style="font-size: 11px; display: block; margin-bottom: 5px;">Port</label>
                                <input type="number" class="form-control" id="ovpn_port" name="ovpn_port" value="<?php echo htmlspecialchars($currentPort); ?>" required style="width: 70px; height: 34px; padding: 6px 4px;">
                            </div>
                        </div>

                        <div style="display: flex; align-items: flex-end; gap: 10px; margin-bottom: 15px; flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="host_ip" style="font-size: 11px; display: block; margin-bottom: 5px;">Host IP</label>
                                <input type="text" class="form-control" id="host_ip" name="host_ip" value="<?php echo htmlspecialchars($activeSettings['host_ip']); ?>" required style="width: 120px; height: 34px;" placeholder="10.8.0.1" oninput="calculateIpRange()">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="client_cidr" style="font-size: 11px; display: block; margin-bottom: 5px;">CIDR</label>
                                <div class="input-group" style="width: 75px;">
                                    <span class="input-group-addon" style="padding: 6px 6px;">/</span>
                                    <input type="number" class="form-control" id="client_cidr" name="client_cidr" value="<?php echo htmlspecialchars($activeSettings['cidr']); ?>" min="8" max="30" required style="height: 34px; padding: 6px 4px;" oninput="calculateIpRange()">
                                </div>
                            </div>
                            <div class="form-group" style="margin-bottom: 0; align-self: center;">
                                <label style="font-size: 11px; display: block; margin-bottom: 2px;">
                                    Client IP Range <span id="ip_count_display" style="font-weight: normal; color: #666; margin-left: 4px;"></span>
                                </label>
                                <span id="ip_range_display" class="label label-info" style="font-size: 12px; padding: 6px 10px; display: inline-block;">Calculating...</span>
                                <div id="ip_warning_display" style="font-size: 11px; color: #a94442; margin-top: 3px; display: none;"></div>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary btn-block" style="max-width: 420px;">
                            <i class="fa fa-save"></i> Save Settings & Restart Daemon
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Right Column: Connected Clients Panel -->
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-users"></i> Connected OpenVPN Clients</h3></div>
                <div class="panel-body" style="padding: 0; max-height: 160px; overflow-y: auto;">
                    <table class="table table-striped table-bordered" style="margin-bottom: 0; font-size: 12px;">
                        <thead>
                            <tr>
                                <th>Extension / MAC</th>
                                <th>Virtual IP (TUN)</th>
                                <th>Real IP / Peer</th>
                                <th>Active Cipher</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($connectedClients)): ?>
                                <tr><td colspan="4" class="text-muted" style="padding: 12px; text-align: center;">No active client tunnels currently connected.</td></tr>
                            <?php else: ?>
                                <?php foreach ($connectedClients as $client): ?>
                                    <tr>
                                        <td><code><?php echo htmlspecialchars($client['mac']); ?></code></td>
                                        <td><code><?php echo htmlspecialchars($client['virtual_ip']); ?></code></td>
                                        <td><?php echo htmlspecialchars($client['real_ip']); ?></td>
                                        <td><span class="label label-info"><?php echo htmlspecialchars($client['active_cipher']); ?></span></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Bottom Grid: Package Builder & Archives -->
    <div class="row">
        <!-- Package Builder -->
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-cube"></i> Build Provisioning Package (vpn.tar)</h3></div>
                <div class="panel-body">
                    <form method="post" action="config.php?display=ovpn_mgr">
                        <input type="hidden" name="action" value="generate_package">
                        <div style="display: flex; align-items: flex-end; gap: 30px; margin-bottom: 10px; flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px;">Extension</label>
                                <input type="text" name="ext" class="form-control" placeholder="101" required style="width: 130px; height: 34px;">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px;">Phone MAC Address</label>
                                <input type="text" name="mac" class="form-control" placeholder="00155D010203" required style="width: 190px; height: 34px;">
                            </div>
                        </div>
                        <div class="well well-sm" style="font-size: 11px; margin-bottom: 10px; padding: 5px; color: #555; max-width: 350px;">
                            Package will use active target: <strong><?php echo htmlspecialchars($currentServerIp); ?>:<?php echo htmlspecialchars($currentPort); ?></strong>
                        </div>
                        <button type="submit" class="btn btn-success btn-block" style="max-width: 350px;">
                            <i class="fa fa-plus"></i> Generate Keys & Build Package
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Provisioning Archives -->
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading" style="display: flex; align-items: center; justify-content: space-between;">
                    <h3 class="panel-title" style="margin: 0;"><i class="fa fa-archive"></i> Created Provisioning Archives</h3>
                    <button type="button" class="btn btn-warning btn-xs" data-toggle="modal" data-target="#revokeModal">
                        <i class="fa fa-key"></i> Manage / Revoke Keys (<?php echo count($issuedCertFiles); ?>)
                    </button>
                </div>
                <div class="panel-body" style="padding: 0; max-height: 190px; overflow-y: auto;">
                    <?php if (empty($createdPackages)): ?>
                        <div style="padding: 20px; text-align: center;" class="text-muted">No provisioning packages have been generated yet.</div>
                    <?php else: ?>
                        <table class="table table-striped table-bordered" style="margin-bottom: 0; table-layout: fixed; width: 100%;">
                            <thead>
                                <tr>
                                    <th style="width: 220px;">Package Name</th>
                                    <th style="width: 55px; text-align: center;">Size</th>
                                    <th style="width: auto; text-align: center;">Date Created</th>
                                    <th style="width: 140px; text-align: center;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($createdPackages as $pkgPath): 
                                    $filename = basename($pkgPath);
                                    $downloadUrl = "/PhoneSettings/vpnkeys/" . $filename;
                                ?>
                                    <tr>
                                        <td style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: middle;">
                                            <code style="color: #08096e; font-size: 14px; font-weight: 500; vertical-align: middle;"><?php echo htmlspecialchars($filename); ?></code>
                                        </td>
                                        <td style="text-align: center; white-space: nowrap; vertical-align: middle; font-size: 12px;"><?php echo round(filesize($pkgPath) / 1024, 0); ?> KB</td>
                                        <td style="text-align: center; white-space: nowrap; vertical-align: middle; font-size: 12px;"><?php echo date("Y-m-d H:i", filemtime($pkgPath)); ?></td>
                                        <td style="text-align: center; white-space: nowrap; vertical-align: middle; padding: 4px 2px;">
                                            <div style="display: flex; justify-content: center; align-items: center; gap: 3px;">
                                                <a href="<?php echo $downloadUrl; ?>" class="btn btn-xs btn-primary" download title="Download Package" style="padding: 2px 6px; font-size: 18px;">
                                                    <i class="fa fa-download"></i>
                                                </a>
                                                <a href="config.php?display=ovpn_mgr&delete_pkg=<?php echo urlencode($filename); ?>" class="btn btn-xs btn-danger" onclick="return confirm('Delete package and REVOKE extension keys? This action cannot be undone.');" title="Delete Package & Revoke Keys" style="padding: 2px 6px; font-size: 18px;">
                                                    <i class="fa fa-trash"></i>
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal: Sign Module Prompt -->
<div class="modal fade" id="signModal" tabindex="-1" role="dialog" aria-labelledby="signModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="config.php?display=ovpn_mgr" id="signModalForm">
                <input type="hidden" name="action" value="resign_custom_module_with_pass">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="signModalLabel"><i class="fa fa-key"></i> Sign Module</h4>
                </div>
                <div class="modal-body">
                    <p>Enter your <strong>root password</strong> below. The system will run the local module signer and clear signature alerts for <code>ovpn_mgr</code>.</p>
                    <div class="form-group">
                        <label>Root Password <span class="text-danger">*</span></label>
                        <input type="password" name="sudo_password" class="form-control" placeholder="Root Password" required>
                    </div>

                    <!-- Progress Loading Container (Hidden by default) -->
                    <div id="signProgressContainer" style="display: none; margin-top: 15px;">
                        <label><i class="fa fa-spinner fa-spin"></i> Signing module and reloading framework... Please wait.</label>
                        <div class="progress progress-striped active" style="margin-bottom: 0;">
                            <div class="progress-bar progress-bar-danger" role="progressbar" style="width: 100%;"></div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal" id="signCancelBtn">Cancel</button>
                    <button type="submit" class="btn btn-danger" style="margin: 0; font-weight: bold; background-color: #db001a; border-color: #6b000d; box-shadow: 0 0 6px rgba(220,53,69,0.4);"id="signSubmitBtn"><i class="fa fa-key"></i> Sign Module</button>
                </div>
            </form>
        </div>
    </div>
</div>


<!-- Modal 1: Revocation Window -->
<div class="modal fade" id="revokeModal" tabindex="-1" role="dialog" aria-labelledby="revokeModalLabel">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="revokeModalLabel"><i class="fa fa-key"></i> Issued Client Certificates & Revocation</h4>
            </div>
            <div class="modal-body" style="padding: 0;">
                <?php if (empty($issuedCertFiles)): ?>
                    <div style="padding: 20px;" class="text-muted">No issued client certificates found in PKI storage.</div>
                <?php else: ?>
                    <table class="table table-striped table-bordered" style="margin-bottom: 0;">
                        <thead>
                            <tr>
                                <th>Common Name (Ext)</th>
                                <th>Serial Number</th>
                                <th>Target (Host:Port)</th>
                                <th>Issued Date</th>
                                <th style="width: 150px; text-align: center;">Revocation</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($issuedCertFiles as $crtPath): 
                                $extName = pathinfo($crtPath, PATHINFO_FILENAME);
                                $parsedCert = openssl_x509_parse((string)@file_get_contents($crtPath));
                                $serial = $parsedCert['serialNumberHex'] ?? $parsedCert['serialNumber'] ?? 'N/A';
                                $validFrom = date("Y-m-d H:i", $parsedCert['validFrom_time_t'] ?? filemtime($crtPath));
                                $targetHostPort = "{$currentServerIp}:{$currentPort}";
                                $matchingTars = glob("{$pkgDir}/*_{$extName}_ovpn.tar");

                                if (!empty($matchingTars[0]) && file_exists($matchingTars[0])) {
                                    $cnfOutput = shell_exec("tar -xOf " . escapeshellarg($matchingTars[0]) . " vpn.cnf 2>/dev/null");
                                    if (!empty($cnfOutput) && preg_match('/^remote\s+([^\s]+)\s+(\d+)/m', $cnfOutput, $mRemote)) {
                                        $targetHostPort = "{$mRemote[1]}:{$mRemote[2]}";
                                    }
                                }
                            ?>
                                <tr>
                                    <td><strong>Extension <?php echo htmlspecialchars($extName); ?></strong></td>
                                    <td><code><?php echo htmlspecialchars($serial); ?></code></td>
                                    <td><code><?php echo htmlspecialchars($targetHostPort); ?></code></td>
                                    <td><?php echo $validFrom; ?></td>
                                    <td style="text-align: center;">
                                        <a href="config.php?display=ovpn_mgr&revoke_ext=<?php echo urlencode($extName); ?>" class="btn btn-xs btn-danger" onclick="return confirm('REVOKE Extension <?php echo $extName; ?>? This will block the phone from connecting and update the CRL.');">
                                            <i class="fa fa-ban"></i> Revoke & Block
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal 2: Log Viewer -->
<div class="modal fade" id="logModal" tabindex="-1" role="dialog" aria-labelledby="logModalLabel">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="logModalLabel"><i class="fa fa-terminal"></i> OpenVPN Live Log Output (Last 200 Lines)</h4>
            </div>
            <div class="modal-body">
                <textarea id="logModalPre" readonly style="width: 100%; height: 350px; min-height: 200px; resize: both; overflow: auto; background: #f4f4f4; color: #111111; font-family: monospace; font-size: 12px; border: 1px solid #ccc; border-radius: 4px; padding: 10px; user-select: text; -webkit-user-select: text; -moz-user-select: text; -ms-user-select: text;"><?php echo !empty($logContent) ? htmlspecialchars($logContent) : 'No log output available.'; ?></textarea>
            </div>
            <div class="modal-footer" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 5px;">
                <div style="display: flex; gap: 5px;">
                    <button type="button" class="btn btn-primary btn-sm" onclick="copyLogContent()">
                        <i class="fa fa-copy"></i> Copy Log
                    </button>
                    <button type="button" class="btn btn-info btn-sm" onclick="addLogPageBreak()">
                        <i class="fa fa-minus"></i> Add Line Break
                    </button>
                </div>
                <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<script>
$('#signModalForm').on('submit', function() {
    // Show animated progress bar
    $('#signProgressContainer').show();
    
    // Disable submit and cancel buttons to prevent duplicate requests
    $('#signSubmitBtn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Signing...');
    $('#signCancelBtn').prop('disabled', true);
});

function setPrivateIp() {
    $('#server_ip').val('<?php echo $_SERVER['SERVER_ADDR']; ?>');
}

function fetchPublicIp() {
    $('#server_ip').val('Fetching...');
    $.get('config.php?display=ovpn_mgr&action=fetch_public_ip', function(ip) {
        $('#server_ip').val(ip.trim());
    }).fail(function() {
        $('#server_ip').val('<?php echo $_SERVER['SERVER_ADDR']; ?>');
    });
}

function copyLogContent() {
    var logTextarea = document.getElementById("logModalPre");
    logTextarea.select();
    logTextarea.setSelectionRange(0, 999999);
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(logTextarea.value).then(function() {
            alert("Log output copied to clipboard!");
        }).catch(function(err) {
            fallbackCopy(logTextarea);
        });
    } else {
        fallbackCopy(logTextarea);
    }
}

function fallbackCopy(element) {
    try {
        var successful = document.execCommand('copy');
        if (successful) {
            alert("Log output copied to clipboard!");
        } else {
            alert("Failed to copy log text.");
        }
    } catch (err) {
        alert("Browser does not support automatic copying.");
    }
}

let logInterval = null;
let isInitialOpen = false;

function fetchOpenVPNLog() {
    $.ajax({
        url: 'config.php',
        type: 'GET',
        data: { display: 'ovpn_mgr', action: 'fetch_log' },
        success: function(response) {
            const $textarea = $('#logModalPre');
            const elem = $textarea[0];
            const isAtBottom = (elem.scrollHeight - elem.clientHeight - elem.scrollTop) <= 40;
            $textarea.val(response);
            if (isInitialOpen || isAtBottom) {
                elem.scrollTop = elem.scrollHeight;
                isInitialOpen = false;
            }
        }
    });
}

function addLogPageBreak() {
    $.ajax({
        url: 'config.php',
        type: 'POST',
        data: { display: 'ovpn_mgr', action: 'add_page_break' },
        success: function(response) {
            if (response.trim() === 'success') {
                isInitialOpen = true;
                fetchOpenVPNLog();
            } else {
                alert("Failed to add line break. Check file permissions or re-authorize credentials.");
            }
        }
    });
}

$('#logModal').on('shown.bs.modal', function () {
    isInitialOpen = true;
    fetchOpenVPNLog();
    if (logInterval) clearInterval(logInterval);
    logInterval = setInterval(fetchOpenVPNLog, 2000);
});

$('#logModal').on('hidden.bs.modal', function () {
    if (logInterval) {
        clearInterval(logInterval);
        logInterval = null;
    }
});

function ipToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function intToIp(int) {
    return [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join('.');
}

function calculateIpRange() {
    const hostIpStr = $('#host_ip').val().trim();
    const cidr = parseInt($('#client_cidr').val(), 10);
    const display = $('#ip_range_display');
    const warning = $('#ip_warning_display');
    const countDisplay = $('#ip_count_display');

    warning.hide().text('');

    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostIpStr) || isNaN(cidr) || cidr < 8 || cidr > 30) {
        display.text('Invalid Input').removeClass('label-info').addClass('label-danger');
        countDisplay.text('');
        return;
    }

    try {
        const hostIpInt = ipToInt(hostIpStr);
        const maskInt = (-1 << (32 - cidr)) >>> 0;
        const netInt = (hostIpInt & maskInt) >>> 0;
        const broadcastInt = (netInt | ~maskInt) >>> 0;

        const firstUsable = intToIp(netInt + 1);
        const lastUsable = intToIp(broadcastInt - 1);

        if (hostIpInt === netInt) {
            const lowerUsable = intToIp(netInt - 2);
            display.text(`Invalid Host. Use ${lowerUsable} or ${firstUsable}`)
                   .removeClass('label-info').addClass('label-danger');
            countDisplay.text('');
            return;
        }

        if (hostIpInt === broadcastInt) {
            const upperUsable = intToIp(broadcastInt + 2);
            display.text(`Invalid Host. Use ${lastUsable} or ${upperUsable}`)
                   .removeClass('label-info').addClass('label-danger');
            countDisplay.text('');
            return;
        }

        const totalUsableIps = (broadcastInt - netInt - 1);
        countDisplay.text(`(${totalUsableIps} total IPs)`);

        if (hostIpStr !== firstUsable) {
            warning.text(`Note: Host IP is not the primary IP in block (${firstUsable})`).show();
        }

        display.text(`${firstUsable} - ${lastUsable} (Host: ${hostIpStr})`)
               .removeClass('label-danger').addClass('label-info');
    } catch (e) {
        display.text('Error').removeClass('label-info').addClass('label-danger');
        countDisplay.text('');
    }
}

$(document).ready(function() {
    calculateIpRange();
});
</script>