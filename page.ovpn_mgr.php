<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

$baseDir = '/var/www/html/PhoneSettings/openvpn';
$pkgDir = '/var/www/html/PhoneSettings/vpnkeys';
$pkiDir = "{$baseDir}/legacy_pki";
$logFile = "{$baseDir}/logs/openvpn.log";
$serverConf = "{$baseDir}/legacy-vpn.conf";
$crlFile = "{$pkiDir}/crl.pem";
$pidFile = "{$baseDir}/openvpn.pid";
$serverKey = "{$pkiDir}/private/server.key";

// Helper Functions
function getOpenVpnVersion() {
    $openvpnBin = file_exists('/usr/sbin/openvpn') ? '/usr/sbin/openvpn' : '/usr/local/sbin/openvpn';
    exec("sudo -n {$openvpnBin} --version 2>&1", $output);

    if (!empty($output[0]) && preg_match('/OpenVPN\s+([0-9]+\.[0-9]+\.[0-9]+)/i', $output[0], $matches)) {
        return $matches[1];
    }
    return '2.4.0';
}

function startOpenVpnServer($serverConf, $baseDir, $serverKey) {
    $logDir = "{$baseDir}/logs";
    $logFile = "{$logDir}/openvpn.log";
    $pkiDir = "{$baseDir}/legacy_pki";
    $crlFile = "{$pkiDir}/crl.pem";

    if (!file_exists($logDir)) {
        @mkdir($logDir, 0775, true);
    }

    // Auto-truncate log if it exceeds 5 MB (keeps last 2000 lines)
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

function getActiveServerSettings($serverConf) {
    $ip = $_SERVER['SERVER_ADDR'] ?? '127.0.0.1';
    $port = '1194';
    
    if (file_exists($serverConf)) {
        $content = (string)@file_get_contents($serverConf);
        if (preg_match('/^port (\d+)/m', $content, $mPort)) {
            $port = trim($mPort[1]);
        }
        if (preg_match('/^# client-remote-host (.+)/m', $content, $mIp)) {
            $ip = trim($mIp[1]);
        }
    }
    return ['ip' => $ip, 'port' => $port];
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
            
            // Append directly using native PHP (since directory/file permissions are owned by asterisk)
            $written = @file_put_contents($logFile, $dividerText, FILE_APPEND);
            exec("sudo -n /bin/chmod 644 " . escapeshellarg($logFile) . " 2>&1");
            
            if ($written !== false) {
                echo "success";
            } else {
                echo "error_write";
            }
        } else {
            echo "error_nofile";
        }
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

// 2. Full Elevation & System Auto-Hardening via GUI (Includes /bin/bash and /usr/bin/printf permissions)
$elevationError = '';
if (isset($_POST['action']) && $_POST['action'] === 'elevate_permissions') {
    $rootPass = $_POST['sudo_password'] ?? '';
    if (!empty($rootPass)) {
        $pyScript = implode("\n", [
            "import pty, os, sys, time, select",
            "password = sys.argv[1] if len(sys.argv) > 1 else ''",
            "pid, fd = pty.fork()",
            "if pid == 0:",
            '    os.execvp("su", ["su", "-", "root", "-c", "mkdir -p /var/www/html/PhoneSettings/openvpn/logs /var/www/html/PhoneSettings/vpnkeys && chown -R asterisk:asterisk /var/www/html/PhoneSettings/openvpn /var/www/html/PhoneSettings/vpnkeys && setcap cap_net_admin+ep /usr/sbin/openvpn && systemctl unmask openvpn openvpn@* openvpn-server@* 2>/dev/null; echo \\"asterisk ALL=(ALL) NOPASSWD: /usr/sbin/openvpn, /bin/kill, /usr/bin/pkill, /bin/chmod, /usr/sbin/setcap, /usr/bin/tail, /bin/bash, /usr/bin/printf\\" > /etc/sudoers.d/openvpn_mgr && chmod 0644 /etc/sudoers.d/openvpn_mgr && echo SUCCESS_ELEVATED"])',
            "else:",
            "    output = ''",
            "    pw_sent = False",
            "    start_time = time.time()",
            "    while time.time() - start_time < 5.0:",
            "        r, _, _ = select.select([fd], [], [], 0.2)",
            "        if r:",
            "            try:",
            "                data = os.read(fd, 1024).decode('utf-8', errors='ignore')",
            "                if not data: break",
            "                output += data",
            "                if 'password' in output.lower() and not pw_sent:",
            "                    os.write(fd, (password + '\\n').encode())",
            "                    pw_sent = True",
            "                if 'SUCCESS_ELEVATED' in output or 'incorrect' in output.lower() or 'failure' in output.lower():",
            "                    break",
            "            except Exception:",
            "                break",
            "    print(output.strip())"
        ]);

        $cmd = "python3 -c " . escapeshellarg($pyScript) . " " . escapeshellarg($rootPass) . " 2>&1";
        exec("which python3", $py3Check);
        if (empty($py3Check)) {
            $cmd = "python -c " . escapeshellarg($pyScript) . " " . escapeshellarg($rootPass) . " 2>&1";
        }

        $output = shell_exec($cmd);
        clearstatcache();

        exec("sudo -n /usr/sbin/openvpn --version 2>&1", $postCheckOut, $postCheckCode);
        if (strpos($output, 'SUCCESS_ELEVATED') !== false || $postCheckCode === 0) {
            if (!file_exists("{$baseDir}/.stopped")) {
                stopOpenVpnServer($pidFile, $serverConf);
                sleep(1);
                startOpenVpnServer($serverConf, $baseDir, $serverKey);
            }

            header("Location: config.php?display=ovpn_mgr");
            exit();
        } else {
            $elevationError = "Authentication failed. Incorrect root password.";
        }
    } else {
        $elevationError = "Password cannot be empty.";
    }
}

// 3. Save Server Settings
if (isset($_POST['action']) && $_POST['action'] === 'update_server_settings') {
    $newPort = intval($_POST['ovpn_port']);
    $newIp = trim($_POST['server_ip']);

    if ($newPort > 0 && $newPort < 65535 && !empty($newIp)) {
        $confContent = (string)@file_get_contents($serverConf);
        $confContent = preg_replace('/^port \d+/m', "port {$newPort}", $confContent);
        
        if (preg_match('/^# client-remote-host .*/m', $confContent)) {
            $confContent = preg_replace('/^# client-remote-host .*/m', "# client-remote-host {$newIp}", $confContent);
        } else {
            $confContent .= "\n# client-remote-host {$newIp}";
        }

        @file_put_contents($serverConf, $confContent);

        if (!file_exists("{$baseDir}/.stopped")) {
            stopOpenVpnServer($pidFile, $serverConf);
            sleep(1);
            startOpenVpnServer($serverConf, $baseDir, $serverKey);
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

// Safe Log Reader (Last 200 lines for initial page load)
$logContent = '';
if (file_exists($logFile)) {
    $logContent = (string)@shell_exec("sudo -n /usr/bin/tail -n 200 " . escapeshellarg($logFile) . " 2>&1");
}

$hasTunError = (strpos($logContent, 'Cannot ioctl TUNSETIFF') !== false || strpos($logContent, 'Exiting due to fatal error') !== false);

// Process Check
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

// Active Client & Cipher Parser
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
    <p>Manage legacy OpenVPN server configuration and Yealink provisioning packages.</p>
    <hr>

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
                    <button type="submit" name="service_cmd" value="stop" class="btn btn-danger btn-sm" onclick="return confirm('Stop OpenVPN service? Remote clients will disconnect.');">
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
        </div>
    </div>

    <!-- Self-Service Permission Panel -->
    <?php if (!$hasSudoRule): ?>
        <div class="panel panel-warning">
            <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-lock"></i> Authorize GUI Service Control</h3></div>
            <div class="panel-body">
                <?php if (!empty($elevationError)): ?>
                    <div class="alert alert-danger" style="padding: 8px; margin-bottom: 10px; font-size: 12px;">
                        <i class="fa fa-exclamation-triangle"></i> <?php echo htmlspecialchars($elevationError); ?>
                    </div>
                <?php endif; ?>
                <p>Enter your <strong>root password</strong> once below to authorize automatic file permission hardening, process control, and systemd unmasking from the GUI:</p>
                <form method="post" action="config.php?display=ovpn_mgr" class="form-inline">
                    <input type="hidden" name="action" value="elevate_permissions">
                    <div class="form-group">
                        <input type="password" class="form-control" name="sudo_password" placeholder="Root Password" required>
                    </div>
                    <button type="submit" class="btn btn-warning">Grant Authorizations</button>
                </form>
            </div>
        </div>
    <?php endif; ?>

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

                        <button type="submit" class="btn btn-primary btn-block" style="max-width: 420px;">
                            <i class="fa fa-save"></i> Save Settings & Restart Daemon
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Right Column: Connected Clients Status Panel -->
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title"><i class="fa fa-users"></i> Connected OpenVPN Clients</h3>
                </div>
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

    <!-- Bottom Layout Grid: Package Builder & Archives -->
    <div class="row">
        <!-- Left Column: Package Builder -->
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

        <!-- Right Column: Provisioning Archives Table -->
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
                            ?>
                                <tr>
                                    <td><strong>Extension <?php echo htmlspecialchars($extName); ?></strong></td>
                                    <td><code><?php echo htmlspecialchars($serial); ?></code></td>
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
        data: {
            display: 'ovpn_mgr',
            action: 'fetch_log'
        },
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
        data: {
            display: 'ovpn_mgr',
            action: 'add_page_break'
        },
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

// When the log modal opens, flag initial open, fetch fresh logs, and scroll to bottom once
$('#logModal').on('shown.bs.modal', function () {
    isInitialOpen = true;
    fetchOpenVPNLog();

    if (logInterval) clearInterval(logInterval);
    logInterval = setInterval(fetchOpenVPNLog, 2000);
});

// When the log modal closes, clear the background interval
$('#logModal').on('hidden.bs.modal', function () {
    if (logInterval) {
        clearInterval(logInterval);
        logInterval = null;
    }
});
</script>