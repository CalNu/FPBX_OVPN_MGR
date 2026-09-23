<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

// ============================================================================
// Paths
// ============================================================================
$ampWebRoot  = rtrim($amp_conf['AMPWEBROOT'] ?? '/var/www/html', '/');
$tftpDir     = '/tftpboot';
$phoneSettingsDir = "{$ampWebRoot}/PhoneSettings";
// VPN state lives under the real web-root PhoneSettings directory.
// Refuse a symlink here so private keys cannot be read/written in /tftpboot.
if (is_link($phoneSettingsDir)) {
    die('ovpn_mgr: PhoneSettings must be a real directory, not a symlink to /tftpboot. Migrate VPN data to the canonical web-root PhoneSettings/openvpn path first.');
}
$baseDir     = "{$phoneSettingsDir}/openvpn";
if (is_dir("/tftpboot/openvpn") && !is_dir($baseDir)) {
    die('ovpn_mgr: Legacy VPN data was found at /tftpboot/openvpn. Back it up and migrate it to ' . htmlspecialchars($baseDir) . ' before using this module.');
}
$pkgDir      = "{$phoneSettingsDir}/vpnkeys";
$pkiDir      = "{$baseDir}/legacy_pki";
$logFile     = "{$baseDir}/logs/openvpn.log";
$serverConf  = "{$baseDir}/legacy-vpn.conf";
$crlFile     = "{$pkiDir}/crl.pem";
$pidFile     = "{$baseDir}/openvpn.pid";
$serverKey   = "{$pkiDir}/private/server.key";
$moduleRoot  = __DIR__;
$ovpnctl     = "{$moduleRoot}/scripts/ovpnctl";
$setupScript = "{$moduleRoot}/scripts/setup-root.sh";

// buildClientPackage(), revokeExtension(), startOpenVpnServer(),
// stopOpenVpnServer(), getActiveServerSettings(), getOpenVpnVersion()
// and tailFile() now live in lib/client_ops.php, shared with any other
// module (e.g. yealink_epm) that wants to generate/revoke an OpenVPN
// client package through this module's own PKI instead of reimplementing
// it themselves.
require_once "{$moduleRoot}/lib/client_ops.php";

// ============================================================================
// CSRF token - one per session, required on every state-changing request.
// ============================================================================
if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}
if (empty($_SESSION['ovpn_mgr_csrf'])) {
    $_SESSION['ovpn_mgr_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['ovpn_mgr_csrf'];

// Align PHP to the system's real timezone
if (!function_exists('ovpn_mgr_detect_system_timezone')) {
    function ovpn_mgr_detect_system_timezone() {
        if (file_exists('/etc/timezone')) {
            $tz = trim((string)@file_get_contents('/etc/timezone'));
            if ($tz !== '' && @timezone_open($tz) !== false) {
                return $tz;
            }
        }
        $tzOut = trim((string)@shell_exec('timedatectl show -p Timezone --value 2>/dev/null'));
        if ($tzOut !== '' && @timezone_open($tzOut) !== false) {
            return $tzOut;
        }
        return null;
    }
}
$ovpnMgrSystemTz = ovpn_mgr_detect_system_timezone();
if ($ovpnMgrSystemTz) {
    date_default_timezone_set($ovpnMgrSystemTz);
}

function csrf_require() {
    global $csrfToken;
    $sent = $_POST['csrf_token'] ?? '';
    if (!hash_equals($csrfToken, (string)$sent)) {
        http_response_code(403);
        die('Security check failed (invalid or expired form token). Please reload the page and try again.');
    }
}

// ============================================================================
// Helper Functions (pure computation)
// ============================================================================
function reqIpsToNetmask($reqIps) {
    $needed = intval($reqIps) + 3;
    $bits = 32 - ceil(log($needed, 2));
    if ($bits < 16) { $bits = 16; }
    if ($bits > 29) { $bits = 29; }
    $mask = (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
    return long2ip($mask);
}

function cidrToNetmask($cidr) {
    $cidr = intval($cidr);
    if ($cidr < 16) { $cidr = 16; }
    if ($cidr > 29) { $cidr = 29; }
    $mask = (0xFFFFFFFF << (32 - $cidr)) & 0xFFFFFFFF;
    return long2ip($mask);
}

function netmaskToReqIps($netmask) {
    $long = ip2long($netmask);
    if ($long === false) { return 250; }
    $base = sprintf("%b", $long);
    $cidr = substr_count($base, '1');
    $hostBits = 32 - $cidr;
    return ($hostBits > 1) ? (pow(2, $hostBits) - 3) : 1;
}

function calculateSubnetDetails($hostIp, $netmask) {
    $longHost = ip2long($hostIp);
    $longMask = ip2long($netmask);

    if ($longHost === false || $longMask === false) {
        return [
            'valid' => false,
            'is_network_or_bcast' => false,
            'net_ip' => '10.8.0.0',
            'suggested_first' => '10.8.0.1',
            'suggested_prev_last' => '10.8.0.254',
            'range_start' => '10.8.0.1',
            'range_end' => '10.8.0.254',
            'is_first_host' => true,
            'cidr' => 24,
        ];
    }

    $longNet = $longHost & $longMask;
    $broadcastLong = $longNet | (~$longMask & 0xFFFFFFFF);

    $isNetwork = ($longHost === $longNet);
    $isBroadcast = ($longHost === $broadcastLong);
    $isInvalid = ($isNetwork || $isBroadcast);

    $firstUsable = $longNet + 1;
    $lastUsable = $broadcastLong - 1;
    $prevBlockLastUsable = $longNet - 2;

    $cidrBits = 32 - strlen(rtrim(decbin(($longMask ^ 0xFFFFFFFF) & 0xFFFFFFFF), '0'));
    $cidrBits = max(0, min(32, 32 - substr_count(decbin((~$longMask) & 0xFFFFFFFF), '1')));

    return [
        'valid' => true,
        'is_network_or_bcast' => $isInvalid,
        'net_ip' => long2ip($longNet),
        'suggested_first' => long2ip($firstUsable),
        'suggested_prev_last' => long2ip($prevBlockLastUsable),
        'range_start' => long2ip($firstUsable),
        'range_end' => long2ip($lastUsable),
        'is_first_host' => ($longHost === $firstUsable),
        'cidr' => $cidrBits,
    ];
}

function isValidHostOrIp($s) {
    if (!is_string($s) || $s === '' || strlen($s) > 253) { return false; }
    if (preg_match('/[\x00-\x1F\x7F]/', $s)) { return false; }
    if (filter_var($s, FILTER_VALIDATE_IP)) { return true; }
    return (bool) preg_match('/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/', $s);
}

function hasOvpnctlAccess($ovpnctl) {
    exec('sudo -n ' . escapeshellarg($ovpnctl) . ' check 2>&1', $out, $rc);
    return ($rc === 0);
}

function syncOvpnFirewallPortRuleStandalone($port, $logFile, $ovpnctl) {
    $result = ['written' => false, 'reloaded' => false, 'message' => ''];

    exec('sudo -n ' . escapeshellarg($ovpnctl) . ' port-sync ' . escapeshellarg($port) . ' 2>&1', $out, $rc);

    $result['written']  = ($rc === 0);
    $result['reloaded'] = ($rc === 0);

    @file_put_contents(
        $logFile,
        "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Standalone iptables fallback: ovpnctl port-sync {$port}, exit={$rc}\n"
            . implode("\n", $out) . "\n",
        FILE_APPEND
    );

    if ($rc !== 0) {
        $result['message'] = "Could not open UDP/{$port} via the standalone iptables fallback (ovpnctl port-sync exited {$rc}).";
    }

    return $result;
}

function syncOvpnFirewallPortRule($newPort, $logFile, $ovpnctl) {
    $port = intval($newPort);
    $serviceName = 'OpenVPN Manager';
    $result = ['written' => false, 'reloaded' => false, 'message' => ''];

    if (!class_exists('FreePBX')) {
        return syncOvpnFirewallPortRuleStandalone($port, $logFile, $ovpnctl);
    }

    try {
        $fw = \FreePBX::Firewall();
    } catch (Throwable $e) {
        @file_put_contents($logFile, "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] FreePBX Firewall module not present - using standalone iptables fallback.\n", FILE_APPEND);
        return syncOvpnFirewallPortRuleStandalone($port, $logFile, $ovpnctl);
    }

    if (!method_exists($fw, 'addCustomService')) {
        $result['message'] = "This FreePBX version's Firewall module doesn't expose addCustomService().";
        @file_put_contents($logFile, "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] " . $result['message'] . "\n", FILE_APPEND);
        return $result;
    }

    try {
        $existingId = null;
        if (method_exists($fw, 'getAllCustomServices')) {
            foreach ((array)$fw->getAllCustomServices() as $key => $svc) {
                $svcArr = (array)$svc;
                $svcName = $svcArr['name'] ?? $svcArr['n'] ?? '';
                if ($svcName === $serviceName) {
                    $existingId = $svcArr['id'] ?? $key;
                    break;
                }
            }
        }

        if ($existingId !== null && method_exists($fw, 'editCustomService')) {
            $fw->editCustomService($existingId, $serviceName, 'udp', $port);
        } else {
            if ($existingId !== null && method_exists($fw, 'deleteCustomService')) {
                $fw->deleteCustomService($existingId);
            }
            $fw->addCustomService($serviceName, 'udp', $port);
        }
        $result['written'] = true;
    } catch (Throwable $e) {
        $result['message'] = "Error calling Firewall API: " . $e->getMessage();
        @file_put_contents($logFile, "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] " . $result['message'] . "\n", FILE_APPEND);
        return $result;
    }

    if (method_exists($fw, 'setCustomServiceZones') && method_exists($fw, 'getAllCustomServices')) {
        $zoneTargetId = null;
        foreach ((array)$fw->getAllCustomServices() as $key => $svc) {
            $svcArr = (array)$svc;
            $svcName = $svcArr['name'] ?? $svcArr['n'] ?? '';
            if ($svcName === $serviceName) {
                $zoneTargetId = $svcArr['id'] ?? $key;
                break;
            }
        }
        if ($zoneTargetId !== null) {
            try {
                $fw->setCustomServiceZones($zoneTargetId, ['external', 'internal', 'other']);
            } catch (Throwable $e) {
                @file_put_contents($logFile, "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Could not set zones: " . $e->getMessage() . "\n", FILE_APPEND);
            }
        }
    }

    // NOTE: this used to call 'fwconsole firewall restart' here directly,
    // and applyVpnRoutingAndNat() below called it again a moment later for
    // the trusted-zone change. That's two full firewall rebuilds (each can
    // take several seconds) for one save. The caller now issues a single
    // combined restart after both updates are made; we just report that one
    // is needed.
    $result['reloaded'] = true; // will be finalized by the caller's single restart
    $result['restart_needed'] = true;
    @file_put_contents(
        $logFile,
        "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Synced Custom Service '{$serviceName}' to UDP/{$port}; firewall restart deferred to caller.\n",
        FILE_APPEND
    );

    return $result;
}

function applyVpnRoutingAndNat($ovpnctl, $netIp, $cidrBits, $iface, $baseDir) {
    exec('sudo -n ' . escapeshellarg($ovpnctl) . ' ipforward-on 2>&1');
    $cidr = "{$netIp}/{$cidrBits}";
    $restartNeeded = false;

    if (class_exists('FreePBX')) {
        $trustedCidrState = "{$baseDir}/.trusted_cidr_state";
        $prevCidr = file_exists($trustedCidrState) ? trim((string)@file_get_contents($trustedCidrState)) : '';

        if ($prevCidr !== $cidr) {
            // Only touch the trusted-zone rules (and therefore need a
            // restart) when the CIDR has actually changed. tun+ only needs
            // adding once; re-running 'add' for an interface/CIDR already
            // trusted is a harmless no-op for the ruleset but still costs a
            // process + doesn't need a restart, so skip it entirely here.
            exec('fwconsole firewall add trusted tun+ 2>&1');
            if ($prevCidr !== '') {
                exec('fwconsole firewall del trusted ' . escapeshellarg($prevCidr) . ' 2>&1');
            }
            exec('fwconsole firewall add trusted ' . escapeshellarg($cidr) . ' 2>&1');
            @file_put_contents($trustedCidrState, $cidr);
            $restartNeeded = true;
        }
    }

    $cmd = 'sudo -n ' . escapeshellarg($ovpnctl) . ' nat-sync ' . escapeshellarg($cidr) . ' ' . escapeshellarg($iface);
    exec($cmd . ' 2>&1');

    return $restartNeeded;
}

// ============================================================================
// Read-only AJAX endpoints
// ============================================================================
if (isset($_GET['action']) && $_GET['action'] === 'fetch_log') {
    if (ob_get_level()) { ob_end_clean(); }
    header('Content-Type: text/plain; charset=utf-8');
    if (file_exists($logFile)) {
        $lines = explode("\n", tailFile($logFile, 200));
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

if (isset($_GET['action']) && $_GET['action'] === 'fetch_public_ip') {
    if (ob_get_level()) { ob_end_clean(); }
    header('Content-Type: text/plain; charset=utf-8');
    $publicIp = @file_get_contents('https://api.ipify.org');
    echo $publicIp ? trim($publicIp) : ($_SERVER['SERVER_ADDR'] ?? '');
    exit();
}

// ============================================================================
// Write AJAX endpoint
// ============================================================================
if (isset($_POST['action']) && $_POST['action'] === 'add_page_break') {
    csrf_require();
    if (ob_get_level()) { ob_end_clean(); }
    if (file_exists($logFile)) {
        $dividerText = "\n#############################################\n--- SEPARATOR (" . date('Y-m-d H:i:s') . ") ---\n#############################################\n";
        $written = @file_put_contents($logFile, $dividerText, FILE_APPEND);
        echo $written !== false ? 'success' : 'error_write';
    } else {
        echo 'error_nofile';
    }
    exit();
}

require_once __DIR__ . '/ovpn_mgr.class.php';
$freepbxObj = \FreePBX::create();
$ovpn_mgr = new \FreePBX\modules\Ovpn_mgr($freepbxObj);

// ============================================================================
// Gather FreePBX Extensions & Yealink EPM MAC Addresses
// ============================================================================
$available_extensions = [];
if (function_exists('core_users_list')) {
    $users = core_users_list();
    foreach ($users as $u) {
        $available_extensions[$u[0]] = $u[1] . " (" . $u[0] . ")";
    }
} elseif (class_exists('FreePBX')) {
    try {
        $core = \FreePBX::Core();
        if (method_exists($core, 'listUsers')) {
            foreach ($core->listUsers() as $u) {
                $available_extensions[$u['extension']] = $u['name'] . " (" . $u['extension'] . ")";
            }
        }
    } catch (\Throwable $e) {}
}

$available_macs = [];
// Uses the top-level $tftpDir (/tftpboot) directly rather than
// "{$ampWebRoot}/tftpboot" - that path only resolved correctly when
// yealink_epm's optional convenience-alias symlink happened to exist,
// and reassigning $tftpDir here would also have clobbered its later use
// by the restore-from-backup handler below.
if (is_dir($tftpDir)) {
    foreach (glob("{$tftpDir}/[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F].cfg") as $cfgFile) {
        $mac = strtolower(pathinfo($cfgFile, PATHINFO_FILENAME));
        $available_macs[$mac] = strtoupper($mac);
    }
}

// Exclude extensions and MAC addresses that already have a provisioning
// archive. A generated archive reserves both identifiers until it is deleted.
$used_extensions = [];
$used_macs = [];
if (is_dir($pkgDir)) {
    foreach (glob("{$pkgDir}/*.tar") as $existingPkg) {
        $existingName = basename($existingPkg);
        // Current format: MAC_EXT_ovpn.tar. Also recognize older tokenized
        // archives: MAC_EXT_TOKEN_ovpn.tar (and legacy *_keys.tar archives).
        if (preg_match('/^([a-f0-9]{12})_(\d+)(?:_[a-f0-9]{8})?_(?:ovpn|keys)\.tar$/i', $existingName, $pkgMatch)) {
            $used_macs[strtolower($pkgMatch[1])] = true;
            $used_extensions[(string)$pkgMatch[2]] = true;
        }
    }
}
$available_extensions = array_diff_key($available_extensions, $used_extensions);
$available_macs = array_diff_key($available_macs, $used_macs);

// ============================================================================
// Sign Module
// ============================================================================
if (isset($_POST['action']) && $_POST['action'] === 'resign_custom_module_with_pass') {
    csrf_require();
    if (ob_get_level()) { ob_end_clean(); }
    header('Content-Type: application/json');

    $modulePath = $moduleRoot;
    $signerScript = file_exists("{$modulePath}/devtools/signer.php")
        ? "{$modulePath}/devtools/signer.php"
        : "{$modulePath}/signer.php";

    if (file_exists($signerScript)) {
        $cmd = sprintf('/usr/bin/php %s %s 2>&1', escapeshellarg($signerScript), escapeshellarg($modulePath));
        exec($cmd, $output, $returnVar);
        clearstatcache(true, "{$modulePath}/module.sig");

        if (file_exists("{$modulePath}/module.sig")) {
            if (isset($pdo)) {
                try {
                    $pdo->exec("DELETE FROM notifications WHERE module IN ('core', 'framework', 'freepbx')");
                } catch (\Exception $e) {}
            }
            echo json_encode(['status' => 'success']);
            exit();
        }
        echo json_encode(['status' => 'error', 'message' => implode("\n", $output)]);
        exit();
    }
    echo json_encode(['status' => 'error', 'message' => 'Signer script not found.']);
    exit();
}

// ============================================================================
// Service Control
// ============================================================================
if (isset($_POST['action']) && $_POST['action'] === 'manage_service') {
    csrf_require();
    $serviceAction = $_POST['service_cmd'] ?? '';
    $settingsNow = getActiveServerSettings($serverConf);

    if ($serviceAction === 'start' || $serviceAction === 'restart') {
        @unlink("{$baseDir}/.stopped");
        stopOpenVpnServer($ovpnctl);
        startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
    } elseif ($serviceAction === 'stop') {
        @touch("{$baseDir}/.stopped");
        stopOpenVpnServer($ovpnctl);
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
        (function_exists('posix_getpwuid') && !file_exists("{$moduleRoot}/module.sig"))
    ) {
        $show_ovpn_resign_button = true;
    }
}

// ============================================================================
// Save Server Settings
// ============================================================================
$settingsError = '';
if (isset($_POST['action']) && $_POST['action'] === 'update_server_settings') {
    csrf_require();

    $newPort   = intval($_POST['ovpn_port']);
    $newIp     = trim((string)($_POST['server_ip'] ?? ''));
    $newHostIp = trim((string)($_POST['ovpn_host_ip'] ?? ''));
    $newCidr   = intval($_POST['ovpn_cidr'] ?? 24);

    if ($newPort <= 0 || $newPort >= 65535) {
        $settingsError = 'Invalid port.';
    } elseif (!isValidHostOrIp($newIp)) {
        $settingsError = 'Server Public IP / Host must be a plain IP address or hostname.';
    } elseif (!filter_var($newHostIp, FILTER_VALIDATE_IP)) {
        $settingsError = 'VPN Host IP must be a valid IP address.';
    } else {
        $oldSettings = getActiveServerSettings($serverConf);
        $oldPort     = intval($oldSettings['port']);
        $oldIp       = $oldSettings['ip'];

        $newNetmask    = cidrToNetmask($newCidr);
        $subnetDetails = calculateSubnetDetails($newHostIp, $newNetmask);
        $newNetIp      = $subnetDetails['net_ip'];

        $finalHostIp = $subnetDetails['suggested_first'];
        $hostIpWasCorrected = ($finalHostIp !== $newHostIp);

        // The firewall/NAT/SIP-localnet sync below is only relevant when the
        // port or the VPN subnet actually changed - re-saving unrelated
        // settings (e.g. cipher) with the same port/subnet doesn't need any
        // of it, and each of those steps can cost several seconds.
        $portChanged   = ($oldPort !== $newPort);
        $subnetChanged = ($oldSettings['host_ip'] !== $finalHostIp) || ($oldSettings['net_mask'] !== $newNetmask);

        // Read and update the actual active directive, accepting tabs/multiple spaces
        // and inserting it if missing. Write atomically and verify before restarting;
        // a silent failed write must never look like a successful port change.
        $confContent = is_readable($serverConf) ? (string)file_get_contents($serverConf) : '';
        if ($confContent === '') {
            $settingsError = 'Unable to read the OpenVPN server configuration.';
        } else {
            $lines = preg_split('/\r?\n/', $confContent);
            $portWritten = false;
            $updatedLines = [];
            foreach ($lines as $line) {
                if (preg_match('/^[ \t]*port[ \t]+\d+(?:[ \t]+#.*)?[ \t]*$/i', $line)) {
                    if (!$portWritten) {
                        $updatedLines[] = "port {$newPort}";
                        $portWritten = true;
                    }
                    continue; // remove duplicate active port directives
                }
                $updatedLines[] = $line;
            }
            if (!$portWritten) { $updatedLines[] = "port {$newPort}"; }
            $confContent = implode("\n", $updatedLines);

            if (preg_match('/^server\s+[0-9\.]+\s+[0-9\.]+/m', $confContent)) {
                $confContent = preg_replace('/^server\s+[0-9\.]+\s+[0-9\.]+/m', "server {$newNetIp} {$newNetmask}", $confContent, 1);
            } else {
                $confContent .= "\nserver {$newNetIp} {$newNetmask}";
            }

            if (preg_match('/^# vpn-host-ip .*/m', $confContent)) {
                $confContent = preg_replace('/^# vpn-host-ip .*/m', "# vpn-host-ip {$finalHostIp}", $confContent, 1);
            } else {
                $confContent .= "\n# vpn-host-ip {$finalHostIp}";
            }
            if (preg_match('/^# client-remote-host .*/m', $confContent)) {
                $confContent = preg_replace('/^# client-remote-host .*/m', "# client-remote-host {$newIp}", $confContent, 1);
            } else {
                $confContent .= "\n# client-remote-host {$newIp}";
            }

            $tmpConf = $serverConf . '.tmp.' . getmypid();
            $oldMode = @fileperms($serverConf);
            $writeOk = (@file_put_contents($tmpConf, rtrim($confContent) . "\n", LOCK_EX) !== false);
            if ($writeOk) {
                if ($oldMode !== false) { @chmod($tmpConf, $oldMode & 0777); }
                $writeOk = @rename($tmpConf, $serverConf);
            }
            // Some installations permit writes to the config file but not a
            // rename in its directory. Fall back to a checked in-place write.
            if (!$writeOk) {
                @unlink($tmpConf);
                $writeOk = (@file_put_contents($serverConf, rtrim($confContent) . "\n", LOCK_EX) !== false);
            }
            if (!$writeOk) {
                $settingsError = 'Could not save the OpenVPN configuration. Check file permissions and try again.';
            } else {
                clearstatcache(true, $serverConf);
                $savedText = (string)@file_get_contents($serverConf);
                $savedSettings = getActiveServerSettings($serverConf);
                if ((int)$savedSettings['port'] !== $newPort || !preg_match('/^[ \t]*port[ \t]+' . preg_quote((string)$newPort, '/') . '(?:[ \t]+#.*)?[ \t]*$/mi', $savedText)) {
                    $settingsError = 'The configuration was written, but the saved port did not verify. OpenVPN was not restarted.';
                }
            }
        }

        if ($settingsError === '') {
            // Keep FreePBX Asterisk SIP Settings > NAT > Local Networks in sync
            // with the OpenVPN pool, but only bother calling out to it when
            // the subnet actually changed. sip-localnet-sync.php itself no
            // longer calls 'fwconsole reload' - it flags FreePBX via
            // needreload() (a single fast DB write) so the change shows up
            // as a normal orange/red "Apply Config" bar, same as any other
            // module's settings, instead of forcing an expensive reload
            // inline on every subnet-changing save. That means this call is
            // now fast enough to just run synchronously like everything else.
            $sipSyncOut = [];
            $sipSyncRc = 0;
            if ($subnetChanged) {
                exec('sudo -n ' . escapeshellarg($ovpnctl) . ' sip-localnet-sync 2>&1', $sipSyncOut, $sipSyncRc);
                // FreePBX may emit shutdown noise after the helper's success marker;
                // trust the explicit marker rather than PHP's final exit status alone.
                $sipSyncConfirmed = in_array('SIP_LOCALNET_SYNC_OK', $sipSyncOut, true);
                if (!$sipSyncConfirmed || $sipSyncRc !== 0) {
                    if ($sipSyncConfirmed) {
                        unset($_SESSION['ovpn_mgr_sipnat_warning']);
                    } else {
                        $_SESSION['ovpn_mgr_sipnat_warning'] = 'VPN settings were saved, but SIP NAT Local Networks could not be synchronized: ' . implode(' ', $sipSyncOut);
                    }
                } else {
                    unset($_SESSION['ovpn_mgr_sipnat_warning']);
                }
            }
            $wasStopped = file_exists("{$baseDir}/.stopped");
            if (!$wasStopped) {
                stopOpenVpnServer($ovpnctl);
            }

        // Firewall custom service (port) and trusted-zone/NAT (subnet) only
        // need touching when the relevant value changed. When both are
        // unchanged this whole block - including any fwconsole firewall
        // restart - is skipped entirely.
        $fwRestartNeeded = false;

        if ($portChanged) {
            $fwSyncResult = syncOvpnFirewallPortRule($newPort, $logFile, $ovpnctl);
            if (!$fwSyncResult['written']) {
                $_SESSION['ovpn_mgr_fw_warning'] = $fwSyncResult['message'];
            }
            $fwRestartNeeded = $fwRestartNeeded || ($fwSyncResult['restart_needed'] ?? false);
        }

        if ($subnetChanged) {
            exec("ip route show default | awk '{print \$5}'", $defaultIfOut);
            $primaryIf = '';
            foreach ($defaultIfOut as $ifLine) {
                $ifLine = trim($ifLine);
                if ($ifLine !== '' && preg_match('/^[a-zA-Z0-9_.@-]{1,15}$/', $ifLine)) {
                    $primaryIf = $ifLine;
                    break;
                }
            }
            if ($primaryIf === '') { $primaryIf = 'ens192'; }

            $natRestartNeeded = applyVpnRoutingAndNat($ovpnctl, $newNetIp, $subnetDetails['cidr'], $primaryIf, $baseDir);
            $fwRestartNeeded = $fwRestartNeeded || $natRestartNeeded;
        }

        if ($fwRestartNeeded) {
            // Single combined restart for both the custom-service and
            // trusted-zone changes above, instead of one restart per change.
            $restartOut = [];
            $restartRc  = 0;
            exec('fwconsole firewall restart 2>&1', $restartOut, $restartRc);
            @file_put_contents(
                $logFile,
                "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Combined fwconsole firewall restart exit={$restartRc}\n"
                    . implode("\n", $restartOut) . "\n",
                FILE_APPEND
            );
            if ($restartRc !== 0 && empty($_SESSION['ovpn_mgr_fw_warning'])) {
                $_SESSION['ovpn_mgr_fw_warning'] = 'Firewall settings were updated, but fwconsole firewall restart returned a non-zero code.';
            }
        }

        if (!$wasStopped) {
            startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
        }

        $existingPkgCount = count(glob("{$pkgDir}/*.tar"));
        $addressChanged = ($oldIp !== $newIp) || ($oldPort !== $newPort);
        if ($hostIpWasCorrected || ($addressChanged && $existingPkgCount > 0)) {
            $_SESSION['ovpn_mgr_flash'] = [
                'host_ip_corrected' => $hostIpWasCorrected,
                'entered_host_ip'   => $newHostIp,
                'final_host_ip'     => $finalHostIp,
                'address_changed'   => $addressChanged,
                'pkg_count'         => $existingPkgCount,
            ];
        }

        header("Location: config.php?display=ovpn_mgr");
        exit();
        } // end verified config save
    }
}

// ============================================================================
// Client Package Builder
// ============================================================================
// ============================================================================
// Edit Package MAC/Extension Action
// ============================================================================
if (isset($_POST['action']) && $_POST['action'] === 'edit_package') {
    csrf_require();

    $oldPkg = basename((string)($_POST['old_pkg'] ?? ''));
    $newExt = preg_replace('/[^0-9]/', '', (string)($_POST['ext'] ?? ''));
    $newMac = strtolower(preg_replace('/[^a-fA-F0-9]/', '', (string)($_POST['mac'] ?? '')));
    $oldPath = "{$pkgDir}/{$oldPkg}";

    if (file_exists($oldPath) && !empty($newExt) && !empty($newMac)) {
        $oldExt = '';
        if (preg_match('/^[a-f0-9]+_(\d+)_(ovpn|keys)\.tar$/i', $oldPkg, $m)) {
            $oldExt = $m[1];
        } elseif (preg_match('/^[a-f0-9]+_(\d+)_[a-f0-9]{8}_ovpn\.tar$/i', $oldPkg, $m)) {
            $oldExt = $m[1];
        }

        if (!empty($oldExt)) {
            revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $oldExt);
        }

        @unlink($oldPath);

        $settings = getActiveServerSettings($serverConf);
        $selectedCipher = (string)($_POST['cipher'] ?? 'AES-128-CBC');
        $allowedCiphers = ['AES-128-CBC', 'AES-256-CBC', 'AES-128-GCM', 'AES-256-GCM'];
        if (!in_array($selectedCipher, $allowedCiphers, true)) {
            $selectedCipher = 'AES-128-CBC';
        }

        // Ensure the server accepts the cipher selected while editing/rebuilding.
        if (is_readable($serverConf) && is_writable($serverConf)) {
            $serverText = (string)file_get_contents($serverConf);
            $serverCipherList = 'AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC';
            if (preg_match('/^data-ciphers\s+.*$/m', $serverText)) {
                $serverText = preg_replace('/^data-ciphers\s+.*$/m', 'data-ciphers ' . $serverCipherList, $serverText);
            } else {
                $serverText .= "\ndata-ciphers " . $serverCipherList . "\n";
            }
            if (!preg_match('/^data-ciphers-fallback\s+/m', $serverText)) {
                $serverText .= "data-ciphers-fallback AES-128-CBC\n";
            }
            file_put_contents($serverConf, $serverText);
        }
        buildClientPackage($pkiDir, $pkgDir, $baseDir, $newExt, $newMac, $settings['ip'], $settings['port'], $selectedCipher);

        if (!file_exists("{$baseDir}/.stopped")) {
            stopOpenVpnServer($ovpnctl);
            startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'generate_package') {
    csrf_require();

    $ext = preg_replace('/[^0-9]/', '', (string)($_POST['ext'] ?? ''));
    $mac = strtolower(preg_replace('/[^a-fA-F0-9]/', '', (string)($_POST['mac'] ?? '')));

    if (!empty($ext) && !empty($mac)) {
        $settings = getActiveServerSettings($serverConf);
        // Keep server negotiation compatible with every cipher offered by the UI.
        // AES-128-CBC remains fallback for legacy phone firmware.
        $serverCipherList = 'AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC';
        if (is_readable($serverConf) && is_writable($serverConf)) {
            $serverText = (string)file_get_contents($serverConf);
            if (preg_match('/^data-ciphers\\s+.*$/m', $serverText)) {
                $serverText = preg_replace('/^data-ciphers\\s+.*$/m', 'data-ciphers ' . $serverCipherList, $serverText);
            } else {
                $serverText .= "\ndata-ciphers " . $serverCipherList . "\n";
            }
            if (!preg_match('/^data-ciphers-fallback\\s+/m', $serverText)) {
                $serverText .= "data-ciphers-fallback AES-128-CBC\n";
            }
            file_put_contents($serverConf, $serverText);
        }
        buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $settings['ip'], $settings['port'], (string)($_POST['cipher'] ?? 'AES-128-CBC'));
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'rebuild_all_packages') {
    csrf_require();

    $settings = getActiveServerSettings($serverConf);
    $existingPkgs = glob("{$pkgDir}/*.tar");
    $rebuilt = 0;

    foreach ($existingPkgs as $pkgPath) {
        $filename = basename($pkgPath);
        $mac = '';
        $ext = '';
        if (preg_match('/^([a-f0-9]+)_(\d+)_[a-f0-9]{8}_ovpn\.tar$/i', $filename, $m)) {
            $mac = strtolower($m[1]);
            $ext = $m[2];
        } elseif (preg_match('/^([a-f0-9]+)_(\d+)_ovpn\.tar$/i', $filename, $m)) {
            $mac = strtolower($m[1]);
            $ext = $m[2];
        }
        if ($ext === '' || $mac === '') {
            continue;
        }

        revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $ext);
        @unlink($pkgPath);
        if (buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $settings['ip'], $settings['port'])) {
            $rebuilt++;
        }
    }

    if (!file_exists("{$baseDir}/.stopped")) {
        stopOpenVpnServer($ovpnctl);
        startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
    }

    unset($_SESSION['ovpn_mgr_flash']);
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'revoke_cert') {
    csrf_require();
    $revokeExt = preg_replace('/[^0-9]/', '', (string)($_POST['revoke_ext'] ?? ''));
    if (!empty($revokeExt)) {
        revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $revokeExt);
        if (!file_exists("{$baseDir}/.stopped")) {
            stopOpenVpnServer($ovpnctl);
            startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'delete_package') {
    csrf_require();
    $targetPkg = basename((string)($_POST['pkg'] ?? ''));
    $fullPath = "{$pkgDir}/{$targetPkg}";

    $looksLikeOurPkg = (strpos($targetPkg, '_ovpn.tar') !== false) || (strpos($targetPkg, '_keys.tar') !== false)
        || (strpos($targetPkg, '-keys.tar') !== false) || (strpos($targetPkg, 'keys_') === 0);

    if (file_exists($fullPath) && $looksLikeOurPkg) {
        $revokeExt = '';
        if (preg_match('/^[a-f0-9]+_(\d+)_(ovpn|keys)\.tar$/i', $targetPkg, $m)) {
            $revokeExt = $m[1];
        } elseif (preg_match('/^[a-f0-9]+_(\d+)_[a-f0-9]{8}_ovpn\.tar$/i', $targetPkg, $m)) {
            $revokeExt = $m[1];
        } elseif (preg_match('/^keys_(\d+)_/i', $targetPkg, $m) || preg_match('/^(\d+)-/i', $targetPkg, $m)) {
            $revokeExt = $m[1];
        }

        @unlink($fullPath);

        if (!empty($revokeExt)) {
            revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $revokeExt);
            if (!file_exists("{$baseDir}/.stopped")) {
                stopOpenVpnServer($ovpnctl);
                startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
            }
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// ============================================================================
// Bulk Actions
// ============================================================================
function ovpnValidateSelectedPkg($pkgDir, $name) {
    $name = basename((string)$name);
    $looksLikeOurPkg = (strpos($name, '_ovpn.tar') !== false) || (strpos($name, '_keys.tar') !== false)
        || (strpos($name, '-keys.tar') !== false) || (strpos($name, 'keys_') === 0);
    $full = "{$pkgDir}/{$name}";
    return ($looksLikeOurPkg && file_exists($full)) ? $name : null;
}

if (isset($_POST['action']) && $_POST['action'] === 'bulk_download_packages') {
    csrf_require();
    $selected = (array)($_POST['pkgs'] ?? []);
    $validFiles = [];
    foreach ($selected as $name) {
        $valid = ovpnValidateSelectedPkg($pkgDir, $name);
        if ($valid !== null) { $validFiles[] = $valid; }
    }
    if (empty($validFiles)) {
        header("Location: config.php?display=ovpn_mgr");
        exit();
    }
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    $bundleName = 'ovpn_packages_' . date('Ymd_His') . '.tar';
    $args = array_map('escapeshellarg', $validFiles);
    header('Content-Description: File Transfer');
    header('Content-Type: application/x-tar');
    header('Content-Disposition: attachment; filename="' . $bundleName . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    flush();
    passthru('cd ' . escapeshellarg($pkgDir) . ' && tar -cf - ' . implode(' ', $args));
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'bulk_revoke_packages') {
    csrf_require();
    $selected = (array)($_POST['pkgs'] ?? []);
    $revokedCount = 0;

    foreach ($selected as $name) {
        $valid = ovpnValidateSelectedPkg($pkgDir, $name);
        if ($valid === null) { continue; }

        $revokeExt = '';
        if (preg_match('/^[a-f0-9]+_(\d+)_[a-f0-9]{8}_ovpn\.tar$/i', $valid, $m)) {
            $revokeExt = $m[1];
        } elseif (preg_match('/^[a-f0-9]+_(\d+)_(ovpn|keys)\.tar$/i', $valid, $m)) {
            $revokeExt = $m[1];
        } elseif (preg_match('/^keys_(\d+)_/i', $valid, $m) || preg_match('/^(\d+)-/i', $valid, $m)) {
            $revokeExt = $m[1];
        }

        @unlink("{$pkgDir}/{$valid}");

        if (!empty($revokeExt)) {
            revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $revokeExt);
            $revokedCount++;
        }
    }

    if ($revokedCount > 0 && !file_exists("{$baseDir}/.stopped")) {
        stopOpenVpnServer($ovpnctl);
        startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
    }

    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'bulk_revoke_rebuild_packages') {
    csrf_require();
    $selected = (array)($_POST['pkgs'] ?? []);
    $settings = getActiveServerSettings($serverConf);
    $rebuilt = 0;

    foreach ($selected as $name) {
        $valid = ovpnValidateSelectedPkg($pkgDir, $name);
        if ($valid === null) { continue; }

        $mac = '';
        $ext = '';
        if (preg_match('/^([a-f0-9]+)_(\d+)_[a-f0-9]{8}_ovpn\.tar$/i', $valid, $m)) {
            $mac = strtolower($m[1]);
            $ext = $m[2];
        } elseif (preg_match('/^([a-f0-9]+)_(\d+)_ovpn\.tar$/i', $valid, $m)) {
            $mac = strtolower($m[1]);
            $ext = $m[2];
        }
        if ($ext === '' || $mac === '') {
            continue;
        }

        revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $ext);
        @unlink("{$pkgDir}/{$valid}");
        if (buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $settings['ip'], $settings['port'])) {
            $rebuilt++;
        }
    }

    if ($rebuilt > 0 && !file_exists("{$baseDir}/.stopped")) {
        stopOpenVpnServer($ovpnctl);
        startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
    }

    header("Location: config.php?display=ovpn_mgr");
    exit();
}

clearstatcache();

$activeSettings = getActiveServerSettings($serverConf);
$currentPort = $activeSettings['port'];
$currentServerIp = $activeSettings['ip'];
$currentHostIp = $activeSettings['host_ip'];
$currentNetMask = $activeSettings['net_mask'];

$subnetDetails = calculateSubnetDetails($currentHostIp, $currentNetMask);
$currentCidr = $subnetDetails['cidr'];
$currentClientIpCount = max(0, (pow(2, 32 - $currentCidr) - 2) - 1);

$logContent = tailFile($logFile, 200);
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
$ip_forward_active = (trim((string)@shell_exec('sysctl -n net.ipv4.ip_forward 2>/dev/null')) === '1');
$hasSudoRule = hasOvpnctlAccess($ovpnctl);

$createdPackages = glob("{$pkgDir}/*.tar");
$issuedCertFiles = glob("{$pkiDir}/issued/*.crt");

$connectedClients = [];
if (file_exists($logFile)) {
    $logData = (string)@file_get_contents($logFile);
    if (preg_match_all('/([A-Za-z0-9_\-]+)\/([\d\.]+:\d+)\s+MULTI_sva:\s+pool returned IPv4=([\d\.]+)/i', $logData, $matches, PREG_SET_ORDER)) {
        $seenIps = [];
        foreach (array_reverse($matches) as $m) {
            $clientName = $m[1];
            $realIp     = $m[2];
            $virtIp     = $m[3];
            if (!in_array($virtIp, $seenIps)) {
                $seenIps[] = $virtIp;
                $activeCipher = 'AES-128-CBC';
                if (preg_match_all('/Data Channel.*[C|c]ipher [\'"]?([A-Za-z0-9\-]+)[\'"]?/i', $logData, $cipherMatches)) {
                    $activeCipher = end($cipherMatches[1]);
                }
                $connectedClients[] = [
                    'mac'           => $clientName,
                    'virtual_ip'    => $virtIp,
                    'real_ip'       => $realIp,
                    'active_cipher' => $activeCipher,
                ];
            }
        }
    }
}
?>

<div class="container-fluid">
    <h1>OpenVPN Manager</h1>

    <?php if (!empty($settingsError)): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($settingsError); ?></div>
    <?php endif; ?>

    <!-- Status Banner -->
    <div class="alert alert-<?php echo ($isRunning && $ip_forward_active) ? 'success' : 'danger'; ?>" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px; padding: 12px 18px;">
        <div style="display: flex; align-items: center; gap: 20px;">
            <div style="font-weight: bold; color: #333; font-size: 13px;">
                <span>OpenVPN Server Status:</span>
                <?php if ($isRunning): ?>
                    <span class="label label-success" style="font-size: 11px; padding: 4px 8px;" title="PID: <?php echo htmlspecialchars(implode(', ', $pids)); ?>">RUNNING</span>
                <?php else: ?>
                    <span class="label label-danger" style="font-size: 11px; padding: 4px 8px;" title="Service Stopped">STOPPED</span>
                <?php endif; ?>
            </div>
            <div style="font-weight: bold; color: #333; font-size: 13px;">
                <span>Kernel IP Forwarding:</span>
                <?php if ($ip_forward_active): ?>
                    <span class="label label-success" style="font-size: 11px; padding: 4px 8px;">ACTIVE</span>
                <?php else: ?>
                    <span class="label label-danger" style="font-size: 11px; padding: 4px 8px;">INACTIVE</span>
                <?php endif; ?>
            </div>
        </div>

        <div style="display: flex; align-items: center; gap: 8px;">
            <form method="post" action="config.php?display=ovpn_mgr" id="ovpnServiceForm" style="display: inline-block; margin: 0;">
                <input type="hidden" name="action" value="manage_service">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <?php if ($isRunning): ?>
                    <button type="submit" name="service_cmd" value="stop" class="btn btn-danger btn-sm" style="background-color: #db001a; border-color: #6b000d;" data-confirm-message="Stop OpenVPN service? Remote clients will disconnect." <?php echo !$hasSudoRule ? 'disabled' : ''; ?>>
                        <i class="fa fa-stop"></i> Stop
                    </button>
                    <button type="submit" name="service_cmd" value="restart" class="btn btn-warning btn-sm" <?php echo !$hasSudoRule ? 'disabled' : ''; ?>>
                        <i class="fa fa-refresh"></i> Restart
                    </button>
                <?php else: ?>
                    <button type="submit" name="service_cmd" value="start" class="btn btn-success btn-sm" <?php echo !$hasSudoRule ? 'disabled' : ''; ?>>
                        <i class="fa fa-play"></i> Start
                    </button>
                <?php endif; ?>
            </form>
            <button type="button" class="btn btn-info btn-sm" data-toggle="modal" data-target="#logModal">
                <i class="fa fa-file-text-o"></i> View Live Logs
            </button>
            <?php if ($show_ovpn_resign_button): ?>
                <button type="button" class="btn btn-danger btn-sm" style="margin: 0; font-weight: bold; background-color: #db001a; border-color: #6b000d;" data-toggle="modal" data-target="#signModal">
                    <i class="fa fa-key"></i> Sign Module
                </button>
            <?php endif; ?>
        </div>
    </div>

    <?php if (!$hasSudoRule): ?>
        <div class="panel panel-warning" style="margin-bottom: 20px;">
            <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-lock"></i> One-Time Root Setup Required</h3></div>
            <div class="panel-body">
                <p>This module needs a narrow, one-time root authorization before it can start the OpenVPN daemon, manage firewall rules, or enable IP forwarding.</p>
                <pre id="setupCmd" title="Click to copy" style="background:#f8f9fa; padding:10px; border:1px solid #ccc; font-size:12px; cursor:pointer;" onclick="copySetupCommand()">sudo bash <?php echo htmlspecialchars($setupScript); ?></pre>
            </div>
        </div>
    <?php elseif (!$ip_forward_active): ?>
        <div class="alert alert-warning" style="margin-bottom: 20px;">
            <i class="fa fa-exclamation-triangle"></i> IP forwarding is currently inactive. Starting the service will enable it.
        </div>
    <?php endif; ?>

    <?php
    $ovpnFwWarning = $_SESSION['ovpn_mgr_fw_warning'] ?? null;
    unset($_SESSION['ovpn_mgr_fw_warning']);
    ?>
    <?php if ($ovpnFwWarning): ?>
        <div class="alert alert-warning" style="margin-bottom: 20px;">
            <i class="fa fa-exclamation-triangle"></i> <strong>Firewall port may not be open yet:</strong> <?php echo nl2br(htmlspecialchars($ovpnFwWarning)); ?>
        </div>
    <?php endif; ?>
    <?php
    $ovpnSipNatWarning = $_SESSION['ovpn_mgr_sipnat_warning'] ?? null;
    unset($_SESSION['ovpn_mgr_sipnat_warning']);
    ?>
    <?php if ($ovpnSipNatWarning): ?>
        <div class="alert alert-warning" style="margin-bottom: 20px;">
            <i class="fa fa-exclamation-triangle"></i> <strong>SIP NAT Local Networks sync warning:</strong> <?php echo htmlspecialchars($ovpnSipNatWarning); ?>
        </div>
    <?php endif; ?>

    <?php
    $ovpnFlash = $_SESSION['ovpn_mgr_flash'] ?? null;
    unset($_SESSION['ovpn_mgr_flash']);
    ?>
    <?php if ($ovpnFlash): ?>
        <div class="alert alert-info" style="margin-bottom: 20px;">
            <?php if (!empty($ovpnFlash['host_ip_corrected'])): ?>
                <p style="margin-bottom: <?php echo !empty($ovpnFlash['address_changed']) ? '10px' : '0'; ?>;">
                    <i class="fa fa-info-circle"></i>
                    VPN Host IP adjusted from <code><?php echo htmlspecialchars($ovpnFlash['entered_host_ip']); ?></code> to <code><?php echo htmlspecialchars($ovpnFlash['final_host_ip']); ?></code>.
                </p>
            <?php endif; ?>
            <?php if (!empty($ovpnFlash['address_changed']) && $ovpnFlash['pkg_count'] > 0): ?>
                <p style="margin-bottom: 10px;">
                    <i class="fa fa-exclamation-triangle"></i>
                    The server address/port changed. <?php echo intval($ovpnFlash['pkg_count']); ?> existing client package(s) still point at the old address.
                </p>
                <form method="post" action="config.php?display=ovpn_mgr" style="display:inline;">
                    <input type="hidden" name="action" value="rebuild_all_packages">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <button type="submit" class="btn btn-warning btn-sm" data-confirm-message="Revoke and rebuild ALL <?php echo intval($ovpnFlash['pkg_count']); ?> existing client package(s)?">
                        <i class="fa fa-refresh"></i> Revoke & Rebuild All (<?php echo intval($ovpnFlash['pkg_count']); ?>)
                    </button>
                </form>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- Top Layout Grid -->
    <div class="row">
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-cogs"></i> OpenVPN Server Settings</h3></div>
                <div class="panel-body">
                    <form method="post" action="config.php?display=ovpn_mgr" id="ovpnSettingsForm">
                        <input type="hidden" name="action" value="update_server_settings">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">

                        <div style="display: flex; align-items: flex-end; gap: 5px; margin-bottom: 15px; flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="server_ip" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 5px;">Server Public IP / Host</label>
                                <input type="text" class="form-control" id="server_ip" name="server_ip" value="<?php echo htmlspecialchars($currentServerIp); ?>" required style="width: 242px; height: 34px; padding-left: 2px">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; visibility: hidden; display: block; margin-bottom: 5px;">Action</label>
                                <button type="button" class="btn btn-default btn-sm" onclick="setPrivateIp()" title="Private IP"  style="width: 34px; height: 34px; padding: 4px 6px; font-size: 13px;">
                                    <i class="fa fa-sitemap"></i> 
                                </button>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; visibility: hidden; display: block; margin-bottom: 5px;">Action</label>
                                <button type="button" class="btn btn-default btn-sm" onclick="fetchPublicIp()" Title="Public IP" style="width: 34px; height: 34px; padding: 4px 6px; font-size: 13px;">
                                    <i class="fa fa-globe"></i> 
                                </button>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="ovpn_port" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 3px;">Port</label>
                                <input type="number" class="form-control" id="ovpn_port" name="ovpn_port" value="<?php echo htmlspecialchars($currentPort); ?>" required style="width: 75px; height: 34px; padding: 6px 4px;">
                            </div>
                        </div>

                        <div style="display: flex; align-items: flex-end; gap: 10px; margin-bottom: 6px; flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="ovpn_host_ip" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 3px;">VPN Host IP</label>
                                <input type="text" class="form-control" id="ovpn_host_ip" name="ovpn_host_ip" value="<?php echo htmlspecialchars($currentHostIp); ?>" required style="width: 130px; height: 34px;" oninput="recalculateRange()">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="ovpn_cidr" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 11px;">CIDR</label>
                                <div style="display: flex; align-items: center;">
                                    <span style="padding: 6px 4px 6px 0; font-size: 14px; color: #666;">/</span>
                                    <input type="number" class="form-control" id="ovpn_cidr" name="ovpn_cidr" value="<?php echo htmlspecialchars($currentCidr); ?>" min="16" max="29" required style="width: 65px; height: 34px; padding: 6px 4px; padding-left: 5px;" oninput="recalculateRange()">
                                </div>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 4px;">Calculated IP Range</label>
                                <div class="well well-sm" id="ip_range_box" style="margin-bottom: 0; padding: 6px 10px; height: 34px; font-size: 11px; font-family: monospace; font-weight: bold; background: #f8f9fa; border-color: #ccc; white-space: nowrap;">
                                    <span id="range_start"><?php echo htmlspecialchars($subnetDetails['range_start']); ?></span> - <span id="range_end"><?php echo htmlspecialchars($subnetDetails['range_end']); ?></span>
                                </div>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 3px;">Client IPs</label>
                                <div class="well well-sm" id="client_ip_count_box" style="margin-bottom: 0; padding: 6px 10px; height: 34px; font-size: 11px; font-family: monospace; font-weight: bold; background: #f8f9fa; border-color: #ccc; white-space: nowrap; text-align: center;">
                                    <span id="client_ip_count"><?php echo (int)$currentClientIpCount; ?></span>
                                </div>
                            </div>
                        </div>

                        <div id="host_ip_live_notice" style="display: none; margin-bottom: 10px; font-size: 11px; padding: 6px 10px; border-radius: 4px;"></div>

                        <button type="submit" class="btn btn-primary btn-block" style="max-width: 420px;">
                            <i class="fa fa-save"></i> Save Settings & Restart Daemon
                        </button>
                    </form>
                </div>
            </div>

            <!-- Build Provisioning Package Panel -->
            <div class="panel panel-default">
                <div class="panel-heading" style="display: flex; align-items: center; padding: 10px 15px;">
                    <h3 class="panel-title" style="margin: 0;"><i class="fa fa-cube"></i> Build Provisioning Package (vpn.tar)</h3>
                </div>
                <div class="panel-body">
                    <form method="post" action="config.php?display=ovpn_mgr">
                        <input type="hidden" name="action" value="generate_package">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                        
                        <div style="display: flex; align-items: flex-end; gap: 10px; margin-bottom: 10px; flex-wrap: wrap;">
                            <!-- Extension Input with Icon Overlay -->
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 5px;">Extension</label>
                                <div class="select-input-container">
                                    <input type="text" name="ext" list="ext_list" class="form-control" placeholder="Select or type..." required autocomplete="off" style="width: 130px; height: 34px;">
                                </div>
                                <datalist id="ext_list">
                                    <?php foreach ($available_extensions as $e_num => $e_label): ?>
                                        <option value="<?php echo htmlspecialchars($e_num); ?>"><?php echo htmlspecialchars($e_label); ?></option>
                                    <?php endforeach; ?>
                                </datalist>
                            </div>

                            <!-- Phone MAC Address Input with Icon Overlay -->
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 5px;">Phone MAC Address</label>
                                <div class="select-input-container">
                                    <input type="text" name="mac" list="mac_list" class="form-control" placeholder="Select or type..." required autocomplete="off" style="width: 165px; height: 34px;">
                                </div>
                                <datalist id="mac_list">
                                    <?php foreach ($available_macs as $m_raw => $m_label): ?>
                                        <option value="<?php echo htmlspecialchars($m_raw); ?>"><?php echo htmlspecialchars($m_label); ?></option>
                                    <?php endforeach; ?>
                                </datalist>
                            </div>

                            <!-- Cipher selector ordered weakest to strongest -->
                            <div class="form-group" style="margin-bottom: 0; min-width: 0;">
                                <label for="ovpn_cipher" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 5px;">Phone / Cipher</label>
                                <select id="ovpn_cipher" name="cipher" class="form-control" style="height: 34px; width: 215px; max-width: 100%;">
                                    <option value="AES-128-CBC" data-level="legacy" selected>1 &mdash; Weakest / Legacy Compatibility &mdash; AES-128-CBC</option>
                                    <option value="AES-256-CBC" data-level="caution">2 &mdash; AES-256-CBC (Legacy CBC)</option>
                                    <option value="AES-128-GCM" data-level="modern">3 &mdash; AES-128-GCM (Modern)</option>
                                    <option value="AES-256-GCM" data-level="strong">4 &mdash; Strongest &mdash; AES-256-GCM</option>
                                </select>
                            </div>
                        </div>

                        <div id="ovpn_cipher_notice" role="status" aria-live="polite" style="margin: 0 0 10px; padding: 7px 10px; border: 1px solid #faebcc; border-radius: 4px; background: #fcf8e3; color: #8a6d3b; font-size: 11px; line-height: 1.5;">
                            <strong>&#9888;&nbsp; Legacy compatibility:</strong> Uses AES-128-CBC and SHA1. Intended for older phones that cannot use modern OpenVPN data ciphers.
                        </div>

                        <div class="well well-sm" style="font-size: 11px; margin-bottom: 10px; padding: 5px; color: #555; max-width: 375px;">
                            Package will target OpenVPN <strong><?php echo htmlspecialchars($currentServerIp); ?>:<?php echo htmlspecialchars($currentPort); ?></strong> and SIP Gateway <strong><?php echo htmlspecialchars($currentHostIp); ?>:5060</strong>
                        </div>
                        
                        <button type="submit" class="btn btn-success btn-block" style="max-width: 375px;">
                            <i class="fa fa-plus"></i> Generate Keys & Build Package
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-users"></i> Connected OpenVPN Clients</h3></div>
                <div class="panel-body" style="padding: 0; max-height: 300px; overflow-y: auto;">
                    <table class="table table-striped table-bordered" style="margin-bottom: 0; font-size: 12px;">
                        <thead>
                            <tr><th>Extension / MAC</th><th>Virtual IP (TUN)</th><th>Real IP / Peer</th><th>Active Cipher</th></tr>
                        </thead>
                        <tbody>
                            <?php if (empty($connectedClients)): ?>
                                <tr><td colspan="4" class="text-muted" style="padding: 12px; text-align: center;">No active client tunnels currently connected.</td></tr>
                            <?php else: foreach ($connectedClients as $client): ?>
                                <tr>
                                    <td><code><?php echo htmlspecialchars($client['mac']); ?></code></td>
                                    <td><code><?php echo htmlspecialchars($client['virtual_ip']); ?></code></td>
                                    <td><?php echo htmlspecialchars($client['real_ip']); ?></td>
                                    <td><span class="label label-info"><?php echo htmlspecialchars($client['active_cipher']); ?></span></td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="panel panel-default">
                <div class="panel-heading" style="display: flex; align-items: center; justify-content: space-between; padding: 10px 15px;">
                    <h3 class="panel-title" style="margin: 0;"><i class="fa fa-archive"></i> Created Provisioning Archives</h3>
                    <button type="button" class="btn btn-warning btn-xs" data-toggle="modal" data-target="#revokeModal">
                        <i class="fa fa-key"></i> Manage / Revoke Keys (<?php echo count($issuedCertFiles); ?>)
                    </button>
                </div>
                <div class="panel-body" style="padding: 0; max-height: 490px; overflow-y: auto;">
                    <?php if (empty($createdPackages)): ?>
                        <div style="padding: 20px; text-align: center;" class="text-muted">No provisioning packages have been generated yet.</div>
                    <?php else: ?>
                        <table class="table table-striped table-bordered" style="margin-bottom: 0; table-layout: fixed; width: 100%;">
                            <colgroup>
                                <col style="width: 100px;">
                                <col style="width: 160px;">
                                <col style="width: auto;">
                                <col style="width: 165px;">
                            </colgroup>

                            <thead>
                                <tr>
                                    <th colspan="2" style="text-align: center;">Extension</th>
                                    <th style="width: auto; text-align: center;">Date Created</th>
                                    <th style="width: 165px; text-align: center;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
<?php foreach ($createdPackages as $pkgPath):
    $filename = basename($pkgPath);
    $downloadUrl = "/PhoneSettings/vpnkeys/" . rawurlencode($filename);
    
    $parts = explode('_', $filename);
    $pkgExt = '';
    $pkgMac = '';

    if (count($parts) >= 3 && end($parts) === 'ovpn.tar' || strpos($filename, '_ovpn.tar') !== false) {
        $pkgMac = strtoupper($parts[0]);
        $pkgExt = $parts[1];
    } else {
        $pkgMac = !empty($parts[0]) ? strtoupper($parts[0]) : '';
        $pkgExt = !empty($parts[1]) ? $parts[1] : '';
    }

    // Read the archive's current cipher so Edit opens with its existing value.
    $pkgCipher = 'AES-128-CBC';
    $tarConfig = @shell_exec('tar -xOf ' . escapeshellarg($pkgPath) . ' vpn.cnf 2>/dev/null');
    if (is_string($tarConfig) && preg_match('/^data-ciphers\s+([^\s]+)/m', $tarConfig, $cm)) {
        $candidateCipher = trim(explode(':', $cm[1])[0]);
        if (in_array($candidateCipher, ['AES-128-CBC', 'AES-256-CBC', 'AES-128-GCM', 'AES-256-GCM'], true)) {
            $pkgCipher = $candidateCipher;
        }
    } elseif (is_string($tarConfig) && preg_match('/^cipher\s+([^\s]+)/m', $tarConfig, $cm)) {
        if (in_array(trim($cm[1]), ['AES-128-CBC', 'AES-256-CBC', 'AES-128-GCM', 'AES-256-GCM'], true)) {
            $pkgCipher = trim($cm[1]);
        }
    }
?>
    <tr>
        <td style="text-align: left; vertical-align: middle; font-size: 14px; cursor: default; padding-left: 15px; border-right: none;" 
            title="<?php echo htmlspecialchars($filename, ENT_QUOTES); ?>">
            <strong>
                <?php echo !empty($pkgExt) ? 'Ext. ' . htmlspecialchars($pkgExt) : '&mdash;'; ?>
            </strong>
        </td>

        <td style="text-align: left; vertical-align: middle; font-size: 14px; cursor: default; padding-left: 5px; border-left: none;" 
            title="<?php echo htmlspecialchars($filename, ENT_QUOTES); ?>">
            <strong>
                <?php echo !empty($pkgMac) ? 'MAC: ' . htmlspecialchars($pkgMac) : '&mdash;'; ?>
            </strong>
        </td>

        <td style="text-align: center; vertical-align: middle; font-size: 12px;"><?php echo date("Y-m-d H:i", filemtime($pkgPath)); ?></td>
        <td style="text-align: center; vertical-align: middle; padding: 4px 2px;">
            <div style="display: flex; justify-content: center; align-items: center; gap: 3px;">
                <button type="button" class="btn btn-xs btn-info" title="Edit Package Details" onclick="openEditPackageModal('<?php echo htmlspecialchars($filename, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pkgExt, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pkgMac, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pkgCipher, ENT_QUOTES); ?>')">
                    <i class="fa fa-pencil"></i>
                </button>
                <a href="<?php echo htmlspecialchars($downloadUrl); ?>" class="btn btn-xs btn-primary" download title="Download Package">
                    <i class="fa fa-download"></i>
                </a>
                <form method="post" action="config.php?display=ovpn_mgr" style="display:inline;">
                    <input type="hidden" name="action" value="delete_package">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <input type="hidden" name="pkg" value="<?php echo htmlspecialchars($filename); ?>">
                    <button type="submit" class="btn btn-xs btn-danger" title="Delete Package & Revoke Keys" data-confirm-message="Delete package and REVOKE extension keys? This action cannot be undone.">
                        <i class="fa fa-trash"></i>
                    </button>
                </form>
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

<!-- Modal: Edit Archive -->
<div class="modal fade" id="editPackageModal" tabindex="-1" role="dialog" aria-labelledby="editPackageModalLabel">
    <div class="modal-dialog" role="document" style="width: 480px; max-width: 96%;">
        <div class="modal-content">
            <form method="post" action="config.php?display=ovpn_mgr" id="editPackageForm">
                <input type="hidden" name="action" value="edit_package">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <input type="hidden" name="old_pkg" id="edit_old_pkg" value="">

                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="editPackageModalLabel"><i class="fa fa-pencil"></i> Edit Provisioning Archive</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="edit_ext">Extension:</label>
                        <div class="select-input-container">
                            <input type="text" name="ext" id="edit_ext" list="ext_list" class="form-control" required autocomplete="off">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="edit_mac">MAC Address:</label>
                        <div class="select-input-container">
                            <input type="text" name="mac" id="edit_mac" list="mac_list" class="form-control" required autocomplete="off">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="edit_cipher">Phone / Cipher (weakest to strongest):</label>
                        <select name="cipher" id="edit_cipher" class="form-control" required>
                            <option value="AES-128-CBC">1 &mdash; Weakest / Legacy Compatibility &mdash; AES-128-CBC</option>
                            <option value="AES-256-CBC">2 &mdash; AES-256-CBC (Legacy CBC)</option>
                            <option value="AES-128-GCM">3 &mdash; AES-128-GCM (Modern)</option>
                            <option value="AES-256-GCM">4 &mdash; Strongest &mdash; AES-256-GCM</option>
                        </select>
                    </div>
                    <div id="edit_cipher_notice" role="status" aria-live="polite" style="margin: 0; padding: 8px 10px; border: 1px solid #faebcc; border-radius: 4px; background: #fcf8e3; color: #8a6d3b; font-size: 11px; line-height: 1.5;"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary"><i class="fa fa-save"></i> Rebuild & Save</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Hidden form for bulk Download/Revoke -->
<form id="bulkPkgForm" method="post" action="config.php?display=ovpn_mgr" style="display:none;">
    <input type="hidden" name="action" id="bulkPkgAction" value="">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
    <div id="bulkPkgInputs"></div>
</form>

<!-- Modal: Sign Module -->
<div class="modal fade" id="signModal" tabindex="-1" role="dialog" aria-labelledby="signModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="config.php?display=ovpn_mgr" id="signModalForm">
                <input type="hidden" name="action" value="resign_custom_module_with_pass">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="signModalLabel"><i class="fa fa-key"></i> Sign Module</h4>
                </div>
                <div class="modal-body">
                    <p>This re-hashes the module's own files and clears the tamper/signature warning for <code>ovpn_mgr</code>.</p>
                    <div id="signProgressContainer" style="display: none; margin-top: 15px;">
                        <label><i class="fa fa-spinner fa-spin"></i> Signing module... Please wait.</label>
                        <div class="progress progress-striped active" style="margin-bottom: 0;">
                            <div class="progress-bar progress-bar-danger" role="progressbar" style="width: 100%;"></div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal" id="signCancelBtn">Cancel</button>
                    <button type="submit" class="btn btn-danger" id="signSubmitBtn"><i class="fa fa-key"></i> Sign Module</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal: Revocation -->
<div class="modal fade" id="revokeModal" tabindex="-1" role="dialog" aria-labelledby="revokeModalLabel">
    <div class="modal-dialog modal-lg" role="document" style="width: 90%; max-width: 950px;">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="revokeModalLabel"><i class="fa fa-key"></i> Manage / Revoke Keys & Provisioning Packages</h4>
            </div>
            <?php if (!empty($issuedCertFiles)): ?>
                <div style="padding: 6px 10px; border-bottom: 1px solid #ddd; display: flex; align-items: center; gap: 6px; background: #f8f9fa;">
                    <span id="pkgSelectedCount" class="text-muted" style="font-size: 11px;">Select rows with a package to enable Download / Revoke Selected below.</span>
                </div>
            <?php endif; ?>
            <div class="modal-body" style="padding: 0;">
                <?php if (empty($issuedCertFiles)): ?>
                    <div style="padding: 20px;" class="text-muted">No issued client certificates found in PKI storage.</div>
                <?php else: ?>
                    <div style="max-height: 461px; overflow-y: auto;">
                        <table class="table table-striped table-bordered" style="margin-bottom: 0;">
                            <thead>
                                <tr>
                                    <th style="width: 26px; text-align: center; position: sticky; top: 0; background: #d6e4dd; z-index: 1;">
                                        <input type="checkbox" id="pkgSelectAll" title="Select all" onchange="toggleAllOvpnPkgCheckboxes(this)">
                                    </th>
                                    <th style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Common Name (Ext)</th>
                                    <th style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Target (Host:Port)</th>
                                    <th style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Issued Date</th>
                                    <th style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Package</th>
                                    <th style="width: 150px; text-align: center; position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Revocation</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($issuedCertFiles as $crtPath):
                                    $extName = pathinfo($crtPath, PATHINFO_FILENAME);
                                    $parsedCert = openssl_x509_parse((string)@file_get_contents($crtPath));
                                    $validFrom = date("Y-m-d H:i", $parsedCert['validFrom_time_t'] ?? filemtime($crtPath));
                                    $targetHostPort = "{$currentServerIp}:{$currentPort}";
                                    $matchingTars = glob("{$pkgDir}/*_{$extName}_*_ovpn.tar");
                                    if (empty($matchingTars)) { $matchingTars = glob("{$pkgDir}/*_{$extName}_ovpn.tar"); }
                                    $pkgFilename = null;
                                    if (!empty($matchingTars[0]) && file_exists($matchingTars[0])) {
                                        $pkgFilename = basename($matchingTars[0]);
                                        // Read vpn.cnf's remote line straight out of the tar via PharData
                                        // (in-process) instead of forking a 'tar' subprocess per row -
                                        // this loop runs on every page load and can cover a lot of
                                        // packages, so N forks here was a real cost.
                                        try {
                                            $pharEntry = new PharData($matchingTars[0]);
                                            if (isset($pharEntry['vpn.cnf'])) {
                                                $cnfOutput = $pharEntry['vpn.cnf']->getContent();
                                                if (!empty($cnfOutput) && preg_match('/^remote\s+([^\s]+)\s+(\d+)/m', $cnfOutput, $mRemote)) {
                                                    $targetHostPort = "{$mRemote[1]}:{$mRemote[2]}";
                                                }
                                            }
                                        } catch (Throwable $e) {
                                            // Corrupt/unreadable package: fall back to the default host:port above.
                                        }
                                    }
                                ?>
                                    <tr>
                                        <td style="text-align: center; vertical-align: middle;">
                                            <?php if ($pkgFilename !== null): ?>
                                                <input type="checkbox" class="ovpn-pkg-checkbox" value="<?php echo htmlspecialchars($pkgFilename, ENT_QUOTES); ?>" onchange="updateOvpnPkgSelection()">
                                            <?php endif; ?>
                                        </td>
                                        <td><strong>Extension <?php echo htmlspecialchars($extName); ?></strong></td>
                                        <td><code><?php echo htmlspecialchars($targetHostPort); ?></code></td>
                                        <td><?php echo htmlspecialchars($validFrom); ?></td>
                                        <td style="font-size: 12px;">
                                            <?php if ($pkgFilename !== null): ?>
                                                <code style="color: #08096e;"><?php echo htmlspecialchars($pkgFilename); ?></code>
                                            <?php else: ?>
                                                <span class="text-muted">&mdash; no package built</span>
                                            <?php endif; ?>
                                        </td>
                                        <td style="text-align: center;">
                                            <form method="post" action="config.php?display=ovpn_mgr" style="display:inline;">
                                                <input type="hidden" name="action" value="revoke_cert">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                                                <input type="hidden" name="revoke_ext" value="<?php echo htmlspecialchars($extName); ?>">
                                                <button type="submit" class="btn btn-xs btn-danger" data-confirm-message="REVOKE Extension <?php echo htmlspecialchars($extName, ENT_QUOTES); ?>?"><i class="fa fa-ban"></i> Revoke & Block</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            <div class="modal-footer" style="display: flex; justify-content: flex-start; gap: 6px; flex-wrap: wrap;">
                <button type="button" style="height:30px;" id="pkgDownloadSelectedBtn" class="btn btn-primary btn-sm" disabled onclick="submitOvpnBulkPkgAction('bulk_download_packages')">
                    <i class="fa fa-download"></i> Download Selected
                </button>
                <button type="button" id="pkgRevokeSelectedBtn" class="btn btn-danger btn-sm" disabled onclick="submitOvpnBulkPkgAction('bulk_revoke_packages')">
                    <i class="fa fa-ban"></i> Revoke Selected
                </button>
                <button type="button" id="pkgRebuildSelectedBtn" class="btn btn-warning btn-sm" disabled onclick="submitOvpnBulkPkgAction('bulk_revoke_rebuild_packages')">
                    <i class="fa fa-refresh"></i> Revoke & Rebuild Selected
                </button>
                <span style="flex: 1 1 auto;"></span>
                <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal: Log Viewer -->
<div class="modal fade" id="logModal" tabindex="-1" role="dialog" aria-labelledby="logModalLabel">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="logModalLabel"><i class="fa fa-terminal"></i> OpenVPN Live Log Output (Last 200 Lines)</h4>
            </div>
            <div class="modal-body">
                <textarea id="logModalPre" readonly style="width: 100%; height: 350px; min-height: 200px; resize: both; overflow: auto; background: #f4f4f4; color: #111111; font-family: monospace; font-size: 12px; border: 1px solid #ccc; border-radius: 4px; padding: 10px;"><?php echo !empty($logContent) ? htmlspecialchars($logContent) : 'No log output available.'; ?></textarea>
            </div>
            <div class="modal-footer" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 5px;">
                <div style="display: flex; gap: 5px;">
                    <button type="button" class="btn btn-primary btn-sm" onclick="copyLogContent()"><i class="fa fa-copy"></i> Copy Log</button>
                    <button type="button" class="btn btn-info btn-sm" onclick="addLogPageBreak()"><i class="fa fa-minus"></i> Add Line Break</button>
                </div>
                <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Progress Overlay -->
<div class="modal fade ovpn-vcenter" id="ovpnProgressModal" tabindex="-1" role="dialog" data-backdrop="static" data-keyboard="false">
    <div class="modal-dialog" role="document" style="width: 360px;">
        <div class="modal-content" style="text-align: center; padding: 28px 24px;">
            <div class="progress" style="height: 20px; margin-bottom: 14px; border-radius: 4px; background-color: #e9ecef; overflow: hidden;">
                <div class="progress-bar progress-bar-striped active" role="progressbar" style="width: 100%; background-color: #007bff;"></div>
            </div>
            <div id="ovpnProgressLabel" style="font-weight: 600; font-size: 13px; color: #555;">Working, please wait...</div>
        </div>
    </div>
</div>

<style>
/* Styled Combo-Box Appearance for Datalist Inputs */
.select-input-container {
    position: relative;
    display: inline-block;
}
.select-input-container .form-control {
    padding-right: 28px;
}
.select-input-container::after {
    content: "\f0d7"; /* FontAwesome caret-down */
    font-family: FontAwesome;
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    pointer-events: none;
    color: #666;
    font-size: 13px;
}

.modal.ovpn-vcenter {
    text-align: center;
    padding: 0 !important;
}
.modal.ovpn-vcenter:before {
    content: '';
    display: inline-block;
    height: 100%;
    vertical-align: middle;
    margin-right: -4px;
}
.modal.ovpn-vcenter .modal-dialog {
    display: inline-block;
    text-align: left;
    vertical-align: middle;
    margin: 0 auto;
}
#ovpnConfirmModal .modal-dialog {
    width: 480px;
}
#ovpnConfirmModal .modal-body {
    padding: 30px 28px !important;
    font-size: 14px;
    display: flex;
    align-items: center;
    min-height: 90px;
}
</style>

<script>
var OVPN_CSRF = <?php echo json_encode($csrfToken); ?>;

function openEditPackageModal(filename, currentExt, currentMac, currentCipher) {
    $('#edit_old_pkg').val(filename);
    $('#edit_ext').val(currentExt);
    $('#edit_mac').val(currentMac);
    $('#edit_cipher').val(currentCipher || 'AES-128-CBC');
    updateEditCipherNotice();
    $('#editPackageModal').modal('show');
}

function showOvpnProgress(label) {
    $('#ovpnProgressLabel').text(label || 'Working, please wait...');
    $('#ovpnProgressModal').modal('show');
}

function ipToLong(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return 0;
    return parts.reduce(function(acc, octet) { return (acc << 8) + parseInt(octet, 10); }, 0) >>> 0;
}
function longToIp(long) {
    return [(long >>> 24) & 255, (long >>> 16) & 255, (long >>> 8) & 255, long & 255].join('.');
}
function cidrToNetmaskJs(cidr) {
    cidr = parseInt(cidr) || 24;
    if (cidr < 16) cidr = 16;
    if (cidr > 29) cidr = 29;
    var mask = (0xFFFFFFFF << (32 - cidr)) >>> 0;
    return longToIp(mask);
}
function recalculateRange() {
    var hostIp = $('#ovpn_host_ip').val().trim();
    var cidr = parseInt($('#ovpn_cidr').val()) || 24;
    if (cidr < 16) cidr = 16;
    if (cidr > 29) cidr = 29;
    var netmask = cidrToNetmaskJs(cidr);
    var longHost = ipToLong(hostIp);
    var longMask = ipToLong(netmask);
    var $notice = $('#host_ip_live_notice');

    var clientIpCount = Math.max(0, (Math.pow(2, 32 - cidr) - 2) - 1);
    $('#client_ip_count').text(clientIpCount);

    var octets = hostIp.split('.');
    var looksLikeIp = octets.length === 4 && octets.every(function(o) {
        return /^\d{1,3}$/.test(o) && parseInt(o, 10) <= 255;
    });

    if (!looksLikeIp || longHost === 0 || longMask === 0) {
        $('#range_start').text('10.8.0.1'); $('#range_end').text('10.8.0.254');
        if (hostIp.length > 0) {
            $notice.text('This does not look like a valid IPv4 address.')
                .css({ display: 'block', background: '#f2dede', color: '#a94442', border: '1px solid #ebccd1' });
        } else {
            $notice.hide();
        }
        return;
    }
    var longNet = (longHost & longMask) >>> 0;
    var broadcastLong = (longNet | (~longMask & 0xFFFFFFFF)) >>> 0;
    var firstUsableLong = longNet + 1;
    var lastUsableLong = broadcastLong - 1;
    $('#range_start').text(longToIp(firstUsableLong));
    $('#range_end').text(longToIp(lastUsableLong));

    if (longHost !== (firstUsableLong >>> 0)) {
        var isNetOrBcast = (longHost === longNet) || (longHost === broadcastLong);
        var reason = isNetOrBcast
            ? 'that is the network/broadcast address of this block, not a usable host'
            : 'OpenVPN\'s "server" directive always assigns itself the first usable address of the subnet';
        $notice.html('<i class="fa fa-info-circle"></i> This will be saved as <code>' + longToIp(firstUsableLong) + '</code> instead - ' + reason + '.')
            .css({ display: 'block', background: '#fcf8e3', color: '#8a6d3b', border: '1px solid #faebcc' });
    } else {
        $notice.hide();
    }
}

$(document).ready(function() {
    $('[data-toggle="popover"]').popover();
    recalculateRange();
});

$('#signModalForm').on('submit', function(e) {
    e.preventDefault();
    $('#signProgressContainer').show();
    $('#signSubmitBtn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Signing...');
    $('#signCancelBtn').prop('disabled', true);
    $.ajax({
        url: 'config.php?display=ovpn_mgr', type: 'POST', data: $(this).serialize(), dataType: 'json',
        success: function(response) {
            if (response.status === 'success') {
                $('#signModal').modal('hide');
                setTimeout(function() { window.location.reload(); }, 400);
            } else {
                showOvpnToast('Signing failed: ' + (response.message || 'Unknown error'));
                $('#signProgressContainer').hide();
                $('#signSubmitBtn').prop('disabled', false).html('<i class="fa fa-key"></i> Sign Module');
                $('#signCancelBtn').prop('disabled', false);
            }
        },
        error: function() {
            showOvpnToast('An error occurred during communication with the server.');
            $('#signProgressContainer').hide();
            $('#signSubmitBtn').prop('disabled', false).html('<i class="fa fa-key"></i> Sign Module');
            $('#signCancelBtn').prop('disabled', false);
        }
    });
});

function setPrivateIp() {
    $('#server_ip').val(<?php echo json_encode($_SERVER['SERVER_ADDR'] ?? ''); ?>);
}
function fetchPublicIp() {
    $('#server_ip').val('Fetching...');
    $.get('config.php?display=ovpn_mgr&action=fetch_public_ip', function(ip) {
        $('#server_ip').val(ip.trim());
    }).fail(function() {
        $('#server_ip').val(<?php echo json_encode($_SERVER['SERVER_ADDR'] ?? ''); ?>);
    });
}
function showOvpnToast(message) {
    var $toast = $('#ovpnToast');
    if ($toast.length === 0) {
        $toast = $('<div id="ovpnToast"></div>').css({
            position: 'fixed', bottom: '20px', right: '20px', zIndex: 9999,
            background: '#333', color: '#fff', padding: '10px 16px',
            borderRadius: '4px', fontSize: '13px', boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
            opacity: 0, transition: 'opacity 0.3s ease'
        }).appendTo('body');
    }
    if ($toast.data('timeout')) { clearTimeout($toast.data('timeout')); }
    $toast.text(message).css('opacity', 1);
    var t = setTimeout(function() { $toast.css('opacity', 0); }, 3000);
    $toast.data('timeout', t);
}

function copyLogContent() {
    var logTextarea = document.getElementById("logModalPre");
    logTextarea.select();
    logTextarea.setSelectionRange(0, 999999);
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(logTextarea.value).then(function() {
            showOvpnToast("Log output copied to clipboard");
        }).catch(function() { fallbackCopy(logTextarea); });
    } else {
        fallbackCopy(logTextarea);
    }
}
function fallbackCopy(element) {
    try {
        var successful = document.execCommand('copy');
        showOvpnToast(successful ? "Log output copied to clipboard" : "Failed to copy log text");
    } catch (err) {
        showOvpnToast("Browser does not support automatic copying");
    }
}

function copySetupCommand() {
    var text = document.getElementById('setupCmd').innerText;
    var done = function() { showOvpnToast('Command copied to clipboard'); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function() {
            var ta = document.createElement('textarea');
            ta.value = text; document.body.appendChild(ta); ta.select();
            try { document.execCommand('copy'); done(); } catch (e) { showOvpnToast('Could not copy - please select and copy manually'); }
            document.body.removeChild(ta);
        });
    } else {
        var ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); } catch (e) { showOvpnToast('Could not copy - please select and copy manually'); }
        document.body.removeChild(ta);
    }
}

function showOvpnConfirm(message, onConfirm) {
    var $modal = $('#ovpnConfirmModal');
    if ($modal.length === 0) {
        $modal = $(
            '<div class="modal fade ovpn-vcenter" id="ovpnConfirmModal" tabindex="-1" role="dialog">' +
            '<div class="modal-dialog" role="document"><div class="modal-content">' +
            '<div class="modal-body" id="ovpnConfirmMessage" style="padding:20px;"></div>' +
            '<div class="modal-footer" style="border-top:none; padding-top:0;">' +
            '<button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Cancel</button>' +
            '<button type="button" class="btn btn-danger btn-sm" id="ovpnConfirmOkBtn">OK</button>' +
            '</div></div></div></div>'
        ).appendTo('body');
    }
    $('#ovpnConfirmMessage').text(message);
    $('#ovpnConfirmOkBtn').off('click').on('click', function() {
        $modal.modal('hide');
        onConfirm();
    });
    $modal.modal('show');
}

$(document).on('click', 'button[data-confirm-message], a[data-confirm-message]', function(e) {
    e.preventDefault();
    var $btn = $(this);
    var message = $btn.attr('data-confirm-message');
    var progressLabel = $btn.attr('data-progress-label') || 'Working, please wait...';
    var form = $btn.closest('form')[0];
    showOvpnConfirm(message, function() {
        if (form) {
            if ($btn.attr('name')) {
                $('<input>').attr({ type: 'hidden', name: $btn.attr('name'), value: $btn.attr('value') }).appendTo(form);
            }
            showOvpnProgress(progressLabel);
            form.submit();
        }
    });
});

$('#ovpnServiceForm').on('submit', function() {
    showOvpnProgress('Applying service command, please wait...');
});
$('#ovpnSettingsForm').on('submit', function() {
    showOvpnProgress('Saving settings and restarting the OpenVPN daemon...');
});

function toggleAllOvpnPkgCheckboxes(source) {
    $('.ovpn-pkg-checkbox').prop('checked', source.checked);
    updateOvpnPkgSelection();
}

function updateOvpnPkgSelection() {
    var $checked = $('.ovpn-pkg-checkbox:checked');
    var total = $('.ovpn-pkg-checkbox').length;
    $('#pkgDownloadSelectedBtn, #pkgRevokeSelectedBtn, #pkgRebuildSelectedBtn').prop('disabled', $checked.length === 0);
    $('#pkgSelectedCount').text($checked.length > 0 ? ($checked.length + ' selected') : '');
    $('#pkgSelectAll').prop('checked', total > 0 && $checked.length === total);
}

function submitOvpnBulkPkgAction(action) {
    var selected = $('.ovpn-pkg-checkbox:checked').map(function() { return this.value; }).get();
    if (selected.length === 0) {
        return;
    }

    var doSubmit = function() {
        var $inputs = $('#bulkPkgInputs').empty();
        selected.forEach(function(name) {
            $('<input>').attr({ type: 'hidden', name: 'pkgs[]', value: name }).appendTo($inputs);
        });
        $('#bulkPkgAction').val(action);
        if (action === 'bulk_revoke_packages') {
            showOvpnProgress('Revoking ' + selected.length + ' package(s), please wait...');
        } else if (action === 'bulk_revoke_rebuild_packages') {
            showOvpnProgress('Revoking and rebuilding ' + selected.length + ' package(s), please wait...');
        }
        document.getElementById('bulkPkgForm').submit();
    };

    if (action === 'bulk_revoke_packages') {
        showOvpnConfirm(
            'REVOKE and delete ' + selected.length + ' selected package(s)?',
            doSubmit
        );
    } else if (action === 'bulk_revoke_rebuild_packages') {
        showOvpnConfirm(
            'REVOKE and rebuild ' + selected.length + ' selected package(s) with current settings?',
            doSubmit
        );
    } else {
        doSubmit();
    }
}

let logInterval = null;
let isInitialOpen = false;

function fetchOpenVPNLog() {
    $.ajax({
        url: 'config.php', type: 'GET', data: { display: 'ovpn_mgr', action: 'fetch_log' },
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
        url: 'config.php', type: 'POST',
        data: { display: 'ovpn_mgr', action: 'add_page_break', csrf_token: OVPN_CSRF },
        success: function(response) {
            if (response.trim() === 'success') {
                isInitialOpen = true;
                fetchOpenVPNLog();
            } else {
                showOvpnToast("Failed to add line break.");
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
    if (logInterval) { clearInterval(logInterval); logInterval = null; }
});

// Keep cipher guidance visible and color-coded in both package forms.
var ovpnCipherGuidance = {
    'AES-128-CBC': { bg: '#fcf8e3', border: '#faebcc', color: '#8a6d3b', text: '<strong><span style="font-size: 1.5em;">&#9888;</span> Legacy compatibility:</strong> Uses AES-128-CBC and SHA1. Intended for older phones that cannot use modern OpenVPN data ciphers.' },
    'AES-256-CBC': { bg: '#fcf8e3', border: '#ffeeba', color: '#856404', text: '<strong><span style="font-size: 1.5em;">&#9888;</span> CBC compatibility:</strong> AES-256-CBC is stronger than AES-128-CBC, but remains a legacy mode. Verify the phone firmware supports it before provisioning.' },
    'AES-128-GCM': { bg: '#d4edda', border: '#c3e6cb', color: '#155724', text: '<strong><span style="font-size: 1.4em;">&#10004;</span> Modern cipher:</strong> AES-128-GCM. Use only with a phone/firmware that supports OpenVPN GCM data ciphers. Older models may fail to connect.' },
    'AES-256-GCM': { bg: '#d4edda', border: '#c3e6cb', color: '#155724', text: '<strong><span style="font-size: 1.4em;">&#10004;</span> Strong modern cipher:</strong> AES-256-GCM. Strongest option in this list; requires verified GCM support in the phone firmware.' }
};
function applyCipherNotice(selectId, noticeId) {
    var select = document.getElementById(selectId), notice = document.getElementById(noticeId);
    if (!select || !notice) return;
    var item = ovpnCipherGuidance[select.value] || ovpnCipherGuidance['AES-128-CBC'];
    notice.innerHTML = item.text;
    notice.style.backgroundColor = item.bg;
    notice.style.borderColor = item.border;
    notice.style.color = item.color;
}
function updateEditCipherNotice() { applyCipherNotice('edit_cipher', 'edit_cipher_notice'); }
(function () {
    var mainSelect = document.getElementById('ovpn_cipher');
    if (mainSelect) {
        mainSelect.addEventListener('change', function () { applyCipherNotice('ovpn_cipher', 'ovpn_cipher_notice'); });
        applyCipherNotice('ovpn_cipher', 'ovpn_cipher_notice');
    }
    var editSelect = document.getElementById('edit_cipher');
    if (editSelect) {
        editSelect.addEventListener('change', updateEditCipherNotice);
        updateEditCipherNotice();
    }
})();
</script>
