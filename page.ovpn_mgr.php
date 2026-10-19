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
$logFile     = "{$baseDir}/logs-legacy/openvpn.log";
$statusFile  = "{$baseDir}/logs-legacy/openvpn-status.log";
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
// Both OpenVPN instances are managed from this one page (there are no tabs):
//   modern - RSA-2048/SHA-256 PKI, AES-GCM, TLS 1.2+ (its own port, subnet and base directory)
//   legacy - the original daemon: RSA-1024/SHA-1 PKI, AES-CBC, for phones with very old OpenVPN firmware
// Both have the same layout, so every handler below works on whichever instance it has
// selected through $baseDir/$pkiDir/$serverConf/$ovpnctl (see ovpnSelectInstance()):
//   - a request that carries an "instance" field (settings, service control, kill client, log
//     viewer, ...) acts on that instance;
//   - an action on a package works out the instance from the package itself (its certificate / port);
//   - a new package or a cipher change goes to the instance the cipher belongs to
//     (AES-GCM -> modern, AES-CBC -> legacy).
// The page itself shows both instances.
// ============================================================================
$ovpnModernUnavailable = false;
if (!is_file(ovpnConfPath($baseDir, 'modern'))) {
    // install.php creates it; build it now if the module was upgraded without re-running that.
    if (!ovpnEnsureModernInstance($phoneSettingsDir, ovpnConfPath($baseDir, 'legacy'))) {
        $ovpnModernUnavailable = true;
    }
}
$ovpnModernExists  = is_file(ovpnConfPath($baseDir, 'modern'));
$ovpnInstanceList  = $ovpnModernExists ? ['modern', 'legacy'] : ['legacy'];

/** Paths for one instance. */
function ovpnInstanceCtx($baseDir, $moduleRoot, $inst) {
    $inst   = ($inst === 'modern') ? 'modern' : 'legacy';
    $pki    = ovpnPkiDir($baseDir, $inst);
    $logDir = ovpnLogDir($baseDir, $inst);
    return [
        'instance'   => $inst,
        'pkiDir'     => $pki,
        'logDir'     => $logDir,
        'logFile'    => "{$logDir}/openvpn.log",
        'statusFile' => "{$logDir}/openvpn-status.log",
        'serverConf' => ovpnConfPath($baseDir, $inst),
        'crlFile'    => "{$pki}/crl.pem",
        'pidFile'    => ovpnPidFile($baseDir, $inst),
        'serverKey'  => "{$pki}/private/server.key",
        'ovpnctl'    => ovpnctlPathForInstance("{$moduleRoot}/scripts", $inst),
    ];
}

/**
 * Points the per-instance globals ($pkiDir, $serverConf, $ovpnctl, ...) and the helper functions'
 * $GLOBALS['ovpnInstance'] at one instance. Handlers call this before acting on it.
 */
function ovpnSelectInstance($inst) {
    global $baseDir, $moduleRoot, $ovpnInstance, $ovpnOtherInstance, $pkiDir, $logDir, $logFile, $statusFile,
           $serverConf, $crlFile, $pidFile, $serverKey, $ovpnctl, $otherInstanceConf;
    $c = ovpnInstanceCtx($baseDir, $moduleRoot, $inst);
    $ovpnInstance      = $c['instance'];
    $ovpnOtherInstance = ($ovpnInstance === 'modern') ? 'legacy' : 'modern';
    $pkiDir            = $c['pkiDir'];
    $logDir            = $c['logDir'];
    $logFile           = $c['logFile'];
    $statusFile        = $c['statusFile'];
    $serverConf        = $c['serverConf'];
    $crlFile           = $c['crlFile'];
    $pidFile           = $c['pidFile'];
    $serverKey         = $c['serverKey'];
    $ovpnctl           = $c['ovpnctl'];
    $otherInstanceConf = ovpnConfPath($baseDir, $ovpnOtherInstance);
    $GLOBALS['ovpnInstance'] = $ovpnInstance;
}

// A request that names an instance (POST or GET) acts on it; otherwise the modern instance (when it exists).
$ovpnRequestedInstance = $_POST['instance'] ?? ($_GET['instance'] ?? '');
if (!in_array($ovpnRequestedInstance, ['legacy', 'modern'], true) || ($ovpnRequestedInstance === 'modern' && !$ovpnModernExists)) {
    $ovpnRequestedInstance = $ovpnModernExists ? 'modern' : 'legacy';
}
ovpnSelectInstance($ovpnRequestedInstance);

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
// Helper functions below read this through $GLOBALS (the page file runs at the top level of config.php).
$GLOBALS['csrfToken']    = $csrfToken;

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

// Cockpit (web console) detection for the optional header button.
// Installed = its systemd socket unit exists. The port comes from the
// ListenStream= lines (base unit, then drop-ins in name order; an empty
// ListenStream= resets the list), falling back to Cockpit's default 9090.
function ovpnCockpitInfo() {
    static $cached = null;
    if ($cached !== null) { return $cached; }
    $info = ['installed' => false, 'port' => 9090];

    $unitPaths = [
        '/etc/systemd/system/cockpit.socket',
        '/usr/lib/systemd/system/cockpit.socket',
        '/lib/systemd/system/cockpit.socket',
    ];
    $mainUnit = null;
    foreach ($unitPaths as $u) {
        if (@is_file($u)) { $mainUnit = $u; break; }
    }
    if ($mainUnit === null) { return $cached = $info; }
    $info['installed'] = true;

    // Drop-ins: same file name in a higher-priority directory wins.
    $dropIns = [];
    foreach (array_reverse(['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system']) as $dir) {
        foreach ((array)@glob($dir . '/cockpit.socket.d/*.conf') as $f) {
            $dropIns[basename($f)] = $f;
        }
    }
    ksort($dropIns);

    $listen = [];
    foreach (array_merge([$mainUnit], array_values($dropIns)) as $file) {
        $lines = @file($file, FILE_IGNORE_NEW_LINES);
        if (!is_array($lines)) { continue; }
        foreach ($lines as $line) {
            if (!preg_match('/^\s*ListenStream\s*=\s*(.*?)\s*$/i', $line, $m)) { continue; }
            if ($m[1] === '') { $listen = []; } else { $listen[] = $m[1]; }
        }
    }
    foreach ($listen as $v) {
        if ($v === '' || $v[0] === '/' || $v[0] === '@') { continue; } // unix socket
        if (ctype_digit($v)) { $port = (int)$v; }
        elseif (preg_match('/:(\d{1,5})$/', $v, $pm)) { $port = (int)$pm[1]; }
        else { continue; }
        if ($port >= 1 && $port <= 65535) { $info['port'] = $port; break; }
    }
    return $cached = $info;
}

function hasOvpnctlAccess($ovpnctl) {
    exec('sudo -n ' . escapeshellarg($ovpnctl) . ' check 2>&1', $out, $rc);
    if ($rc !== 0) { return false; }
    // The sudoers rule runs this file as root, so it must be root-owned and
    // not writable by the web user (a module upgrade resets it to
    // asterisk:asterisk). Treat that state as "setup needed" too.
    clearstatcache(true, $ovpnctl);
    $st = @stat($ovpnctl);
    if ($st === false || $st['uid'] !== 0 || ($st['mode'] & 0022) !== 0) { return false; }
    return true;
}

// True when FreePBX's own Firewall module is usable through fwconsole.
// Plain Incredible PBX installs often lack it; those use the iptables
// fallbacks in ovpnctl instead. Checked as root via the helper.
function ovpnFreepbxFirewallAvailable($ovpnctl) {
    static $cached = null;
    if ($cached === null) {
        $o = [];
        exec('sudo -n ' . escapeshellarg($ovpnctl) . ' fw-available 2>&1', $o, $rc);
        $cached = ($rc === 0);
    }
    return $cached;
}

// Runs "fwconsole firewall ..." as root through ovpnctl. The web user
// (asterisk) cannot run fwconsole firewall itself, which is why restarts
// issued directly from PHP returned a non-zero code and changed nothing.
function ovpnRunFwconsoleFirewall($ovpnctl, array $args, &$out, &$rc) {
    $out = [];
    $cmd = 'sudo -n ' . escapeshellarg($ovpnctl);
    foreach ($args as $a) { $cmd .= ' ' . escapeshellarg($a); }
    exec($cmd . ' 2>&1', $out, $rc);
}

// Two instances must not share a UDP port or overlap their VPN subnets.
function ovpnSubnetsOverlap($ipA, $maskA, $ipB, $maskB) {
    $a = ip2long($ipA); $b = ip2long($ipB); $ma = ip2long($maskA); $mb = ip2long($maskB);
    if ($a === false || $b === false || $ma === false || $mb === false) { return false; }
    $common = $ma & $mb;
    return (($a & $common) === ($b & $common));
}

function ovpnCrossInstanceConflict($newPort, $newNetIp, $newNetmask, $otherConf) {
    if ($otherConf === '' || !is_file($otherConf)) { return ''; }
    $other = getActiveServerSettings($otherConf);
    if (intval($other['port']) === intval($newPort)) {
        return "UDP port {$newPort} is already used by the other OpenVPN instance. Each instance needs its own port.";
    }
    if (ovpnSubnetsOverlap($newNetIp, $newNetmask, $other['host_ip'], $other['net_mask'])) {
        return 'This VPN subnet overlaps the other OpenVPN instance\'s subnet. Each instance needs its own, non-overlapping subnet.';
    }
    return '';
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
    // Each instance gets its own FreePBX Firewall custom service, or one would overwrite the other.
    $serviceName = (($GLOBALS['ovpnInstance'] ?? 'legacy') === 'modern') ? 'OpenVPN Manager (modern)' : 'OpenVPN Manager';
    $result = ['written' => false, 'reloaded' => false, 'message' => ''];

    if (!class_exists('FreePBX') || !ovpnFreepbxFirewallAvailable($ovpnctl)) {
        @file_put_contents($logFile, "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] FreePBX Firewall module not usable - using standalone iptables fallback.\n", FILE_APPEND);
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

    if (!ovpnFreepbxFirewallAvailable($ovpnctl)) {
        // No FreePBX Firewall module (e.g. plain Incredible PBX): trust the
        // tunnel and VPN pool with module-owned iptables rules instead.
        $tOut = [];
        exec('sudo -n ' . escapeshellarg($ovpnctl) . ' trust-sync ' . escapeshellarg($cidr) . ' 2>&1', $tOut, $tRc);
        @file_put_contents(
            ovpnLogDir($baseDir, $GLOBALS['ovpnInstance']) . '/openvpn.log',
            "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Standalone trust-sync {$cidr}, exit={$tRc}\n" . implode("\n", $tOut) . "\n",
            FILE_APPEND
        );
    } elseif (class_exists('FreePBX')) {
        $trustedCidrState = ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.trusted_cidr_state');
        $prevCidr = file_exists($trustedCidrState) ? trim((string)@file_get_contents($trustedCidrState)) : '';

        if ($prevCidr !== $cidr) {
            // Only touch the trusted-zone rules (and therefore need a
            // restart) when the CIDR has actually changed. tun+ only needs
            // adding once; re-running 'add' for an interface/CIDR already
            // trusted is a harmless no-op for the ruleset but still costs a
            // process + doesn't need a restart, so skip it entirely here.
            ovpnRunFwconsoleFirewall($ovpnctl, ['fw-trusted', 'add', 'tun+'], $o1, $r1);
            if ($prevCidr !== '') {
                ovpnRunFwconsoleFirewall($ovpnctl, ['fw-trusted', 'del', $prevCidr], $o2, $r2);
            }
            ovpnRunFwconsoleFirewall($ovpnctl, ['fw-trusted', 'add', $cidr], $o3, $r3);
            @file_put_contents($trustedCidrState, $cidr);
            $restartNeeded = true;
        }
    }

    $cmd = 'sudo -n ' . escapeshellarg($ovpnctl) . ' nat-sync ' . escapeshellarg($cidr) . ' ' . escapeshellarg($iface);
    exec($cmd . ' 2>&1');

    ovpnSyncFirewallLabels($baseDir, $GLOBALS['ovpnInstance'], __DIR__ . '/scripts');

    return $restartNeeded;
}

// ============================================================================
// FreePBX Firewall labels and trust for each instance
//   - Networks tab: each instance's VPN subnet gets a description ("OpenVPN Legacy ..." / "OpenVPN Modern ...").
//   - Interfaces tab: tun0 (legacy) and tun1 (modern) get the same kind of description.
// Descriptions the admin typed themselves are never overwritten; only empty ones are filled in.
// ============================================================================
function ovpnFirewallLabel($instance) {
    return $instance === 'modern' ? 'OpenVPN Modern (AES-GCM) - ovpn_mgr' : 'OpenVPN Legacy (AES-CBC) - ovpn_mgr';
}

function ovpnFirewallModuleUsable() {
    static $ok = null;
    if ($ok !== null) { return $ok; }
    $ok = false;
    try {
        $ok = class_exists('FreePBX') && \FreePBX::Modules()->checkStatus('firewall');
    } catch (\Throwable $e) { $ok = false; }
    return $ok;
}

// The subnet this instance's server hands out, as "a.b.c.d/nn", plus the one the module last trusted.
function ovpnInstanceSubnets($baseDir, $instance) {
    $conf = ovpnConfPath($baseDir, $instance);
    $cidrs = [];
    if (is_file($conf)) {
        $st = getActiveServerSettings($conf);
        $d = calculateSubnetDetails($st['host_ip'], $st['net_mask']);
        if (!empty($d['net_ip']) && !empty($d['cidr'])) { $cidrs[] = "{$d['net_ip']}/{$d['cidr']}"; }
    }
    $stateFile = ovpnStateFile($baseDir, $instance, '.trusted_cidr_state');
    if (is_file($stateFile)) {
        $prev = trim((string)@file_get_contents($stateFile));
        if ($prev !== '' && !in_array($prev, $cidrs, true)) { $cidrs[] = $prev; }
    }
    return $cidrs;
}

function ovpnSyncFirewallLabels($baseDir, $instance, $scriptsDir) {
    if (!ovpnFirewallModuleUsable()) { return; }
    $label = ovpnFirewallLabel($instance);

    // Networks: only subnets that are already in the firewall's networks list.
    try {
        $fw    = \FreePBX::Firewall();
        $maps  = (array)$fw->getConfig('networkmaps');
        $descs = $fw->getConfig('descriptions', 'network');
        $descs = is_array($descs) ? $descs : [];
        $changed = false;
        foreach (ovpnInstanceSubnets($baseDir, $instance) as $i => $cidr) {
            // The instance's current subnet is labelled even if the firewall's list isn't visible to this
            // request yet (the description is simply waiting there); an older, remembered subnet only if
            // it is still in the list.
            if (($i === 0 || isset($maps[$cidr])) && trim((string)($descs[$cidr] ?? '')) === '') {
                $descs[$cidr] = $label;
                $changed = true;
            }
        }
        if ($changed) { $fw->setConfig('descriptions', $descs, 'network'); }
    } catch (\Throwable $e) {
        // best effort
    }

    // Interface: legacy runs on tun0, modern on tun1 (pinned in modern-vpn.conf).
    $tun = ($instance === 'modern') ? 'tun1' : 'tun0';
    $jsonFile = '/var/spool/asterisk/firewall/interface-zones.json';
    if (is_readable($jsonFile)) {
        $cur = json_decode((string)@file_get_contents($jsonFile), true);
        if (is_array($cur) && trim((string)($cur[$tun]['DESCRIPTION'] ?? '')) !== '' && $cur[$tun]['DESCRIPTION'] !== 'unset') { return; }
    }
    $helper = ovpnctlPathForInstance($scriptsDir, $instance);
    if (is_executable($helper)) {
        $o = []; $rc = 0;
        exec('sudo -n ' . escapeshellarg($helper) . ' fw-iface-desc ' . escapeshellarg($tun) . ' ' . escapeshellarg($label) . ' 2>&1', $o, $rc);
    }
}

// Makes sure this instance's VPN subnet is in FreePBX Firewall's trusted networks. Only adds - it never
// removes a network, so a subnet that was trusted before a change stays. Returns true when a firewall
// restart is needed to apply what was added.
function ovpnEnsureFirewallTrust($ovpnctl, $baseDir, $serverConf, $logFile) {
    $instance = $GLOBALS['ovpnInstance'];
    if (!ovpnFirewallModuleUsable() || !ovpnFreepbxFirewallAvailable($ovpnctl)) { return false; }
    $st = getActiveServerSettings($serverConf);
    $d  = calculateSubnetDetails($st['host_ip'], $st['net_mask']);
    $cidr = "{$d['net_ip']}/{$d['cidr']}";
    $maps = [];
    try { $maps = (array)\FreePBX::Firewall()->getConfig('networkmaps'); } catch (\Throwable $e) {}
    $scriptsDir = __DIR__ . '/scripts';
    $stateFile = ovpnStateFile($baseDir, $instance, '.trusted_cidr_state');
    $alreadyTrusted = (($maps[$cidr] ?? '') === 'trusted')
        || (empty($maps) && is_file($stateFile) && trim((string)@file_get_contents($stateFile)) === $cidr);
    if ($alreadyTrusted) {
        ovpnSyncFirewallLabels($baseDir, $instance, $scriptsDir);
        return false;
    }
    $o = []; $rc = 0;
    ovpnRunFwconsoleFirewall($ovpnctl, ['fw-trusted', 'add', $cidr], $o, $rc);
    @file_put_contents($logFile, "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Added {$cidr} to FreePBX Firewall trusted networks ({$instance}), exit={$rc}\n" . implode("\n", $o) . "\n", FILE_APPEND);
    if ($rc !== 0) { return false; }
    @file_put_contents($stateFile, $cidr);
    ovpnSyncFirewallLabels($baseDir, $instance, $scriptsDir);
    return true;
}

// ============================================================================
// Read-only AJAX endpoints
// ============================================================================
if (isset($_GET['action']) && $_GET['action'] === 'fetch_log') {
    if (ob_get_level()) { ob_end_clean(); }
    header('Content-Type: text/plain; charset=utf-8');
    if (file_exists($logFile)) {
        $breakMarkerFile = ovpnLogDir($baseDir, $GLOBALS['ovpnInstance']) . '/.line_break_pos';
        $breakMarkerPos = file_exists($breakMarkerFile) ? (int)trim((string)@file_get_contents($breakMarkerFile)) : null;
        $lines = explode("\n", tailFileFromMarker($logFile, $breakMarkerPos, 500));
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
        // Recorded *before* the append, so the marker points at the start
        // of the divider itself - fetch_log's tailFileFromMarker() then
        // always includes the divider line, not just whatever happens to
        // follow it.
        $breakMarkerFile = ovpnLogDir($baseDir, $GLOBALS['ovpnInstance']) . '/.line_break_pos';
        $preAppendPos = filesize($logFile);
        $dividerText = "\n#############################################\n--- SEPARATOR (" . date('Y-m-d H:i:s') . ") ---\n#############################################\n";
        $written = @file_put_contents($logFile, $dividerText, FILE_APPEND);
        if ($written !== false) {
            @file_put_contents($breakMarkerFile, (string)$preAppendPos);
        }
        echo $written !== false ? 'success' : 'error_write';
    } else {
        echo 'error_nofile';
    }
    exit();
}

require_once __DIR__ . '/Ovpn_mgr.class.php';
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

// Limit the dropdown to extensions whose device technology is SIP (chan_sip)
// or PJSIP. Other types (IAX2, DAHDi, virtual extensions without a device)
// cannot register a Yealink phone. If the devices table cannot be read, the
// list is left unfiltered rather than emptied.
try {
    $sipDevices = \FreePBX::Database()->query("SELECT id, user FROM devices WHERE LOWER(tech) IN ('sip','pjsip')")->fetchAll(\PDO::FETCH_ASSOC);
    $sipExts = [];
    foreach ($sipDevices as $d) {
        $sipExts[(string)$d['id']] = true;
        if (isset($d['user']) && $d['user'] !== '' && $d['user'] !== 'none') {
            $sipExts[(string)$d['user']] = true;
        }
    }
    $available_extensions = array_intersect_key($available_extensions, $sipExts);
} catch (\Throwable $e) {}

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
        $pkgId = ovpnParsePackageName($existingName, true);
        if ($pkgId !== null) {
            $used_macs[$pkgId['mac']] = true;
            $used_extensions[$pkgId['ext']] = true;
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
// Pending port / subnet changes
// ============================================================================
// "Save Settings" stores a port or VPN subnet change without applying its
// firewall / NAT / SIP-localnet side (see update_server_settings) and leaves
// a .pending_apply marker. Whenever the daemon is started or restarted -
// from Save & Restart Daemon or from the status bar's Start / Restart - the
// waiting changes are applied first and the marker is cleared, which is also
// what makes the Save & Restart Daemon button go away.
function ovpnApplyPendingChanges($baseDir, $serverConf, $ovpnctl, $logFile) {
    $pendFile = ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.pending_apply');
    if (!is_file($pendFile)) { return; }
    $pend = (array)json_decode((string)@file_get_contents($pendFile), true);
    $st = getActiveServerSettings($serverConf);
    $fwRestart = false;

    if (!empty($pend['port'])) {
        $r = syncOvpnFirewallPortRule(intval($st['port']), $logFile, $ovpnctl);
        if (empty($r['written'])) { $_SESSION['ovpn_mgr_fw_warning'] = $r['message']; }
        $fwRestart = $fwRestart || !empty($r['restart_needed']);
    }
    if (!empty($pend['subnet'])) {
        $sipOut = []; $sipRc = 0;
        exec('sudo -n ' . escapeshellarg($ovpnctl) . ' sip-localnet-sync 2>&1', $sipOut, $sipRc);
        if (!in_array('SIP_LOCALNET_SYNC_OK', $sipOut, true)) {
            $_SESSION['ovpn_mgr_sipnat_warning'] = 'VPN settings were saved, but SIP NAT Local Networks could not be synchronized: ' . implode(' ', $sipOut);
        } else {
            unset($_SESSION['ovpn_mgr_sipnat_warning']);
        }
        $details = calculateSubnetDetails($st['host_ip'], $st['net_mask']);
        $ifOut = [];
        exec("ip route show default | awk '{print \$5}'", $ifOut);
        $primaryIf = '';
        foreach ($ifOut as $l) {
            $l = trim($l);
            if ($l !== '' && preg_match('/^[a-zA-Z0-9_.@-]{1,15}$/', $l)) { $primaryIf = $l; break; }
        }
        if ($primaryIf === '') { $primaryIf = 'ens192'; }
        $fwRestart = applyVpnRoutingAndNat($ovpnctl, $details['net_ip'], $details['cidr'], $primaryIf, $baseDir) || $fwRestart;
    }
    if (!ovpnFreepbxFirewallAvailable($ovpnctl)) {
        $ensureOut = []; $ensureRc = 0;
        exec('sudo -n ' . escapeshellarg($ovpnctl) . ' fw-ensure 2>&1', $ensureOut, $ensureRc);
    } elseif ($fwRestart) {
        $o = []; $rc = 0;
        ovpnRunFwconsoleFirewall($ovpnctl, ['fw-restart'], $o, $rc);
        if ($rc !== 0 && empty($_SESSION['ovpn_mgr_fw_warning'])) {
            $_SESSION['ovpn_mgr_fw_warning'] = 'Firewall settings were updated, but fwconsole firewall restart returned a non-zero code (' . $rc . '). See the OpenVPN log for details.';
        }
    }
    @unlink($pendFile);
}

// ============================================================================
// Service Control
// ============================================================================
if (isset($_POST['action']) && $_POST['action'] === 'manage_service') {
    csrf_require();
    $serviceAction = $_POST['service_cmd'] ?? '';
    $settingsNow = getActiveServerSettings($serverConf);

    if ($serviceAction === 'start' || $serviceAction === 'restart') {
        @unlink(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'));
        stopOpenVpnServer($ovpnctl);
        ovpnApplyPendingChanges($baseDir, $serverConf, $ovpnctl, $logFile);
        // A subnet that isn't in FreePBX Firewall's trusted networks yet (for example the modern
        // instance's, which nothing had added) is added now, with a description.
        if (ovpnEnsureFirewallTrust($ovpnctl, $baseDir, $serverConf, $logFile)) {
            $fwO = []; $fwRc = 0;
            ovpnRunFwconsoleFirewall($ovpnctl, ['fw-restart'], $fwO, $fwRc);
            if ($fwRc !== 0 && empty($_SESSION['ovpn_mgr_fw_warning'])) {
                $_SESSION['ovpn_mgr_fw_warning'] = 'The VPN subnet was added to the firewall, but fwconsole firewall restart returned a non-zero code (' . $fwRc . ').';
            }
        }
        startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
    } elseif ($serviceAction === 'stop') {
        @touch(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'));
        stopOpenVpnServer($ovpnctl);
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// ============================================================================
// Kill one connected client's session (by its live status-file Client ID,
// not by common name - see scripts/kill-client.php for why).
// ============================================================================
if (isset($_POST['action']) && $_POST['action'] === 'kill_client') {
    csrf_require();
    $cid = $_POST['client_id'] ?? '';
    if (preg_match('/^[0-9]{1,10}$/', (string)$cid)) {
        exec('sudo -n ' . escapeshellarg($ovpnctl) . ' kill-client ' . escapeshellarg($cid) . ' 2>&1', $killOut, $killRc);
        if ($killRc !== 0) {
            @file_put_contents($logFile, "\n[GUI KILL-CLIENT cid={$cid} Exit Code: {$killRc}]\n" . implode("\n", $killOut) . "\n", FILE_APPEND);
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// ============================================================================
// VPN Access list: networks allowed to reach the phones' tunnel addresses.
// Saved through ovpnctl (root) for every server, which also applies it right away.
// ============================================================================
if (isset($_POST['action']) && $_POST['action'] === 'save_lan_access') {
    csrf_require();
    list($lanOk, $lanBad) = ovpnParseLanAccessInput($_POST['lan_access'] ?? '');
    if (!empty($lanBad)) {
        $_SESSION['ovpn_mgr_settings_error'] = 'VPN access list not saved. Not a valid address or network (use for example 10.2.0.10 or 10.0.20.0/24, prefix /8 to /32): '
            . implode(', ', array_slice($lanBad, 0, 5)) . (count($lanBad) > 5 ? ' ...' : '');
    } elseif (count($lanOk) > 64) {
        $_SESSION['ovpn_mgr_settings_error'] = 'VPN access list not saved. At most 64 entries are allowed.';
    } else {
        $lanArgs = '';
        foreach ($lanOk as $lanEntry) { $lanArgs .= ' ' . escapeshellarg($lanEntry); }
        $lanFailed = '';
        foreach ($ovpnInstanceList as $lanInst) {
            $lanCtlInfo = ovpnInstanceCtx($baseDir, $moduleRoot, $lanInst);
            $lanOut = []; $lanRc = 0;
            exec('sudo -n ' . escapeshellarg($lanCtlInfo['ovpnctl']) . ' lan-access-sync' . $lanArgs . ' 2>&1', $lanOut, $lanRc);
            if ($lanRc !== 0 || !in_array('LAN_ACCESS_OK', $lanOut, true)) {
                $lanFailed = ucfirst($lanInst) . ' server: ' . trim(implode(' ', array_slice($lanOut, -2)));
                break;
            }
        }
        if ($lanFailed !== '') {
            $_SESSION['ovpn_mgr_settings_error'] = 'VPN access list could not be applied (' . $lanFailed . '). If this is the first time, re-run scripts/setup-root.sh after the upgrade.';
        } else {
            $_SESSION['ovpn_mgr_notice'] = empty($lanOk)
                ? 'VPN access list cleared. Only the PBX\'s own LAN can reach the phones\' VPN addresses.'
                : 'VPN access list saved and applied: ' . implode(', ', $lanOk) . '.';
        }
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
// An error from a failed save is handed over via the session (Post/Redirect/Get)
// so the browser never ends up sitting on a POST response; reloading the page
// then doesn't trigger Firefox/Chrome's "resend form data?" prompt.
$settingsError = '';
if (!empty($_SESSION['ovpn_mgr_settings_error'])) {
    $settingsError = (string)$_SESSION['ovpn_mgr_settings_error'];
}
unset($_SESSION['ovpn_mgr_settings_error']);
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
    } elseif (($ovpnCrossError = ovpnCrossInstanceConflict($newPort, calculateSubnetDetails($newHostIp, cidrToNetmask($newCidr))['net_ip'], cidrToNetmask($newCidr), $otherInstanceConf)) !== '') {
        $settingsError = $ovpnCrossError;
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

        // "Save Settings" never touches the running daemon. Changing the
        // server host/FQDN only affects packages built from now on and needs
        // no restart at all. A port / VPN subnet change is saved to the
        // config, but its firewall, NAT and SIP-localnet sync is deferred
        // (the running daemon still uses the old values and the old port must
        // stay open) until "Save & Restart Daemon" (restart_daemon=1). What is
        // waiting is remembered in .pending_apply so that restart applies it.
        $wantRestart = !empty($_POST['restart_daemon']);
        $pendFile = ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.pending_apply');
        $pend = is_file($pendFile) ? (array)json_decode((string)@file_get_contents($pendFile), true) : [];
        if ($wantRestart) {
            $portChanged   = $portChanged   || !empty($pend['port']);
            $subnetChanged = $subnetChanged || !empty($pend['subnet']);
        }
        $deferApply = !$wantRestart && ($portChanged || $subnetChanged);

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
            if ($deferApply) {
                @file_put_contents($pendFile, json_encode([
                    'port'   => !empty($pend['port'])   || $portChanged,
                    'subnet' => !empty($pend['subnet']) || $subnetChanged,
                ]));
                $portChanged = false;
                $subnetChanged = false;
            } elseif ($wantRestart) {
                @unlink($pendFile);
            }
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
            // Only the running daemon's port/subnet actually require a restart
            // to apply - restarting drops every connected client (one shared
            // process), so a plain re-save that touches neither must not
            // bounce it. Mirrors the same fix already applied to edit_package.
            $daemonRestartNeeded = $wantRestart;

            $wasStopped = file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'));
            if ($daemonRestartNeeded && !$wasStopped) {
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

        // Without the FreePBX Firewall module, (re)apply the module's own
        // iptables rules from the live config on every save, not only when
        // the port/subnet changed. The values may already have been saved by
        // an earlier version that failed to create the rules, in which case
        // "changed" would never be true again.
        if (!$deferApply && !ovpnFreepbxFirewallAvailable($ovpnctl)) {
            $ensureOut = [];
            exec('sudo -n ' . escapeshellarg($ovpnctl) . ' fw-ensure 2>&1', $ensureOut, $ensureRc);
            @file_put_contents(
                $logFile,
                "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Standalone fw-ensure exit={$ensureRc}\n" . implode("\n", $ensureOut) . "\n",
                FILE_APPEND
            );
            if ($ensureRc !== 0 && empty($_SESSION['ovpn_mgr_fw_warning'])) {
                $_SESSION['ovpn_mgr_fw_warning'] = 'Could not create the iptables rules for the VPN port/subnet (exit ' . $ensureRc . '): ' . trim((string)end($ensureOut));
            }
        }

        if ($fwRestartNeeded) {
            // Single combined restart for both the custom-service and
            // trusted-zone changes above, instead of one restart per change.
            $restartOut = [];
            $restartRc  = 0;
            if (ovpnFreepbxFirewallAvailable($ovpnctl)) {
                ovpnRunFwconsoleFirewall($ovpnctl, ['fw-restart'], $restartOut, $restartRc);
            }
            @file_put_contents(
                $logFile,
                "\n[FIREWALL SYNC " . date('Y-m-d H:i:s') . "] Combined fwconsole firewall restart exit={$restartRc}\n"
                    . implode("\n", $restartOut) . "\n",
                FILE_APPEND
            );
            if ($restartRc !== 0 && empty($_SESSION['ovpn_mgr_fw_warning'])) {
                $_SESSION['ovpn_mgr_fw_warning'] = 'Firewall settings were updated, but fwconsole firewall restart returned a non-zero code (' . $restartRc . '). See the OpenVPN log for details.';
            }
        }

        if ($daemonRestartNeeded && !$wasStopped) {
            startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
        }

        $existingPkgCount = count(ovpnInstancePackages($pkgDir, $pkiDir, $serverConf));
        $addressChanged = ($oldIp !== $newIp) || ($oldPort !== $newPort);
        if ($hostIpWasCorrected || ($addressChanged && $existingPkgCount > 0)) {
            $_SESSION['ovpn_mgr_flash'] = [
                'host_ip_corrected' => $hostIpWasCorrected,
                'entered_host_ip'   => $newHostIp,
                'final_host_ip'     => $finalHostIp,
                'address_changed'   => $addressChanged,
                'pkg_count'         => $existingPkgCount,
                'instance'          => $ovpnInstance,
            ];
        }

        header("Location: config.php?display=ovpn_mgr");
        exit();
        } // end verified config save
    }

    // Validation / save failed: redirect back (PRG) and show the error there.
    $_SESSION['ovpn_mgr_settings_error'] = $settingsError;
    header("Location: config.php?display=ovpn_mgr");
    exit();
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
    $newExt = ovpnNormalizeExt($_POST['ext'] ?? '');
    $newMac = ovpnNormalizeMac($_POST['mac'] ?? '');
    $oldPath = "{$pkgDir}/{$oldPkg}";

    if (file_exists($oldPath) && ($newExt === '' || $newMac === '')) {
        $_SESSION['ovpn_mgr_settings_error'] = 'Extension and MAC / name must each contain at least one letter, digit or "-" (and the extension cannot be a reserved name such as "ca" or "server"). Nothing was changed.';
    }
    if (file_exists($oldPath) && $newExt !== '' && $newMac !== '') {
        $oldExt = '';
        $oldId = ovpnParsePackageName($oldPkg, true);
        if ($oldId !== null) {
            $oldExt = $oldId['ext'];
        }

        // The package's current server, and the server its (possibly new) cipher belongs to:
        // AES-GCM is served by the modern instance, AES-CBC by the legacy one.
        $fromInst = ovpnPackageInstance($oldPath, $baseDir);
        $selectedCipher = (string)($_POST['cipher'] ?? '');
        if (!in_array($selectedCipher, ovpnAllowedCiphers(), true)) {
            $selectedCipher = getDefaultCipher(ovpnConfPath($baseDir, $fromInst));
        }
        $toInst = ovpnInstanceForCipher($selectedCipher);
        // Only meaningful for GCM ciphers; confirms the phone's OpenVPN build
        // is 2.5+ and actually understands data-ciphers / data-ciphers-fallback.
        $includeDataCiphers = !empty($_POST['include_data_ciphers']);
        $fromCtx = ovpnInstanceCtx($baseDir, $moduleRoot, $fromInst);
        $toCtx   = ovpnInstanceCtx($baseDir, $moduleRoot, $toInst);

        if (!is_file($toCtx['serverConf']) || !is_dir($toCtx['pkiDir'])) {
            $_SESSION['ovpn_mgr_settings_error'] = 'The ' . ($toInst === 'modern' ? 'Modern' : 'Legacy') . ' OpenVPN server does not exist yet, so nothing was changed.';
        } elseif ($fromInst === $toInst) {
            ovpnSelectInstance($fromInst);

            // Snapshot before revokeExtension()/syncServerCiphers() so a restart
            // can be based on whether the server config actually changed, not
            // just on whether the cipher list did (revokeExtension() can also
            // wire in crl-verify the very first time it ever runs on this server).
            $confBeforeEdit = (string)@file_get_contents($serverConf);

            if (!empty($oldExt)) {
                revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $oldExt);
            }

            @unlink($oldPath);

            $settings = getActiveServerSettings($serverConf);

            // Keep the server's cipher lines in step with what is in use; AES-128-CBC
            // is only a fallback if it is the default or a package actually uses it.
            // Restart only if the server config actually changed - not
            // unconditionally on every edit (a restart drops every connected
            // client, not just this extension, since OpenVPN runs as one shared
            // process here).
            syncServerCiphers($serverConf, $pkgDir, [$selectedCipher]);
            buildClientPackage($pkiDir, $pkgDir, $baseDir, $newExt, $newMac, $settings['ip'], $settings['port'], $selectedCipher, false, $includeDataCiphers);

            $confChanged = ((string)@file_get_contents($serverConf) !== $confBeforeEdit);
            if ($confChanged && !file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'))) {
                stopOpenVpnServer($ovpnctl);
                startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
            }
        } else {
            // The new cipher belongs to the other server: build the package there first (a new
            // certificate from that server's CA), then revoke the extension on the old server.
            $fromConfBefore = (string)@file_get_contents($fromCtx['serverConf']);
            $toConfBefore   = (string)@file_get_contents($toCtx['serverConf']);
            $toSettings     = getActiveServerSettings($toCtx['serverConf']);
            $toLabel        = ($toInst === 'modern') ? 'Modern' : 'Legacy';
            $fromLabel      = ($fromInst === 'modern') ? 'Modern' : 'Legacy';

            $newPath = buildClientPackage($toCtx['pkiDir'], $pkgDir, $baseDir, $newExt, $newMac, $toSettings['ip'], $toSettings['port'], $selectedCipher, false, $includeDataCiphers);
            if (!$newPath) {
                $_SESSION['ovpn_mgr_settings_error'] = "Could not build the package on the {$toLabel} server, so nothing was changed.";
            } else {
                if (basename($newPath) !== $oldPkg) { @unlink($oldPath); }
                if (!empty($oldExt)) {
                    // Leaves the new package alone: it points at the other server's port.
                    revokeExtension($fromCtx['pkiDir'], $fromCtx['serverConf'], $fromCtx['crlFile'], $pkgDir, $oldExt);
                }
                syncServerCiphers($toCtx['serverConf'], $pkgDir, [$selectedCipher]);
                ovpnRestartIfConfChanged($fromInst, $fromConfBefore);
                ovpnRestartIfConfChanged($toInst, $toConfBefore);
                $_SESSION['ovpn_mgr_notice'] = "{$selectedCipher} is served by the {$toLabel} server, so this phone moved from the {$fromLabel} server to it. "
                    . "The certificate on the {$fromLabel} server is revoked: download the new package and give it to the phone.";
            }
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'generate_package') {
    csrf_require();

    // Extension and MAC accept anything usable as a name (a number, a label
    // like "MasterKey", or just "-"); see ovpnNormalizeExt / ovpnNormalizeMac.
    $ext = ovpnNormalizeExt($_POST['ext'] ?? '');
    $mac = ovpnNormalizeMac($_POST['mac'] ?? '');

    if ($ext === '' || $mac === '') {
        // Used to do nothing at all, silently.
        $_SESSION['ovpn_mgr_settings_error'] = 'Could not build the package: Extension and MAC / name must each contain at least one letter, digit or "-" (and the extension cannot be a reserved name such as "ca" or "server").';
    } else {
        // The cipher decides which server the phone connects to: AES-GCM -> the modern instance,
        // AES-CBC -> the legacy instance.
        $selectedCipher = (string)($_POST['cipher'] ?? '');
        if (!in_array($selectedCipher, ovpnAllowedCiphers(), true)) {
            $selectedCipher = getDefaultCipher(ovpnConfPath($baseDir, $ovpnModernExists ? 'modern' : 'legacy'));
        }
        $genInst = ovpnInstanceForCipher($selectedCipher);
        if ($genInst === 'modern' && !$ovpnModernExists) {
            $_SESSION['ovpn_mgr_settings_error'] = 'Could not build the package: ' . $selectedCipher . ' is served by the Modern server, which does not exist on this system.';
            header("Location: config.php?display=ovpn_mgr");
            exit();
        }
        ovpnSelectInstance($genInst);
        $settings = getActiveServerSettings($serverConf);
        // Only meaningful for GCM ciphers; confirms the phone's OpenVPN build
        // is 2.5+ and actually understands data-ciphers / data-ciphers-fallback.
        $includeDataCiphers = !empty($_POST['include_data_ciphers']);
        // "Set as default cipher" checkbox: remember this cipher as its server's default
        // (pre-selected next time, and what the legacy server falls back to).
        if (!empty($_POST['set_default_cipher'])) {
            setDefaultCipher($serverConf, $selectedCipher);
        }
        // AES-128-CBC is only added to the server's data-ciphers / fallback when it
        // is the default or a package uses it. Restart only if that changed.
        $cipherCfgChanged = syncServerCiphers($serverConf, $pkgDir, [$selectedCipher]);
        $builtPkg = buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $settings['ip'], $settings['port'], $selectedCipher, false, $includeDataCiphers);
        if (!$builtPkg) {
            $_SESSION['ovpn_mgr_settings_error'] = "The package for '{$mac}' / '{$ext}' could not be built. See the OpenVPN log and check the PKI.";
        }
        if ($cipherCfgChanged && !file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'))) {
            stopOpenVpnServer($ovpnctl);
            startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
        }
    }
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'rebuild_all_packages') {
    csrf_require();

    $settings = getActiveServerSettings($serverConf);
    $existingPkgs = ovpnInstancePackages($pkgDir, $pkiDir, $serverConf);
    $rebuilt = 0;

    // Restart only if the server config actually changed - revokeExtension()'s
    // CRL updates and syncServerCiphers()'s now-static cipher list don't
    // require one on their own; see the same pattern in
    // edit_package/revoke_cert/delete_package.
    $confBeforeRebuild = (string)@file_get_contents($serverConf);

    foreach ($existingPkgs as $pkgPath) {
        $filename = basename($pkgPath);
        $pid = ovpnParsePackageName($filename);
        if ($pid === null) {
            continue;
        }
        $mac = $pid['mac'];
        $ext = $pid['ext'];

        // Read the cipher (and data-ciphers opt-in) before revoking -
        // revokeExtension() deletes the package.
        $pkgCipher = getPackageCipher($pkgPath);
        $pkgIncludeDataCiphers = packageHasDataCiphers($pkgPath);
        revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $ext);
        @unlink($pkgPath);
        if (buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $settings['ip'], $settings['port'], $pkgCipher, false, $pkgIncludeDataCiphers)) {
            $rebuilt++;
        }
    }

    syncServerCiphers($serverConf, $pkgDir);

    $confChanged = ((string)@file_get_contents($serverConf) !== $confBeforeRebuild);
    if ($confChanged && !file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'))) {
        stopOpenVpnServer($ovpnctl);
        startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
    }

    unset($_SESSION['ovpn_mgr_flash']);
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'revoke_cert') {
    csrf_require();
    $revokeExt = ovpnNormalizeExt($_POST['revoke_ext'] ?? '');
    if ($revokeExt !== '') {
        // OpenVPN re-reads crl-verify's target file on every new connection
        // on its own - no restart needed for the revocation itself to take
        // effect. The only thing that ever needs a restart here is the
        // one-time addition of the crl-verify directive itself (the very
        // first revoke on a given server), so gate on whether the config
        // text actually changed, same as edit_package.
        $confBeforeRevoke = (string)@file_get_contents($serverConf);
        revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $revokeExt);
        $confChanged = ((string)@file_get_contents($serverConf) !== $confBeforeRevoke);
        if ($confChanged && !file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'))) {
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
        // Revoke on the server the package belongs to.
        ovpnSelectInstance(ovpnPackageInstance($fullPath, $baseDir));
        $revokeExt = '';
        $delId = ovpnParsePackageName($targetPkg, true);
        if ($delId !== null) {
            $revokeExt = $delId['ext'];
        } elseif (preg_match('/^keys_(\d+)_/i', $targetPkg, $m) || preg_match('/^(\d+)-/i', $targetPkg, $m)) {
            $revokeExt = $m[1];
        }

        @unlink($fullPath);

        if (!empty($revokeExt)) {
            // Same reasoning as revoke_cert: a restart is only ever needed for
            // the one-time addition of crl-verify, not for the revoke itself.
            $confBeforeRevoke = (string)@file_get_contents($serverConf);
            revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $revokeExt);
            $confChanged = ((string)@file_get_contents($serverConf) !== $confBeforeRevoke);
            if ($confChanged && !file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'))) {
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

// Selected package file names, validated and grouped by the OpenVPN instance each one belongs to
// (worked out before anything is revoked or rebuilt): ['modern' => [...], 'legacy' => [...]], empty
// groups left out.
function ovpnGroupPackagesByInstance($pkgDir, $baseDir, array $selected) {
    $groups = [];
    foreach ($selected as $name) {
        $valid = ovpnValidateSelectedPkg($pkgDir, $name);
        if ($valid === null) { continue; }
        $groups[ovpnPackageInstance("{$pkgDir}/{$valid}", $baseDir)][] = $valid;
    }
    return $groups;
}

// Restarts an instance's daemon, but only if its config text changed since $confBefore and the daemon is
// not stopped on purpose (a restart drops every client connected to that instance).
function ovpnRestartIfConfChanged($inst, $confBefore) {
    global $baseDir, $moduleRoot;
    $c = ovpnInstanceCtx($baseDir, $moduleRoot, $inst);
    if ((string)@file_get_contents($c['serverConf']) === (string)$confBefore) { return false; }
    if (file_exists(ovpnStateFile($baseDir, $inst, '.stopped'))) { return false; }
    stopOpenVpnServer($c['ovpnctl']);
    startOpenVpnServer($c['ovpnctl'], $c['serverConf'], $baseDir, $c['serverKey']);
    return true;
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

// Single-file .ovpn profile (CA, certificate and key inline) for each selected package, for OpenVPN
// Connect and similar apps. Built from the package's own files, so it carries the same server address,
// port and cipher. One package downloads as a .ovpn, several as one .tar of .ovpn files.
function ovpnBuildProfile($pkgPath, $legacy = false) {
    // Read the package in-process (PharData), the same way the Manage table reads vpn.cnf.
    $cnf = $ca = $crt = $key = '';
    try {
        $phar = new PharData($pkgPath);
        $get = function ($member) use ($phar) {
            return isset($phar[$member]) ? trim((string)$phar[$member]->getContent()) : '';
        };
        $cnf = $get('vpn.cnf');
        $ca  = $get('keys/ca.crt');
        $crt = $get('keys/client.crt');
        $key = $get('keys/client.key');
    } catch (Throwable $e) {
        return null;
    }
    if ($cnf === '' || $ca === '' || $crt === '' || $key === '') { return null; }
    $out = [];
    foreach (preg_split('/\r?\n/', $cnf) as $line) {
        $line = trim($line);
        // The key files are inline below; script-security is a phone-firmware leftover.
        if ($line === '' || preg_match('/^(ca|cert|key|script-security)\s/i', $line)) { continue; }
        $out[] = $line;
    }
    if ($legacy) {
        // The legacy server's certificates are RSA-1024 / SHA-1. Current OpenVPN clients (OpenVPN Connect, OpenSSL 3)
        // reject them ("ee key too small") unless the certificate profile is relaxed.
        $out[] = 'tls-cert-profile insecure';
    }
    return implode("\n", $out) . "\n<ca>\n{$ca}\n</ca>\n<cert>\n{$crt}\n</cert>\n<key>\n{$key}\n</key>\n";
}

if (isset($_POST['action']) && $_POST['action'] === 'bulk_download_ovpn') {
    csrf_require();
    $profiles = [];
    foreach ((array)($_POST['pkgs'] ?? []) as $name) {
        $valid = ovpnValidateSelectedPkg($pkgDir, $name);
        if ($valid === null) { continue; }
        $id = ovpnParsePackageName($valid, true);
        $text = ovpnBuildProfile("{$pkgDir}/{$valid}", ovpnPackageInstance("{$pkgDir}/{$valid}", $baseDir) === 'legacy');
        if ($id === null || $text === null) { continue; }
        $profiles[$id['ext'] . '_' . $id['mac'] . '.ovpn'] = $text;
    }
    if (empty($profiles)) {
        $_SESSION['ovpn_mgr_settings_error'] = 'No .ovpn file could be created: the selected packages have no readable key files.';
        header("Location: config.php?display=ovpn_mgr");
        exit();
    }
    while (ob_get_level() > 0) { ob_end_clean(); }
    if (count($profiles) === 1) {
        // One extension: the .ovpn profile itself (plain text), not an archive.
        $fname = (string)key($profiles);
        $body  = $profiles[$fname];
        header_remove('Content-Type');
        header('Content-Type: application/octet-stream');
        header('Content-Description: File Transfer');
        header('Content-Disposition: attachment; filename="' . $fname . '"; filename*=UTF-8\'\'' . rawurlencode($fname));
        header('Content-Length: ' . strlen($body));
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        echo $body;
        exit();
    }
    $tmp = sys_get_temp_dir() . '/ovpn_profiles_' . bin2hex(random_bytes(6));
    @mkdir($tmp, 0700, true);
    foreach ($profiles as $fname => $text) { @file_put_contents("{$tmp}/{$fname}", $text); @chmod("{$tmp}/{$fname}", 0600); }
    header('Content-Type: application/x-tar');
    header('Content-Description: File Transfer');
    header('Content-Disposition: attachment; filename="ovpn_profiles_' . date('Ymd_His') . '.tar"');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    flush();
    passthru('cd ' . escapeshellarg($tmp) . ' && tar -cf - ' . implode(' ', array_map('escapeshellarg', array_keys($profiles))));
    exec('rm -rf ' . escapeshellarg($tmp));
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'bulk_revoke_packages') {
    csrf_require();
    // Each package is revoked on the server it belongs to.
    $groups = ovpnGroupPackagesByInstance($pkgDir, $baseDir, (array)($_POST['pkgs'] ?? []));

    foreach ($groups as $grpInst => $grpNames) {
        ovpnSelectInstance($grpInst);

        // See revoke_cert: a restart is only ever needed for the one-time
        // addition of crl-verify, not for the revocation itself.
        $confBeforeRevoke = (string)@file_get_contents($serverConf);

        foreach ($grpNames as $valid) {
            $revokeExt = '';
            $bulkId = ovpnParsePackageName($valid, true);
            if ($bulkId !== null) {
                $revokeExt = $bulkId['ext'];
            } elseif (preg_match('/^keys_(\d+)_/i', $valid, $m) || preg_match('/^(\d+)-/i', $valid, $m)) {
                $revokeExt = $m[1];
            }

            @unlink("{$pkgDir}/{$valid}");

            if (!empty($revokeExt)) {
                revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $revokeExt);
            }
        }

        $confChanged = ((string)@file_get_contents($serverConf) !== $confBeforeRevoke);
        if ($confChanged && !file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'))) {
            stopOpenVpnServer($ovpnctl);
            startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
        }
    }

    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// Rebuild vpn.cnf only - keeps each phone's existing key/cert and cipher (no revoke).
// Selected packages are rebuilt against the server each one belongs to; "rebuild all" (offered after a
// server's address or port changed) covers one instance's packages.
if (isset($_POST['action']) && in_array($_POST['action'], ['bulk_rebuild_config_packages', 'rebuild_config_all'], true)) {
    csrf_require();
    $cfgGroups = [];

    if ($_POST['action'] === 'rebuild_config_all') {
        $cfgGroups[$ovpnInstance] = array_map('basename', array_filter(ovpnInstancePackages($pkgDir, $pkiDir, $serverConf), function ($t) { return substr($t, -9) === '_ovpn.tar'; }));
    } else {
        $cfgGroups = ovpnGroupPackagesByInstance($pkgDir, $baseDir, (array)($_POST['pkgs'] ?? []));
    }

    $cfgResult = ['rebuilt' => 0, 'skipped' => []];
    foreach ($cfgGroups as $grpInst => $names) {
        ovpnSelectInstance($grpInst);
        $settings = getActiveServerSettings($serverConf);
        $r = rebuildPackagesConfigOnly($pkiDir, $pkgDir, $baseDir, $settings['ip'], $settings['port'], $names);
        $cfgResult['rebuilt'] += $r['rebuilt'];
        $cfgResult['skipped']  = array_merge($cfgResult['skipped'], $r['skipped']);
    }

    $_SESSION['ovpn_mgr_cfg_rebuild'] = $cfgResult;
    header("Location: config.php?display=ovpn_mgr");
    exit();
}

if (isset($_POST['action']) && $_POST['action'] === 'bulk_revoke_rebuild_packages') {
    csrf_require();
    // Each package is revoked and rebuilt on the server it belongs to.
    $groups = ovpnGroupPackagesByInstance($pkgDir, $baseDir, (array)($_POST['pkgs'] ?? []));

    foreach ($groups as $grpInst => $grpNames) {
        ovpnSelectInstance($grpInst);
        $settings = getActiveServerSettings($serverConf);
        $rebuilt = 0;

        // See rebuild_all_packages: revoke/rebuild no longer implies a restart
        // is needed by itself, so gate on whether the config actually changed.
        $confBeforeRebuild = (string)@file_get_contents($serverConf);

        foreach ($grpNames as $valid) {
            $pid = ovpnParsePackageName($valid);
            if ($pid === null) {
                continue;
            }
            $mac = $pid['mac'];
            $ext = $pid['ext'];

            // Read the cipher (and data-ciphers opt-in) before revoking -
            // revokeExtension() deletes the package.
            $pkgCipher = getPackageCipher("{$pkgDir}/{$valid}");
            $pkgIncludeDataCiphers = packageHasDataCiphers("{$pkgDir}/{$valid}");
            revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $ext);
            @unlink("{$pkgDir}/{$valid}");
            if (buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $settings['ip'], $settings['port'], $pkgCipher, false, $pkgIncludeDataCiphers)) {
                $rebuilt++;
            }
        }

        if ($rebuilt > 0) {
            syncServerCiphers($serverConf, $pkgDir);
        }

        $confChanged = ((string)@file_get_contents($serverConf) !== $confBeforeRebuild);
        if ($confChanged && !file_exists(ovpnStateFile($baseDir, $GLOBALS['ovpnInstance'], '.stopped'))) {
            stopOpenVpnServer($ovpnctl);
            startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey);
        }
    }

    header("Location: config.php?display=ovpn_mgr");
    exit();
}

// Mass cipher change (Manage / Revoke Keys > Edit Selected with several packages selected).
// Every selected package gets the chosen cipher and keeps its extension, MAC and the address its
// phone already uses. The cipher decides the server: a package that is already on that server keeps
// its key and certificate (only vpn.cnf changes); one that is on the other server is built on the
// right one (new certificate from its CA) and its certificate on the old server is revoked.
if (isset($_POST['action']) && $_POST['action'] === 'bulk_change_cipher') {
    csrf_require();
    $newCipher = (string)($_POST['cipher'] ?? '');
    $includeDataCiphers = !empty($_POST['include_data_ciphers']);

    if (!in_array($newCipher, ovpnAllowedCiphers(), true)) {
        $_SESSION['ovpn_mgr_settings_error'] = 'Choose one of the listed ciphers. Nothing was changed.';
    } else {
        $toInst  = ovpnInstanceForCipher($newCipher);
        $toCtx   = ovpnInstanceCtx($baseDir, $moduleRoot, $toInst);
        $toLabel = ($toInst === 'modern') ? 'Modern' : 'Legacy';

        if (!is_file($toCtx['serverConf']) || !is_dir($toCtx['pkiDir'])) {
            $_SESSION['ovpn_mgr_settings_error'] = "The {$toLabel} OpenVPN server does not exist yet, so nothing was changed.";
        } else {
            $groups   = ovpnGroupPackagesByInstance($pkgDir, $baseDir, (array)($_POST['pkgs'] ?? []));
            $toSettings = getActiveServerSettings($toCtx['serverConf']);

            // Config text of every server before anything is touched, to restart only those that changed.
            $confBefore = [];
            foreach ($ovpnInstanceList as $li) {
                $confBefore[$li] = (string)@file_get_contents(ovpnConfPath($baseDir, $li));
            }

            $changed = 0; $moved = 0; $failed = [];
            foreach ($groups as $fromInst => $names) {
                $fromCtx = ovpnInstanceCtx($baseDir, $moduleRoot, $fromInst);
                foreach ($names as $valid) {
                    $pid = ovpnParsePackageName($valid);
                    if ($pid === null) { continue; }
                    $mac = $pid['mac'];
                    $ext = $pid['ext'];

                    // Keep the address the phone already uses (IP or hostname); only the port can differ.
                    $oldHost = getPackageRemote("{$pkgDir}/{$valid}");
                    $host    = ($oldHost !== '' && $oldHost !== null) ? $oldHost : $toSettings['ip'];

                    // The build replaces the package file (same MAC and extension). On the same server
                    // the existing certificate is reused; on the other server a new one is issued.
                    if (!buildClientPackage($toCtx['pkiDir'], $pkgDir, $baseDir, $ext, $mac, $host, $toSettings['port'], $newCipher, false, $includeDataCiphers)) {
                        $failed[] = $ext;
                        continue;
                    }
                    $changed++;
                    if ($fromInst !== $toInst) {
                        // Leaves the new package alone: it points at the other server's port.
                        revokeExtension($fromCtx['pkiDir'], $fromCtx['serverConf'], $fromCtx['crlFile'], $pkgDir, $ext);
                        $moved++;
                    }
                }
            }

            if ($changed > 0) {
                syncServerCiphers($toCtx['serverConf'], $pkgDir, [$newCipher]);
            }
            foreach ($ovpnInstanceList as $li) {
                ovpnRestartIfConfChanged($li, $confBefore[$li]);
            }

            if ($changed > 0) {
                $_SESSION['ovpn_mgr_notice'] = "Changed the cipher of {$changed} package(s) to {$newCipher} ({$toLabel} server). "
                    . ($moved > 0 ? "{$moved} of them moved over from the other server and their certificates there are revoked. " : '')
                    . 'Phones need to download the updated package.';
            }
            if (!empty($failed)) {
                $_SESSION['ovpn_mgr_settings_error'] = "Could not build the package on the {$toLabel} server for extension " . implode(', ', $failed)
                    . '. Nothing was changed or revoked for those.';
            }
        }
    }

    header("Location: config.php?display=ovpn_mgr");
    exit();
}

clearstatcache();

// ============================================================================
// State of every instance (the page shows both)
// ============================================================================
$ovpnIpForwardActive = (trim((string)@shell_exec('sysctl -n net.ipv4.ip_forward 2>/dev/null')) === '1');
$ip_forward_active   = $ovpnIpForwardActive;
$ovpnInst         = [];   // per instance: paths, settings, running state, ...
$ovpnSharedConflicts = [];  // packages used by more than one device, from the server logs
$connectedClients = [];   // both instances combined, each row tagged with its instance

foreach ($ovpnInstanceList as $li) {
    $c  = ovpnInstanceCtx($baseDir, $moduleRoot, $li);
    $st = getActiveServerSettings($c['serverConf']);
    $det = calculateSubnetDetails($st['host_ip'], $st['net_mask']);
    $c['settings']        = $st;
    $c['subnet']          = $det;
    $c['cidr']            = $det['cidr'];
    $c['clientIpCount']   = max(0, (pow(2, 32 - $det['cidr']) - 2) - 1);
    $c['defaultCipher']   = getDefaultCipher($c['serverConf']);
    $c['pendingApply']    = is_file(ovpnStateFile($baseDir, $li, '.pending_apply'));
    $c['label']           = ($li === 'modern') ? 'Modern' : 'Legacy';

    // Only errors from the most recent launch count: the log is append-only, so a
    // fatal error from an earlier failed attempt must not keep the banner on
    // STOPPED after a later start succeeded.
    $markerFile = "{$c['logDir']}/.line_break_pos";
    $markerPos  = file_exists($markerFile) ? (int)trim((string)@file_get_contents($markerFile)) : null;
    $logSinceStart = ovpnLogSinceLastStart(tailFileFromMarker($c['logFile'], $markerPos, 500));
    $hasTunError = (strpos($logSinceStart, 'Cannot ioctl TUNSETIFF') !== false || strpos($logSinceStart, 'Exiting due to fatal error') !== false);

    $pids = [];
    if (!file_exists(ovpnStateFile($baseDir, $li, '.stopped'))) {
        if (file_exists($c['pidFile'])) {
            $savedPid = intval(trim((string)@file_get_contents($c['pidFile'])));
            if ($savedPid > 0 && file_exists("/proc/{$savedPid}")) {
                $pids[] = $savedPid;
            } else {
                @unlink($c['pidFile']);
            }
        }
        if (empty($pids)) {
            $rawPids = [];
            exec("pgrep -f " . escapeshellarg($li === 'modern' ? 'modern-vpn' : 'legacy-vpn'), $rawPids);
            foreach ($rawPids as $rawPid) {
                $cleanPid = intval(trim($rawPid));
                if ($cleanPid > 0) {
                    $pids[] = $cleanPid;
                }
            }
        }
    }
    $c['pids']      = $pids;
    $c['isRunning'] = !empty($pids) && !$hasTunError;
    // A daemon only reads its config (incl. client-config-dir) when it starts.
    $c['restartReason'] = ($c['isRunning'] && !empty($pids))
        ? ovpnDaemonRestartReason($baseDir, $li, $c['serverConf'], $pids[0]) : '';

    // The sudo check costs a process spawn on every page load; a recent success is cached for a minute.
    // (The modern instance is driven through its own root shim, so the rule is checked per instance.)
    $accessKey = 'ovpn_mgr_access_ok_' . md5($c['ovpnctl']);
    if (!empty($_SESSION[$accessKey]) && $_SESSION[$accessKey] > time() - 60) {
        $c['sudo'] = true;
    } else {
        $c['sudo'] = hasOvpnctlAccess($c['ovpnctl']);
        if ($c['sudo']) { $_SESSION[$accessKey] = time(); }
    }

    // An older setup-root.sh wrote a unit whose ExecStart calls "ovpnctl start".
    // Until setup-root.sh is re-run, the GUI launches the daemon itself (inside
    // php-fpm's sandbox) instead of via systemd.
    $unitPath = '/etc/systemd/system/ovpn-mgr-openvpn' . ($li === 'modern' ? '-modern' : '') . '.service';
    $c['unitStale'] = is_readable($unitPath) && (strpos((string)@file_get_contents($unitPath), 'start-daemon') === false);

    // Whether crl-verify is already wired into this server's config. If it isn't yet, the NEXT
    // revoke of any kind (including one from an Edit Package save) is the one that adds it - a
    // genuine, if rare, restart-requiring change.
    $c['crlVerifyPresent'] = (strpos((string)@file_get_contents($c['serverConf']), 'crl-verify') !== false);

    // Read OpenVPN's own live status file (status-version 3, tab-separated -
    // see install.php / startOpenVpnServer()'s reconciliation) rather than
    // inferring "still connected" from CONNECT events in the daemon's
    // free-text activity log. The status file is rewritten by the daemon itself
    // in real time and only ever lists sessions that are actually live right now.
    //
    // One exception: OpenVPN never clears that file on exit, so after a Stop (or
    // a crash) it still holds the last snapshot of live sessions. Only trust it
    // while the daemon is actually running, otherwise a stopped server would keep
    // listing its last clients as "connected".
    if ($c['isRunning'] && file_exists($c['statusFile']) && is_readable($c['statusFile'])) {
        $statusData = (string)@file_get_contents($c['statusFile']);
        foreach (explode("\n", $statusData) as $line) {
            if (strpos($line, "CLIENT_LIST\t") !== 0) { continue; }
            $f = explode("\t", rtrim($line, "\r\n"));
            // CLIENT_LIST  CN  RealAddr  VirtAddr  VirtIPv6Addr  BytesRecv
            // BytesSent  ConnectedSince  ConnectedSinceEpoch  Username
            // ClientID  PeerID  DataChannelCipher
            if (count($f) < 13) { continue; }
            // The status file is only rewritten every few seconds, so a client that
            // was just revoked/killed lingers in it. A session whose certificate no
            // longer exists in the PKI (revoked) is not a live connection - hide it.
            if (preg_match('/^[A-Za-z0-9-]+$/', $f[1]) && !in_array(strtolower($f[1]), ovpnReservedNames(), true) && !file_exists("{$c['pkiDir']}/issued/{$f[1]}.crt")) { continue; }
            // RealAddr is "ip:port" (or "[ipv6]:port"); only the address is shown.
            $realIp = $f[2];
            if (preg_match('/^\[(.+)\]:\d+$/', $realIp, $mRealIp) || preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $realIp, $mRealIp)) {
                $realIp = $mRealIp[1];
            }
            $connectedClients[] = [
                'instance'      => $li,
                'mac'           => $f[1],
                'real_ip'       => $realIp,
                'virtual_ip'    => $f[3],
                'active_cipher' => $f[12] !== '' ? $f[12] : 'AES-128-CBC',
                'client_id'     => $f[10],
            ];
        }
    }

    // Packages that two or more devices are using (they keep taking the connection from each other).
    foreach (ovpnDetectSharedPackages(tailFileFromMarker($c['logFile'], null, 3000), 3600) as $sharedPkg) {
        $sharedPkg['server'] = $c['label'];
        $ovpnSharedConflicts[] = $sharedPkg;
    }

    $ovpnInst[$li] = $c;
}

// Upgrade auto-relock (path unit) added in 2.69; older setups lack it.
$ovpnWatchMissing = is_dir('/run/systemd/system') && !file_exists('/etc/systemd/system/ovpn-mgr-fixperms.path');
$ovpnAnyNoSudo    = false;
$ovpnAnyUnitStale = false;
$ovpnAllRunning   = true;
foreach ($ovpnInst as $c) {
    if (!$c['sudo'])      { $ovpnAnyNoSudo = true; }
    if ($c['unitStale'])  { $ovpnAnyUnitStale = true; }
    if (!$c['isRunning']) { $ovpnAllRunning = false; }
}
$hasSudoRule = !$ovpnAnyNoSudo;

// Every package, both instances together (each is shown against the server it belongs to).
$createdPackages = glob("{$pkgDir}/*.tar") ?: [];
$ovpnCbcInUse = []; // legacy (CBC) cipher => package count, for the mixed-cipher warning

// Every issued client certificate of both instances (the server's own certificate is not a client).
$issuedCerts = [];
foreach ($ovpnInstanceList as $li) {
    foreach (glob("{$ovpnInst[$li]['pkiDir']}/issued/*.crt") ?: [] as $crtPath) {
        if (in_array(strtolower(pathinfo($crtPath, PATHINFO_FILENAME)), ovpnReservedNames(), true)) { continue; }
        $issuedCerts[] = ['instance' => $li, 'path' => $crtPath];
    }
}
?>

<?php
// Descriptions in FreePBX Firewall for both instances' subnets and tun interfaces (cheap: at most
// every 30 seconds per session, and only fills in descriptions that are empty).
if (ovpnFirewallModuleUsable() && (($_SESSION['ovpn_fw_labels_ts'] ?? 0) < time() - 30)) {
    $_SESSION['ovpn_fw_labels_ts'] = time();
    foreach (['legacy', 'modern'] as $ovpnLabelInst) {
        if (is_file(ovpnConfPath($baseDir, $ovpnLabelInst))) {
            ovpnSyncFirewallLabels($baseDir, $ovpnLabelInst, "{$moduleRoot}/scripts");
        }
    }
}
?>

<div class="container-fluid">
    <h1>OpenVPN Manager</h1>
    <style>
    /* Modern / Legacy tabs, copied from the FreePBX tabs (Settings > Asterisk IAX Settings): 6px rounded tops, 1px #72a78b outline, 2px
       apart, sitting on a 1px #72a78b line. Inactive tabs are white; the open tab is a gradient from #d9e5df (top) to white (bottom)
       with no bottom edge, so it breaks the line. Text is bold #1b5a59. */
    .ovpn-set-tabs { display: flex; gap: 2px; margin: 0 0 14px; padding: 0 0 0 6px; border-bottom: 1px solid #72a78b; }
    .ovpn-set-tab { display: block; margin: 0; padding: 8px 20px; font-size: 14px; line-height: 15px; font-weight: bold; color: #1b5a59; background: #fff; border: 1px solid #72a78b; border-bottom: none; border-radius: 6px 6px 0 0; text-decoration: none; outline: none; }
    .ovpn-set-tab:hover, .ovpn-set-tab:focus { color: #1b5a59; background: #fff; text-decoration: none; }
    .ovpn-set-tab.active, .ovpn-set-tab.active:hover, .ovpn-set-tab.active:focus { background: linear-gradient(to bottom, #d9e5df 0%, #ffffff 100%); padding-bottom: 9px; margin-bottom: -1px; cursor: default; }
    .ovpn-set-panes { padding: 0; }
    /* Status area: the two servers stacked with Kernel IP Forwarding beside them, with tight row spacing; on a very narrow banner
       Kernel IP Forwarding goes under Legacy. */
    .ovpn-banner { container-type: inline-size; }
    .ovpn-status { display: grid; grid-template-columns: auto auto; grid-template-areas: "m k" "l k"; column-gap: 45px; row-gap: 0; align-items: center; }
    .ovpn-st-m { grid-area: m; } .ovpn-st-l { grid-area: l; } .ovpn-st-k { grid-area: k; }
    .ovpn-status .fa-check-circle, .ovpn-status .fa-times-circle { font-size: 18px !important; }
    .ovpn-status .ovpn-svc-icon { font-size: 20px; }
    @container (max-width: 520px)  { .ovpn-status { grid-template-columns: auto; grid-template-areas: "m" "l" "k"; } }
    @supports not (container-type: inline-size) {
        @media (max-width: 800px)  { .ovpn-status { grid-template-columns: auto; grid-template-areas: "m" "l" "k"; } }
    }
    .ovpn-foot-icon { padding: 4px 10px; font-size: 14px; }
    .ovpn-svc-icon { background: none; border: none; padding: 0; line-height: 1; font-size: 22px; cursor: pointer; vertical-align: middle; }
    .ovpn-svc-icon[disabled] { opacity: .4; cursor: default; }
    </style>
<div class="ovpn-panel-inner">
    <?php if (!empty($_SESSION['ovpn_mgr_notice'])): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars((string)$_SESSION['ovpn_mgr_notice'], ENT_QUOTES, 'UTF-8'); ?></div>
        <?php unset($_SESSION['ovpn_mgr_notice']); ?>
    <?php endif; ?>
    <?php if ($ovpnModernUnavailable): ?>
        <div class="alert alert-warning">The modern instance could not be created (is <code>openssl</code> available, and is <code>PhoneSettings</code> writable by the web user?). Only the legacy server is shown.</div>
    <?php endif; ?>

    <?php if (!empty($settingsError)): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($settingsError); ?></div>
    <?php endif; ?>

    <!-- Status Banner: both instances. Start / Stop / Restart are in the settings table below. -->
    <div class="alert ovpn-banner alert-<?php echo ($ovpnAllRunning && $ovpnIpForwardActive) ? 'success' : 'danger'; ?>" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px; padding: 7px 18px;">
        <div class="ovpn-status">
            <?php foreach ($ovpnInstanceList as $li): ?>
                <form method="post" action="config.php?display=ovpn_mgr" id="ovpnServiceForm-<?php echo $li; ?>" class="ovpn-service-form" style="display: none;">
                    <input type="hidden" name="action" value="manage_service">
                    <input type="hidden" name="instance" value="<?php echo $li; ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                </form>
            <?php endforeach; ?>
            <?php foreach ($ovpnInstanceList as $li): $c = $ovpnInst[$li]; $dis = !$c['sudo'] ? ' disabled' : ''; ?>
                    <div class="ovpn-st-<?php echo $li === 'modern' ? 'm' : 'l'; ?>" style="display: flex; align-items: center; gap: 8px; font-weight: bold; color: #333; font-size: 13px;">
                        <?php if ($c['isRunning']): ?>
                            <i class="fa fa-check-circle" style="color: #1e7b34; font-size: 20px;" title="RUNNING (PID: <?php echo htmlspecialchars(implode(', ', $c['pids'])); ?>)"></i>
                        <?php else: ?>
                            <i class="fa fa-times-circle" style="color: #c9302c; font-size: 20px;" title="STOPPED"></i>
                        <?php endif; ?>
                        <span style="min-width: 170px;"><?php echo htmlspecialchars($c['label']); ?> OpenVPN Server</span>
                        <?php if ($c['isRunning']): ?>
                            <button type="submit" form="ovpnServiceForm-<?php echo $li; ?>" name="service_cmd" value="stop" class="ovpn-svc-icon" style="color: #D60500;" title="Stop the <?php echo htmlspecialchars($c['label']); ?> server" aria-label="Stop the <?php echo htmlspecialchars($c['label']); ?> server" data-confirm-message="Stop the <?php echo htmlspecialchars($c['label']); ?> OpenVPN service? Its remote clients will disconnect."<?php echo $dis; ?>><i class="fa fa-stop-circle"></i></button>
                            <button type="submit" form="ovpnServiceForm-<?php echo $li; ?>" name="service_cmd" value="restart" class="ovpn-svc-icon" style="color: #c87f0a; margin-left: 6px;" title="Restart the <?php echo htmlspecialchars($c['label']); ?> server" aria-label="Restart the <?php echo htmlspecialchars($c['label']); ?> server" data-confirm-message="Restart the <?php echo htmlspecialchars($c['label']); ?> OpenVPN service? Its remote clients will disconnect and reconnect on their own."<?php echo $dis; ?>><i class="fa fa-refresh"></i></button>
                        <?php else: ?>
                            <button type="submit" form="ovpnServiceForm-<?php echo $li; ?>" name="service_cmd" value="start" class="ovpn-svc-icon" style="color: #1e7b34;" title="Start the <?php echo htmlspecialchars($c['label']); ?> server" aria-label="Start the <?php echo htmlspecialchars($c['label']); ?> server"<?php echo $dis; ?>><i class="fa fa-play-circle"></i></button>
                        <?php endif; ?>
                        <?php if ($c['isRunning'] && $c['restartReason'] !== ''): ?>
                            <span class="ovpn-restart-needed" style="color: #8a5a00; background: #fcf8e3; border: 1px solid #faebcc; border-radius: 3px; padding: 0 7px; font-weight: normal; margin-left: 8px; line-height: 18px;" title="<?php echo htmlspecialchars($c['restartReason'] . ' Restart it so phones get the current settings and routes.'); ?>"><i class="fa fa-exclamation-triangle"></i> Restart needed</span>
                        <?php endif; ?>
                    </div>
            <?php endforeach; ?>
            <div class="ovpn-st-k" style="display: flex; align-items: center; gap: 8px; font-weight: bold; color: #333; font-size: 13px;">
                <?php if ($ovpnIpForwardActive): ?>
                    <i class="fa fa-check-circle" style="color: #1e7b34; font-size: 20px;" title="ACTIVE"></i>
                <?php else: ?>
                    <i class="fa fa-times-circle" style="color: #c9302c; font-size: 20px;" title="INACTIVE"></i>
                <?php endif; ?>
                <span>Kernel IP Forwarding</span>
            </div>
        </div>

        <div style="display: flex; align-items: center; gap: 8px;">
            <button type="button" class="btn btn-info btn-sm" data-toggle="modal" data-target="#logModal">
                <i class="fa fa-file-text-o"></i> View Live Logs
            </button>
            <button type="button" class="btn btn-default btn-sm" data-toggle="modal" data-target="#lanAccessModal" title="Networks allowed to reach the phones' VPN addresses">
                <i class="fa fa-unlock-alt"></i> VPN Access
            </button>
            <?php $ovpnCockpit = ovpnCockpitInfo(); if ($ovpnCockpit['installed']): ?>
                <button type="button" class="btn btn-default btn-sm" id="ovpnCockpitBtn" data-port="<?php echo (int)$ovpnCockpit['port']; ?>" title="Open Cockpit in a new tab (port <?php echo (int)$ovpnCockpit['port']; ?>)" aria-label="Open Cockpit" onclick="openCockpit(this)">
                    <svg width="15" height="15" viewBox="0 0 24 24" aria-hidden="true" style="vertical-align: -3px; margin-right: 3px;"><circle cx="12" cy="12" r="10.8" fill="none" stroke="#0066cc" stroke-width="1.8"/><path fill="#0066cc" transform="translate(12 12) rotate(45) scale(0.58) translate(-12 -12)" d="M21 16v-2l-8-5V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/></svg>
                    Cockpit
                </button>
            <?php endif; ?>
            <?php if ($show_ovpn_resign_button): ?>
                <button type="button" class="btn btn-danger btn-sm" style="margin: 0; font-weight: bold; background-color: #db001a; border-color: #6b000d;" data-toggle="modal" data-target="#signModal">
                    <i class="fa fa-key"></i> Sign Module
                </button>
            <?php endif; ?>
        </div>
    </div>

    <?php foreach ($ovpnSharedConflicts as $sharedPkg): ?>
        <div class="alert alert-warning" role="alert" style="font-size: 12px; padding: 8px 14px;">
            <i class="fa fa-exclamation-triangle"></i>
            <strong>The package for &ldquo;<?php echo htmlspecialchars($sharedPkg['cn']); ?>&rdquo; is in use on <?php echo count($sharedPkg['devices']); ?> different devices (<?php echo htmlspecialchars($sharedPkg['server']); ?> server).</strong>
            A package allows only one connection at a time, so these devices keep disconnecting each other (<?php echo (int)$sharedPkg['switches']; ?> switches in the last hour, the latest at <?php echo htmlspecialchars(date('H:i:s', $sharedPkg['last'])); ?>):
            <?php
            $sharedList = [];
            foreach ($sharedPkg['devices'] as $dev) {
                $sharedList[] = '<code>' . htmlspecialchars($dev['ip']) . '</code>' . ($dev['label'] !== '' ? ' (' . htmlspecialchars($dev['label']) . ')' : '') . ' last connected ' . htmlspecialchars(date('H:i:s', $dev['last']));
            }
            echo implode('; ', $sharedList);
            ?>.
            Build a separate package for each device (Build Provisioning Package), each with its own name.
        </div>
    <?php endforeach; ?>

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

    <?php if ($hasSudoRule && $ovpnWatchMissing): ?>
        <div class="alert alert-warning" style="margin-bottom: 20px;">
            <i class="fa fa-exclamation-triangle"></i> Re-run the root setup once so future module upgrades re-secure the root helper automatically (otherwise this page asks for setup again after every upgrade):
            <pre id="setupCmdWatch" title="Click to copy" style="background:#f8f9fa; padding:10px; border:1px solid #ccc; font-size:12px; margin:8px 0 0; cursor:pointer;" onclick="copySetupCommand('setupCmdWatch')">sudo bash <?php echo htmlspecialchars($setupScript); ?></pre>
        </div>
    <?php endif; ?>

    <?php if ($hasSudoRule && $ovpnAnyUnitStale): ?>
        <div class="alert alert-warning" style="margin-bottom: 20px;">
            <i class="fa fa-exclamation-triangle"></i> The OpenVPN systemd unit is out of date. Re-run the root setup so Start/Stop launch the daemon through systemd instead of from inside the web server (this avoids start failures such as a missing <code>/dev/net/tun</code> when php-fpm is sandboxed, and keeps the VPN up when php-fpm restarts):
            <pre id="setupCmdStale" title="Click to copy" style="background:#f8f9fa; padding:10px; border:1px solid #ccc; font-size:12px; margin:8px 0 0; cursor:pointer;" onclick="copySetupCommand('setupCmdStale')">sudo bash <?php echo htmlspecialchars($setupScript); ?></pre>
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
    $ovpnCrlWarning = $_SESSION['ovpn_mgr_crl_warning'] ?? null;
    unset($_SESSION['ovpn_mgr_crl_warning']);
    ?>
    <?php if ($ovpnCrlWarning): ?>
        <div class="alert alert-danger" style="margin-bottom: 20px;">
            <i class="fa fa-exclamation-triangle"></i> <strong>Certificate revocation list error:</strong> <?php echo nl2br(htmlspecialchars($ovpnCrlWarning)); ?>
            <br>This is almost certainly why the "first-time revocation" prompt keeps reappearing - the CRL file is failing to (re)generate, so crl-verify can't stay in the config.
        </div>
    <?php endif; ?>

    <?php
    $ovpnCfgRebuild = $_SESSION['ovpn_mgr_cfg_rebuild'] ?? null;
    unset($_SESSION['ovpn_mgr_cfg_rebuild']);
    ?>
    <?php if (is_array($ovpnCfgRebuild)): ?>
        <div class="alert <?php echo empty($ovpnCfgRebuild['skipped']) ? 'alert-success' : 'alert-warning'; ?>" style="margin-bottom: 20px;">
            <i class="fa fa-check-circle"></i>
            Rebuilt the config for <?php echo intval($ovpnCfgRebuild['rebuilt']); ?> package(s); existing keys and ciphers were kept. Phones need to download the updated package.
            <?php if (!empty($ovpnCfgRebuild['skipped'])): ?>
                <br><i class="fa fa-exclamation-triangle"></i>
                Skipped <?php echo count($ovpnCfgRebuild['skipped']); ?> package(s) whose key/certificate is no longer in the PKI (use Revoke &amp; Rebuild for those):
                <?php echo htmlspecialchars(implode(', ', $ovpnCfgRebuild['skipped'])); ?>
            <?php endif; ?>
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
                    The <?php echo (($ovpnFlash['instance'] ?? '') === 'modern') ? 'Modern' : 'Legacy'; ?> server address/port changed. <?php echo intval($ovpnFlash['pkg_count']); ?> existing client package(s) on it still point at the old address.
                </p>
                <form method="post" action="config.php?display=ovpn_mgr" style="display:inline;">
                    <input type="hidden" name="action" value="rebuild_config_all">
                    <input type="hidden" name="instance" value="<?php echo htmlspecialchars((string)($ovpnFlash['instance'] ?? 'legacy'), ENT_QUOTES); ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <button type="submit" class="btn btn-default btn-sm" data-confirm-message="Rebuild the config of ALL <?php echo intval($ovpnFlash['pkg_count']); ?> existing client package(s) on the <?php echo (($ovpnFlash['instance'] ?? '') === 'modern') ? 'Modern' : 'Legacy'; ?> server, keeping their keys?">
                        <i class="fa fa-file-text-o"></i> Rebuild Config, Keep Keys (<?php echo intval($ovpnFlash['pkg_count']); ?>)
                    </button>
                </form>
                <form method="post" action="config.php?display=ovpn_mgr" style="display:inline;">
                    <input type="hidden" name="action" value="rebuild_all_packages">
                    <input type="hidden" name="instance" value="<?php echo htmlspecialchars((string)($ovpnFlash['instance'] ?? 'legacy'), ENT_QUOTES); ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <button type="submit" class="btn btn-warning btn-sm" data-confirm-message="Revoke and rebuild ALL <?php echo intval($ovpnFlash['pkg_count']); ?> existing client package(s) on the <?php echo (($ovpnFlash['instance'] ?? '') === 'modern') ? 'Modern' : 'Legacy'; ?> server?">
                        <i class="fa fa-refresh"></i> Revoke & Rebuild All (<?php echo intval($ovpnFlash['pkg_count']); ?>)
                    </button>
                </form>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <div class="row">
        <div class="col-md-6">
            <!-- OpenVPN Server Settings: the Modern / Legacy tabs in the heading switch which server's settings are shown -->
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title"><i class="fa fa-cogs"></i> OpenVPN Server Settings</h3></div>
                <div class="panel-body">
                <div class="ovpn-set-tabs" id="ovpnSetTabs" role="tablist">
                    <?php foreach ($ovpnInstanceList as $li): ?>
                        <a href="#" role="tab" aria-selected="<?php echo $li === $ovpnInstanceList[0] ? 'true' : 'false'; ?>" class="ovpn-set-tab<?php echo $li === $ovpnInstanceList[0] ? ' active' : ''; ?>" data-instance="<?php echo $li; ?>" title="<?php echo $li === 'modern' ? 'RSA-2048 / SHA-256 certificates, AES-GCM, TLS 1.2 or newer (for example Yealink T48S, OpenVPN Connect).' : 'RSA-1024 / SHA-1 certificates and AES-CBC, for phones with very old OpenVPN firmware (for example Yealink T28P).'; ?>"><?php echo htmlspecialchars($ovpnInst[$li]['label']); ?></a>
                    <?php endforeach; ?>
                </div>
                <div class="ovpn-set-panes">
                <?php foreach ($ovpnInstanceList as $li): $c = $ovpnInst[$li]; $serverHostIsIp = (bool) filter_var($c['settings']['ip'], FILTER_VALIDATE_IP); ?>
                    <div class="ovpn-set-pane" data-instance="<?php echo $li; ?>"<?php echo $li === $ovpnInstanceList[0] ? '' : ' style="display: none;"'; ?>>
                    <form method="post" action="config.php?display=ovpn_mgr" id="ovpnSettingsForm-<?php echo $li; ?>" class="ovpn-settings-form" data-instance="<?php echo $li; ?>">
                        <input type="hidden" name="action" value="update_server_settings">
                        <input type="hidden" name="instance" value="<?php echo $li; ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                        <input type="hidden" name="restart_daemon" id="restart_daemon-<?php echo $li; ?>" value="0">

                        <div style="display: flex; align-items: flex-end; gap: 5px; margin-bottom: 15px; flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="server_ip-<?php echo $li; ?>" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 5px;">Server Public IP / Host</label>
                                <input type="text" class="form-control" id="server_ip-<?php echo $li; ?>" name="server_ip" value="<?php echo htmlspecialchars($c['settings']['ip']); ?>" required style="width: 242px; height: 34px; padding-left: 2px">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; visibility: hidden; display: block; margin-bottom: 5px;">Action</label>
                                <button type="button" class="btn btn-default btn-sm" onclick="setPrivateIp('<?php echo $li; ?>')" title="Private IP"  style="width: 34px; height: 34px; padding: 4px 6px; font-size: 13px;">
                                    <i class="fa fa-sitemap"></i> 
                                </button>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; visibility: hidden; display: block; margin-bottom: 5px;">Action</label>
                                <button type="button" class="btn btn-default btn-sm" onclick="fetchPublicIp('<?php echo $li; ?>')" title="Public IP" style="width: 34px; height: 34px; padding: 4px 6px; font-size: 13px;">
                                    <i class="fa fa-globe"></i> 
                                </button>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="ovpn_port-<?php echo $li; ?>" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 3px;">Port</label>
                                <input type="number" class="form-control" id="ovpn_port-<?php echo $li; ?>" name="ovpn_port" value="<?php echo htmlspecialchars($c['settings']['port']); ?>" required style="width: 75px; height: 34px; padding: 6px 4px;">
                            </div>
                        </div>

                        <div id="fqdnNotice-<?php echo $li; ?>" class="alert alert-warning" style="font-size: 12px; padding: 8px 10px; margin-bottom: 15px;<?php echo $serverHostIsIp ? ' display: none;' : ''; ?>">
                            <i class="fa fa-exclamation-triangle"></i>
                            <strong>Hostname entered.</strong> Some Yealink phones get stuck on &ldquo;obtaining IP address&rdquo; when <code>vpn.cnf</code> uses a hostname instead of an IP address, apparently because the phone tries to resolve the name before its DHCP lease is complete. If a phone hangs, use the server&rsquo;s IP address here instead, or set that phone to a static IP rather than DHCP.
                        </div>

                        <div style="display: flex; align-items: flex-end; gap: 10px; margin-bottom: 6px; flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="ovpn_host_ip-<?php echo $li; ?>" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 3px;">VPN Host IP</label>
                                <input type="text" class="form-control" id="ovpn_host_ip-<?php echo $li; ?>" name="ovpn_host_ip" value="<?php echo htmlspecialchars($c['settings']['host_ip']); ?>" required style="width: 130px; height: 34px;" oninput="recalculateRange('<?php echo $li; ?>')">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="ovpn_cidr-<?php echo $li; ?>" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 11px;">CIDR</label>
                                <div style="display: flex; align-items: center;">
                                    <span style="padding: 6px 4px 6px 0; font-size: 14px; color: #666;">/</span>
                                    <input type="number" class="form-control" id="ovpn_cidr-<?php echo $li; ?>" name="ovpn_cidr" value="<?php echo htmlspecialchars($c['cidr']); ?>" min="16" max="29" required style="width: 65px; height: 34px; padding: 6px 4px; padding-left: 5px;" oninput="recalculateRange('<?php echo $li; ?>')">
                                </div>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 4px;">Calculated IP Range</label>
                                <div class="well well-sm" style="margin-bottom: 0; padding: 6px 10px; height: 34px; font-size: 11px; font-family: monospace; font-weight: bold; background: #f8f9fa; border-color: #ccc; white-space: nowrap;">
                                    <span id="range_start-<?php echo $li; ?>"><?php echo htmlspecialchars($c['subnet']['range_start']); ?></span> - <span id="range_end-<?php echo $li; ?>"><?php echo htmlspecialchars($c['subnet']['range_end']); ?></span>
                                </div>
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 3px;">Client IPs</label>
                                <div class="well well-sm" style="margin-bottom: 0; padding: 6px 10px; height: 34px; font-size: 11px; font-family: monospace; font-weight: bold; background: #f8f9fa; border-color: #ccc; white-space: nowrap; text-align: center;">
                                    <span id="client_ip_count-<?php echo $li; ?>"><?php echo (int)$c['clientIpCount']; ?></span>
                                </div>
                            </div>
                        </div>

                        <div id="host_ip_live_notice-<?php echo $li; ?>" style="display: none; margin-bottom: 10px; font-size: 11px; padding: 6px 10px; border-radius: 4px;"></div>

                        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                            <button type="submit" class="btn btn-primary" id="ovpnSaveBtn-<?php echo $li; ?>" style="width: 170px;">
                                <i class="fa fa-save"></i> Save Settings
                            </button>
                            <button type="button" class="btn btn-warning ovpn-save-restart-btn" id="ovpnSaveRestartBtn-<?php echo $li; ?>" data-instance="<?php echo $li; ?>" data-pending="<?php echo $c['pendingApply'] ? '1' : '0'; ?>" style="display: none; padding-left: 20px; padding-right: 20px;">
                                <i class="fa fa-refresh"></i> Save &amp; Restart Daemon
                            </button>
                        </div>
                        <div id="ovpnRestartHint-<?php echo $li; ?>" class="help-block" style="display: none; font-size: 11px; margin: 6px 0 0;"></div>
                    </form>
                    </div>
                <?php endforeach; ?>
                </div>
                </div>
            </div>

            <!-- Build Provisioning Package Panel -->
            <div class="panel panel-default">
                <div class="panel-heading" style="display: flex; align-items: center; padding: 10px 15px;">
                    <h3 class="panel-title" style="margin: 0;"><i class="fa fa-cube"></i> Build Provisioning Package (vpn.tar)</h3>
                </div>
                <div class="panel-body">
                    <form method="post" action="config.php?display=ovpn_mgr" id="ovpnGenerateForm">
                        <input type="hidden" name="action" value="generate_package">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                        
                        <div style="display: flex; align-items: flex-end; gap: 10px; margin-bottom: 10px; flex-wrap: wrap;">
                            <!-- Extension Input with Icon Overlay -->
                            <div class="form-group" style="margin-bottom: 0;">
                                <label style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 5px;">Extension</label>
                                <div class="select-input-container">
                                    <input type="text" name="ext" list="ext_list" class="form-control" placeholder="Select or type..." title="An extension number, or any name (letters, digits and - only), e.g. - for a master key" required autocomplete="off" style="width: 130px; height: 34px;">
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
                                    <input type="text" name="mac" list="mac_list" class="form-control" placeholder="Select or type..." title="A phone MAC address, or any name (letters, digits and - only), e.g. MasterKey" required autocomplete="off" style="width: 165px; height: 34px;">
                                </div>
                                <datalist id="mac_list">
                                    <?php foreach ($available_macs as $m_raw => $m_label): ?>
                                        <option value="<?php echo htmlspecialchars($m_raw); ?>"><?php echo htmlspecialchars($m_label); ?></option>
                                    <?php endforeach; ?>
                                </datalist>
                            </div>

                            <!-- Cipher selector. The cipher decides which server the package connects to:
                                 AES-GCM -> the modern server, AES-CBC -> the legacy server. -->
                            <?php
                            $ovpnDefaultModern = isset($ovpnInst['modern']) ? $ovpnInst['modern']['defaultCipher'] : '';
                            $ovpnDefaultLegacy = $ovpnInst['legacy']['defaultCipher'];
                            $ovpnPreselectCipher = isset($ovpnInst['modern']) ? $ovpnDefaultModern : $ovpnDefaultLegacy;
                            ?>
                            <div class="form-group" style="margin-bottom: 0; min-width: 0;">
                                <label for="ovpn_cipher" style="font-size: 11px; display: block; margin-bottom: 5px; padding-left: 5px;">Cipher</label>
                                <div style="display: flex; align-items: center; gap: 10px;">
                                    <select id="ovpn_cipher" name="cipher" class="form-control" style="height: 34px; width: 190px; max-width: 100%;" data-default-modern="<?php echo htmlspecialchars($ovpnDefaultModern); ?>" data-default-legacy="<?php echo htmlspecialchars($ovpnDefaultLegacy); ?>">
                                        <?php if ($ovpnModernExists): ?>
                                        <option value="AES-256-GCM"<?php echo $ovpnPreselectCipher === 'AES-256-GCM' ? ' selected' : ''; ?>>AES-256-GCM - Modern</option>
                                        <option value="AES-128-GCM"<?php echo $ovpnPreselectCipher === 'AES-128-GCM' ? ' selected' : ''; ?>>AES-128-GCM - Modern</option>
                                        <?php endif; ?>
                                        <option value="AES-256-CBC"<?php echo $ovpnPreselectCipher === 'AES-256-CBC' ? ' selected' : ''; ?>>AES-256-CBC - Legacy</option>
                                        <option value="AES-128-CBC"<?php echo $ovpnPreselectCipher === 'AES-128-CBC' ? ' selected' : ''; ?>>AES-128-CBC - Legacy</option>
                                    </select>
                                    <label for="ovpn_cipher_default" style="font-size: 11px; font-weight: normal; margin: 0; white-space: nowrap; cursor: pointer;" title="Pre-selects this cipher for new packages. For a legacy cipher it also becomes the legacy server's fallback cipher; AES-128-CBC is only a fallback when it is the default or a phone is using it.">
                                        <input type="checkbox" id="ovpn_cipher_default" name="set_default_cipher" value="1" style="margin: 0 4px 0 0; vertical-align: middle;">
                                        <span id="ovpn_cipher_default_text">Default</span>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div id="ovpn_cipher_notice" role="status" aria-live="polite" style="margin: 0 0 10px; padding: 7px 10px; border: 1px solid #faebcc; border-radius: 4px; background: #fcf8e3; color: #8a6d3b; font-size: 11px; line-height: 1.5;">
                            <strong>&#9888;&nbsp; Legacy compatibility:</strong> Uses AES-128-CBC and SHA1. Intended for older phones that cannot use modern OpenVPN data ciphers.
                        </div>

                        <div id="ovpn_data_ciphers_row" style="display: none; margin: 0 0 10px;">
                            <label style="font-size: 11px; font-weight: normal; margin: 0; cursor: pointer;" title="Adds data-ciphers / data-ciphers-fallback to vpn.cnf so the client negotiates this cipher via NCP. Only understood by OpenVPN 2.5+ clients - on 2.4.x (including some phones' embedded builds, even ones that otherwise connect fine with a GCM cipher) this keyword fails to parse and the client won't start at all. Leave unchecked unless you've confirmed the client's OpenVPN version.">
                                <input type="checkbox" id="ovpn_include_data_ciphers" name="include_data_ciphers" value="1" style="margin: 0 4px 0 0; vertical-align: middle;">
                                Include data-ciphers (requires OpenVPN 2.5+ client &mdash; confirm before enabling)
                            </label>
                        </div>

                        <div class="well well-sm" style="font-size: 11px; margin-bottom: 10px; padding: 5px; color: #555; max-width: 375px;">
                            Package will target the <strong id="ovpn_target_label"></strong> OpenVPN server <strong id="ovpn_target_hostport"></strong> and SIP Gateway <strong id="ovpn_target_sip"></strong>
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
                    <table id="ovpnClientsTable" class="table table-striped table-bordered ovpn-sortable-table" style="margin-bottom: 0; font-size: 12px;">
                        <thead>
                            <tr><th class="ovpn-sortable" data-col="0" data-type="nat" tabindex="0" title="Sort by extension / MAC">Extension / MAC <span class="ovpn-sort-ind"></span></th><th class="ovpn-sortable" data-col="1" data-type="ip" tabindex="0" title="Sort by virtual IP">Virtual IP (TUN) <span class="ovpn-sort-ind"></span></th><th class="ovpn-sortable" data-col="2" data-type="ip" tabindex="0" title="Sort by real IP">Real IP <span class="ovpn-sort-ind"></span></th><th class="ovpn-sortable" data-col="3" data-type="text" tabindex="0" title="Sort by cipher">Active Cipher <span class="ovpn-sort-ind"></span></th></tr>
                        </thead>
                        <tbody>
                            <?php if (empty($connectedClients)): ?>
                                <tr><td colspan="4" class="text-muted" style="padding: 12px; text-align: center;">No active client tunnels currently connected.</td></tr>
                            <?php else: foreach ($connectedClients as $client): ?>
                                <tr>
                                    <td style="vertical-align: middle !important;"><code><?php echo htmlspecialchars($client['mac']); ?></code></td>
                                    <td style="vertical-align: middle !important;"><code><?php echo htmlspecialchars($client['virtual_ip']); ?></code></td>
                                    <td style="vertical-align: middle !important;"><?php echo htmlspecialchars($client['real_ip']); ?></td>
                                    <td style="padding-left: 10px; " data-sv="<?php echo htmlspecialchars($client['active_cipher'], ENT_QUOTES); ?>">
                                        <span class="label <?php echo $client['instance'] === 'modern' ? 'label-success' : 'label-warning'; ?>" title="Connected to the <?php echo $client['instance'] === 'modern' ? 'Modern' : 'Legacy'; ?> server"><?php echo htmlspecialchars($client['active_cipher']); ?></span>
                                        <form method="post" action="config.php?display=ovpn_mgr" style="display:inline;">
                                            <input type="hidden" name="action" value="kill_client">
                                            <input type="hidden" name="instance" value="<?php echo htmlspecialchars($client['instance'], ENT_QUOTES); ?>">
                                            <input type="hidden" name="client_id" value="<?php echo htmlspecialchars($client['client_id'], ENT_QUOTES); ?>">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                                            <button type="submit" title="Kill connection to Ext. <?php echo htmlspecialchars($client['mac'], ENT_QUOTES); ?>" data-confirm-message="Disconnect extension <?php echo htmlspecialchars($client['mac'], ENT_QUOTES); ?> at <?php echo htmlspecialchars($client['virtual_ip'], ENT_QUOTES); ?>? The phone will reconnect on its own if it's still online." <?php echo empty($ovpnInst[$client['instance']]['sudo']) ? 'disabled' : ''; ?> style="background: none; border: none; padding: 0; margin-left: 20px; color: #D60500; cursor: pointer; font-size: 22px; vertical-align: middle; line-height: 1;">
                                                <i class="fa fa-times-circle"></i>
                                            </button>
                                        </form>
                                    </td>
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
                        <i class="fa fa-key"></i> Manage / Revoke Keys (<?php echo count($issuedCerts); ?>)
                    </button>
                </div>
                <div class="panel-body" style="padding: 0; max-height: 490px; overflow-y: auto;">
                    <?php if (empty($createdPackages)): ?>
                        <div style="padding: 20px; text-align: center;" class="text-muted">No provisioning packages have been generated yet.</div>
                    <?php else: ?>
                        <table id="ovpnPkgTable" class="table table-striped table-bordered" style="margin-bottom: 0; table-layout: fixed; width: 100%;">
                            <colgroup>
                                <col style="width: 105px;">
                                <col style="width: 130px;">
                                <col style="width: 110px;">
                                <col style="width: auto;">
                                <col style="width: 170px;">
                            </colgroup>

                            <thead>
                                <tr>
                                    <th class="ovpn-sortable" data-sort="ext" tabindex="0" title="Sort by extension" style="text-align: left; padding-left: 10px;">Extension <span class="ovpn-sort-ind"></span></th>
                                    <th class="ovpn-sortable" data-sort="mac" tabindex="0" title="Sort by MAC address" style="text-align: left; padding-left: 15px;">MAC <span class="ovpn-sort-ind"></span></th>
                                    <th class="ovpn-sortable" data-sort="cipher" tabindex="0" title="Sort by cipher" style="text-align: center;">Cipher <span class="ovpn-sort-ind"></span></th>
                                    <th class="ovpn-sortable date-column" style="width: auto; text-align: center;  white-space: normal; overflow: hidden;" data-sort="date" tabindex="0" title="Sort by date created">Date Created <span class="ovpn-sort-ind"></span></th>
                                    <th style="width: 155px; text-align: center;">Actions</th>
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
    // The name as written in the file name (not upper-cased), for the Edit dialog.
    $pkgMacRaw = !empty($parts[0]) ? (preg_match('/^[0-9a-f]{12}$/i', $parts[0]) ? strtoupper($parts[0]) : $parts[0]) : '';

    // Read the archive's current cipher (and data-ciphers opt-in) so Edit
    // opens with its existing values; and the server it connects to.
    $pkgCipher = getPackageCipher($pkgPath);
    $pkgHasDataCiphers = packageHasDataCiphers($pkgPath);
    $pkgInstance = ovpnPackageInstance($pkgPath, $baseDir);
    $pkgServerLabel = ($pkgInstance === 'modern') ? 'Modern' : 'Legacy';
    if (ovpnIsCbcCipher($pkgCipher)) { $ovpnCbcInUse[$pkgCipher] = ($ovpnCbcInUse[$pkgCipher] ?? 0) + 1; }
    $pkgMtime = (int)filemtime($pkgPath);
?>
    <tr data-ext="<?php echo htmlspecialchars($pkgExt, ENT_QUOTES); ?>" data-mac="<?php echo htmlspecialchars(strtolower($pkgMac), ENT_QUOTES); ?>" data-cipher="<?php echo htmlspecialchars(strtolower($pkgCipher), ENT_QUOTES); ?>" data-date="<?php echo $pkgMtime; ?>" data-instance="<?php echo $pkgInstance; ?>">
        <td style="text-align: left; vertical-align: middle; font-size: 14px; cursor: default; padding-left: 10px; border-right: none;" 
            title="<?php echo htmlspecialchars($filename, ENT_QUOTES); ?>">
            <strong>
                <?php echo !empty($pkgExt) ? 'Ext. ' . htmlspecialchars($pkgExt) : '&mdash;'; ?>
            </strong>
        </td>

        <td style="text-align: left; vertical-align: middle; font-size: 14px; cursor: default; padding-left: 15px; border-left: none;" 
            title="<?php echo htmlspecialchars($filename, ENT_QUOTES); ?>">
            <strong>
                <?php echo !empty($pkgMac) ? ' ' . htmlspecialchars($pkgMac) : '&mdash;'; ?>
            </strong>
        </td>

        <td style="text-align: center; vertical-align: middle; font-size: 12px;">
            <span class="label <?php echo $pkgInstance === 'modern' ? 'label-success' : 'label-warning'; ?>" title="Connects to the <?php echo $pkgServerLabel; ?> server"><?php echo htmlspecialchars($pkgCipher); ?></span>
        </td>

        <td class="date-column" style="text-align: center; vertical-align: middle; font-size: 12px;"><?php echo date("Y-m-d H:i", $pkgMtime); ?></td>
        <td style="text-align: center; vertical-align: middle; padding: 4px 3px; padding-left: 8px;">
            <div style="display: flex; justify-content: center; align-items: center; gap: 3px;">
                <button type="button" class="btn btn-xs btn-info" style="padding: 3px;" title="Edit Package Details" onclick="openEditPackageModal('<?php echo htmlspecialchars($filename, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pkgExt, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pkgMacRaw, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pkgCipher, ENT_QUOTES); ?>', <?php echo $pkgHasDataCiphers ? 'true' : 'false'; ?>, '<?php echo $pkgInstance; ?>')">
                    <i class="fa fa-pencil"></i>
                </button>
                <a href="<?php echo htmlspecialchars($downloadUrl); ?>" style="padding: 3px; font-size: 16px;" class="btn btn-xs btn-primary" download title="Download Package">
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
</div><!-- container-fluid -->

<!-- Modal: Edit Archive -->
<div class="modal fade" id="editPackageModal" tabindex="-1" role="dialog" aria-labelledby="editPackageModalLabel">
    <div class="modal-dialog" role="document" style="width: 480px; max-width: 96%;">
        <div class="modal-content">
            <form method="post" action="config.php?display=ovpn_mgr" id="editPackageForm">
                <input type="hidden" name="action" value="edit_package">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <input type="hidden" name="old_pkg" id="edit_old_pkg" value="">
                <input type="hidden" id="edit_from_instance" value="">

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
                        <label for="edit_cipher">Cipher:</label>
                        <select name="cipher" id="edit_cipher" class="form-control" required>
                            <?php if ($ovpnModernExists): ?>
                            <option value="AES-256-GCM">AES-256-GCM - Modern</option>
                            <option value="AES-128-GCM">AES-128-GCM - Modern</option>
                            <?php endif; ?>
                            <option value="AES-256-CBC">AES-256-CBC - Legacy</option>
                            <option value="AES-128-CBC">AES-128-CBC - Legacy</option>
                        </select>
                    </div>
                    <div id="edit_cipher_notice" role="status" aria-live="polite" style="margin: 0 0 10px; padding: 8px 10px; border: 1px solid #faebcc; border-radius: 4px; background: #fcf8e3; color: #8a6d3b; font-size: 11px; line-height: 1.5;"></div>
                    <div id="edit_server_notice" class="alert alert-info" style="display: none; margin: 0 0 10px; padding: 8px 10px; font-size: 11px;"></div>

                    <div id="edit_data_ciphers_row" style="display: none; margin: 0;">
                        <label style="font-size: 11px; font-weight: normal; margin: 0; cursor: pointer;" title="Adds data-ciphers / data-ciphers-fallback to vpn.cnf so the client negotiates this cipher via NCP. Only understood by OpenVPN 2.5+ clients - on 2.4.x (including some phones' embedded builds, even ones that otherwise connect fine with a GCM cipher) this keyword fails to parse and the client won't start at all. Leave unchecked unless you've confirmed the client's OpenVPN version.">
                            <input type="checkbox" id="edit_include_data_ciphers" name="include_data_ciphers" value="1" style="margin: 0 4px 0 0; vertical-align: middle;">
                            Include data-ciphers (requires OpenVPN 2.5+ client &mdash; confirm before enabling)
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary"><i class="fa fa-save"></i> Rebuild & Save</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal: change the cipher of several selected packages at once -->
<div class="modal fade" id="bulkCipherModal" tabindex="-1" role="dialog" aria-labelledby="bulkCipherModalLabel">
    <div class="modal-dialog" role="document" style="width: 480px; max-width: 96%;">
        <div class="modal-content">
            <form method="post" action="config.php?display=ovpn_mgr" id="bulkCipherForm">
                <input type="hidden" name="action" value="bulk_change_cipher">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <div id="bulkCipherInputs"></div>

                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="bulkCipherModalLabel"><i class="fa fa-pencil"></i> Change Cipher of Selected Packages</h4>
                </div>
                <div class="modal-body">
                    <p id="bulkCipherSummary" style="font-size: 12px; color: #555;"></p>
                    <div class="form-group">
                        <label for="bulk_cipher">New cipher:</label>
                        <select name="cipher" id="bulk_cipher" class="form-control" required>
                            <?php if ($ovpnModernExists): ?>
                            <option value="AES-256-GCM">AES-256-GCM - Modern</option>
                            <option value="AES-128-GCM">AES-128-GCM - Modern</option>
                            <?php endif; ?>
                            <option value="AES-256-CBC">AES-256-CBC - Legacy</option>
                            <option value="AES-128-CBC">AES-128-CBC - Legacy</option>
                        </select>
                    </div>
                    <div id="bulk_cipher_notice" role="status" aria-live="polite" style="margin: 0 0 10px; padding: 8px 10px; border: 1px solid #faebcc; border-radius: 4px; background: #fcf8e3; color: #8a6d3b; font-size: 11px; line-height: 1.5;"></div>
                    <div id="bulk_server_notice" class="alert alert-info" style="display: none; margin: 0 0 10px; padding: 8px 10px; font-size: 11px;"></div>

                    <div id="bulk_data_ciphers_row" style="display: none; margin: 0;">
                        <label style="font-size: 11px; font-weight: normal; margin: 0; cursor: pointer;" title="Adds data-ciphers / data-ciphers-fallback to vpn.cnf so the client negotiates this cipher via NCP. Only understood by OpenVPN 2.5+ clients - on 2.4.x (including some phones' embedded builds, even ones that otherwise connect fine with a GCM cipher) this keyword fails to parse and the client won't start at all. Leave unchecked unless you've confirmed the client's OpenVPN version.">
                            <input type="checkbox" id="bulk_include_data_ciphers" name="include_data_ciphers" value="1" style="margin: 0 4px 0 0; vertical-align: middle;">
                            Include data-ciphers (requires OpenVPN 2.5+ client &mdash; confirm before enabling)
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary"><i class="fa fa-save"></i> Change Cipher</button>
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

<!-- Modal: Revocation (both instances) -->
<div class="modal fade" id="revokeModal" tabindex="-1" role="dialog" aria-labelledby="revokeModalLabel">
    <div class="modal-dialog modal-lg" role="document" style="width: 90%; max-width: 1050px;">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="revokeModalLabel"><i class="fa fa-key"></i> Manage / Revoke Keys & Provisioning Packages</h4>
            </div>
            <?php if (!empty($issuedCerts)): ?>
                <div style="padding: 6px 10px; border-bottom: 1px solid #ddd; display: flex; align-items: center; gap: 6px; background: #f8f9fa;">
                    <span id="pkgSelectedCount" class="text-muted" style="font-size: 11px;">Select rows with a package to enable Download / Edit / Revoke Selected below.</span>
                </div>
            <?php endif; ?>
            <div class="modal-body" style="padding: 0;">
                <?php if (empty($issuedCerts)): ?>
                    <div style="padding: 20px;" class="text-muted">No issued client certificates found in PKI storage.</div>
                <?php else: ?>
                    <div style="max-height: 461px; overflow-y: auto;">
                        <table id="ovpnRevokeTable" class="table table-striped table-bordered ovpn-sortable-table" style="margin-bottom: 0;">
                            <thead>
                                <tr>
                                    <th style="width: 26px; text-align: center; position: sticky; top: 0; background: #d6e4dd; z-index: 1;">
                                        <input type="checkbox" id="pkgSelectAll" title="Select all" onchange="toggleAllOvpnPkgCheckboxes(this)">
                                    </th>
                                    <th class="ovpn-sortable" data-col="1" data-type="nat" tabindex="0" title="Sort by common name" style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Common Name (Ext) <span class="ovpn-sort-ind"></span></th>
                                    <th class="ovpn-sortable" data-col="2" data-type="text" tabindex="0" title="Sort by server" style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Server <span class="ovpn-sort-ind"></span></th>
                                    <th class="ovpn-sortable" data-col="3" data-type="ip" tabindex="0" title="Sort by target" style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Target (Host:Port) <span class="ovpn-sort-ind"></span></th>
                                    <th class="ovpn-sortable" data-col="4" data-type="text" tabindex="0" title="Sort by issued date" style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Issued Date <span class="ovpn-sort-ind"></span></th>
                                    <th class="ovpn-sortable" data-col="5" data-type="text" tabindex="0" title="Sort by package" style="position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Package <span class="ovpn-sort-ind"></span></th>
                                    <th style="width: 150px; text-align: center; position: sticky; top: 0; background: #d6e4dd; z-index: 1;">Revocation</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($issuedCerts as $issuedCert):
                                    $certInst = $issuedCert['instance'];
                                    $crtPath  = $issuedCert['path'];
                                    $certLabel = $ovpnInst[$certInst]['label'];
                                    $extName = pathinfo($crtPath, PATHINFO_FILENAME);
                                    $parsedCert = openssl_x509_parse((string)@file_get_contents($crtPath));
                                    $validFrom = date("Y-m-d H:i", $parsedCert['validFrom_time_t'] ?? filemtime($crtPath));
                                    $targetHostPort = "{$ovpnInst[$certInst]['settings']['ip']}:{$ovpnInst[$certInst]['settings']['port']}";
                                    // The package of this certificate: the one that belongs to this server (an
                                    // extension can have a certificate on both servers).
                                    $matchingTars = array_merge(
                                        glob("{$pkgDir}/*_{$extName}_*_ovpn.tar") ?: [],
                                        glob("{$pkgDir}/*_{$extName}_ovpn.tar") ?: []
                                    );
                                    $pkgFile = null;
                                    foreach ($matchingTars as $candidateTar) {
                                        if (file_exists($candidateTar) && ovpnPackageInstance($candidateTar, $baseDir) === $certInst) { $pkgFile = $candidateTar; break; }
                                    }
                                    $pkgFilename = null;
                                    $rowMac = ''; $rowCipher = ''; $rowDataCiphers = false;
                                    if ($pkgFile !== null) {
                                        $pkgFilename = basename($pkgFile);
                                        $rowId = ovpnParsePackageName($pkgFilename, true);
                                        $rowMac = ($rowId !== null) ? $rowId['mac'] : '';
                                        if (preg_match('/^[0-9a-f]{12}$/i', $rowMac)) { $rowMac = strtoupper($rowMac); }
                                        $rowCipher = getPackageCipher($pkgFile);
                                        $rowDataCiphers = packageHasDataCiphers($pkgFile);
                                        // Read vpn.cnf's remote line straight out of the tar via PharData
                                        // (in-process) instead of forking a 'tar' subprocess per row -
                                        // this loop runs on every page load and can cover a lot of
                                        // packages, so N forks here was a real cost.
                                        try {
                                            $pharEntry = new PharData($pkgFile);
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
                                                <input type="checkbox" class="ovpn-pkg-checkbox" value="<?php echo htmlspecialchars($pkgFilename, ENT_QUOTES); ?>"
                                                    data-ext="<?php echo htmlspecialchars($extName, ENT_QUOTES); ?>"
                                                    data-mac="<?php echo htmlspecialchars($rowMac, ENT_QUOTES); ?>"
                                                    data-cipher="<?php echo htmlspecialchars($rowCipher, ENT_QUOTES); ?>"
                                                    data-datacipher="<?php echo $rowDataCiphers ? '1' : '0'; ?>"
                                                    data-instance="<?php echo $certInst; ?>"
                                                    onchange="updateOvpnPkgSelection()">
                                            <?php endif; ?>
                                        </td>
                                        <td data-sv="<?php echo htmlspecialchars($extName, ENT_QUOTES); ?>"><strong>Extension <?php echo htmlspecialchars($extName); ?></strong></td>
                                        <td><span class="label <?php echo $certInst === 'modern' ? 'label-success' : 'label-warning'; ?>"><?php echo htmlspecialchars($certLabel); ?></span></td>
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
                                                <input type="hidden" name="instance" value="<?php echo $certInst; ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                                                <input type="hidden" name="revoke_ext" value="<?php echo htmlspecialchars($extName); ?>">
                                                <button type="submit" class="btn btn-xs btn-danger" data-confirm-message="REVOKE Extension <?php echo htmlspecialchars($extName, ENT_QUOTES); ?> on the <?php echo htmlspecialchars($certLabel, ENT_QUOTES); ?> server?"><i class="fa fa-ban"></i> Revoke & Block</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            <div class="modal-footer" style="display: flex; justify-content: flex-start; align-items: center; gap: 6px; flex-wrap: wrap;">
                <button type="button" id="pkgDownloadSelectedBtn" class="btn btn-primary btn-xs ovpn-foot-icon" disabled title="Download Selected (.tar of the provisioning packages)" aria-label="Download Selected" onclick="submitOvpnBulkPkgAction('bulk_download_packages')">
                    <i class="fa fa-download"></i>
                </button>
                <button type="button" id="pkgOvpnSelectedBtn" class="btn btn-primary btn-xs ovpn-foot-icon" disabled title="Download .ovpn Selected (single-file profile with CA, certificate and key for OpenVPN Connect and similar apps; several come as one .tar)" aria-label="Download .ovpn Selected" onclick="submitOvpnBulkPkgAction('bulk_download_ovpn')">
                    <svg width="16" height="16" viewBox="0 0 100 100" aria-hidden="true" style="vertical-align: -3px;"><rect width="100" height="100" rx="20" fill="#fff"/><path d="M 37 90 A 40 40 0 1 1 63 90" fill="none" stroke="#ED8B1F" stroke-width="20"/><circle cx="50" cy="47" r="14" fill="#1A2A6C"/><path d="M 41 56 L 59 56 L 66 94 L 34 94 Z" fill="#1A2A6C"/></svg>
                </button>
                <button type="button" id="pkgRebuildCfgSelectedBtn" class="btn btn-default btn-xs ovpn-foot-icon" disabled title="Rebuild Config Selected (rewrites vpn.cnf only; keeps each phone's key and cipher)" aria-label="Rebuild Config Selected" onclick="submitOvpnBulkPkgAction('bulk_rebuild_config_packages')">
                    <i class="fa fa-wrench"></i>
                </button>
                <button type="button" id="pkgRevokeSelectedBtn" class="btn btn-danger btn-xs ovpn-foot-icon" disabled title="Revoke Selected" aria-label="Revoke Selected" onclick="submitOvpnBulkPkgAction('bulk_revoke_packages')">
                    <i class="fa fa-ban"></i>
                </button>
                <button type="button" id="pkgRebuildSelectedBtn" class="btn btn-warning btn-xs ovpn-foot-icon" disabled title="Revoke & Rebuild Selected" aria-label="Revoke & Rebuild Selected" onclick="submitOvpnBulkPkgAction('bulk_revoke_rebuild_packages')">
                    <i class="fa fa-refresh"></i>
                </button>
                <button type="button" id="pkgEditSelectedBtn" class="btn btn-info btn-xs ovpn-foot-icon" disabled title="Edit Selected (one package: same dialog as the pencil in the archive table; several: change all their ciphers at once)" aria-label="Edit Selected" onclick="editSelectedOvpnPackages()">
                    <i class="fa fa-pencil"></i>
                </button>
                <span style="flex: 1 1 auto;"></span>
                <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal: Log Viewer -->
<!-- VPN Access popup -->
<?php
    $ovpnLanAccessNow = ovpnReadLanAccess();
    $ovpnLanInfo      = ovpnDetectLanInfo();
    // Each server's VPN pool (always allowed into the other server's tunnel) and an example phone address from the first one.
    $ovpnPoolsShown = []; $ovpnExamplePhoneIp = '';
    foreach ($ovpnInstanceList as $poolInst) {
        $pool = ovpnServerPoolFromConf(ovpnConfPath($baseDir, $poolInst));
        if ($pool === null) { continue; }
        $ovpnPoolsShown[] = ucfirst($poolInst) . ' ' . $pool['cidr'];
        if ($ovpnExamplePhoneIp === '') { $ovpnExamplePhoneIp = long2ip(ip2long($pool['net']) + 2); }
    }
?>
<div class="modal fade" id="lanAccessModal" tabindex="-1" role="dialog" aria-labelledby="lanAccessModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="config.php?display=ovpn_mgr" id="lanAccessForm">
                <input type="hidden" name="action" value="save_lan_access">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="lanAccessModalLabel"><i class="fa fa-unlock-alt"></i> Networks allowed to reach the VPN</h4>
                </div>
                <div class="modal-body">
                    <p>Computers on these addresses can reach the phones' VPN addresses<?php if ($ovpnExamplePhoneIp !== ''): ?> (for example <code><?php echo htmlspecialchars($ovpnExamplePhoneIp); ?></code>)<?php endif; ?>. Their traffic is sent into the VPN as if it came from the PBX, so the phone can answer. This list applies to both the Legacy and Modern servers, and does not affect phones provisioning to the PBX itself.</p>
                    <p style="margin-bottom: 4px;"><strong>Always included:</strong>
                        <?php if ($ovpnLanInfo['cidr'] !== ''): ?><code><?php echo htmlspecialchars($ovpnLanInfo['cidr']); ?></code> (this PBX's own LAN)<?php else: ?>this PBX's own LAN (not detected right now)<?php endif; ?></p>
                    <?php if (count($ovpnPoolsShown) > 1): ?>
                        <p style="margin-bottom: 4px;"><strong>Also always included:</strong> the two servers' VPN subnets (<?php echo htmlspecialchars(implode(', ', $ovpnPoolsShown)); ?>), so each server's clients can reach the other's.</p>
                    <?php endif; ?>
                    <label for="lanAccessText" style="margin-top: 8px;">Also allow (one address or network per line)</label>
                    <textarea id="lanAccessText" name="lan_access" rows="7" class="form-control" spellcheck="false" style="font-family: monospace;" placeholder="10.2.0.10&#10;10.0.20.0/24"><?php echo htmlspecialchars(implode("\n", $ovpnLanAccessNow)); ?></textarea>
                    <p class="help-block" style="margin-bottom: 0;">Use the address the PBX actually sees on the incoming traffic. Run <code>tcpdump -ni any icmp and host <?php echo htmlspecialchars($ovpnExamplePhoneIp !== '' ? $ovpnExamplePhoneIp : '<phone VPN address>'); ?></code> while you ping the phone, and use the source shown on the <?php echo $ovpnLanInfo['dev'] !== '' ? '<code>' . htmlspecialchars($ovpnLanInfo['dev']) . '</code>' : 'LAN interface'; ?> line. Single addresses or networks from /8 to /32, up to 64 entries. Applied immediately to every server; no restart needed.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary"><i class="fa fa-check"></i> Save</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="logModal" tabindex="-1" role="dialog" aria-labelledby="logModalLabel">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="logModalLabel" style="display: inline-block;"><i class="fa fa-terminal"></i> OpenVPN Live Log Output (Last 500 Lines)</h4>
            </div>
            <div class="modal-body">
                <div class="ovpn-set-tabs" id="logInstanceTabs" role="tablist" style="margin-bottom: 10px;">
                    <?php foreach ($ovpnInstanceList as $li): ?>
                        <a href="#" role="tab" aria-selected="<?php echo $li === $ovpnInstanceList[0] ? 'true' : 'false'; ?>" class="ovpn-set-tab<?php echo $li === $ovpnInstanceList[0] ? ' active' : ''; ?>" data-instance="<?php echo $li; ?>"><?php echo htmlspecialchars($ovpnInst[$li]['label']); ?></a>
                    <?php endforeach; ?>
                </div>
                <textarea id="logModalPre" readonly style="width: 100%; height: 350px; min-height: 200px; resize: both; overflow: auto; background: #f4f4f4; color: #111111; font-family: monospace; font-size: 12px; border: 1px solid #ccc; border-radius: 4px; padding: 10px;">Loading...</textarea>
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
#ovpnPkgTable th.ovpn-sortable, .ovpn-sortable-table th.ovpn-sortable { cursor: pointer; user-select: none; white-space: nowrap; }
#ovpnPkgTable th.ovpn-sortable:hover, #ovpnPkgTable th.ovpn-sortable:focus, .ovpn-sortable-table th.ovpn-sortable:hover, .ovpn-sortable-table th.ovpn-sortable:focus { background-color: rgba(0,0,0,0.05); outline: none; }
#ovpnPkgTable .ovpn-sort-ind, .ovpn-sortable-table .ovpn-sort-ind { font-size: 15px; opacity: 0.8; color: #0f5a59 }
#ovpnPkgTable th.ovpn-sorted .ovpn-sort-ind, .ovpn-sortable-table th.ovpn-sorted .ovpn-sort-ind { opacity: 0.8; }

.date-column { 
	width: auto; 
	text-align: center;  
	white-space: normal; 
	overflow: hidden; 
}	 

</style>

<script>
var OVPN_CSRF = <?php echo json_encode($csrfToken); ?>;
var OVPN_CBC_IN_USE = <?php echo json_encode((object)$ovpnCbcInUse); ?>;
// Per instance: whether crl-verify is already wired into its server config. If it isn't yet,
// the NEXT revoke of any kind (including one from an Edit Package save) is
// the one that adds it - a genuine, if rare, restart-requiring change. Once
// present (true on essentially every already-used install), edits never
// need a restart at all under the current design.
var OVPN_CRL_VERIFY_PRESENT = <?php echo json_encode((object)array_map(function ($c) { return (bool)$c['crlVerifyPresent']; }, $ovpnInst)); ?>;
// Per instance: what the page needs to describe a package's target and each server's default cipher.
var OVPN_INSTANCES = <?php
    $ovpnJsInst = [];
    foreach ($ovpnInst as $li => $c) {
        $ovpnJsInst[$li] = [
            'label'         => $c['label'],
            'ip'            => $c['settings']['ip'],
            'port'          => $c['settings']['port'],
            'hostIp'        => $c['settings']['host_ip'],
            'defaultCipher' => $c['defaultCipher'],
        ];
    }
    echo json_encode((object)$ovpnJsInst);
?>;
var OVPN_HAS_MODERN = <?php echo json_encode($ovpnModernExists); ?>;

// AES-GCM is served by the modern instance, AES-CBC by the legacy one.
function ovpnInstanceForCipher(cipher) { return /-CBC$/.test(cipher || '') ? 'legacy' : 'modern'; }
function ovpnInstanceLabel(inst) { return inst === 'modern' ? 'Modern' : 'Legacy'; }

// Tells the person which server the chosen cipher connects to, and whether picking it moves an existing package.
function ovpnServerNotice(noticeId, cipher, fromInstance) {
    var $n = $('#' + noticeId);
    if (!$n.length) return;
    var to = ovpnInstanceForCipher(cipher);
    if (fromInstance && fromInstance !== to) {
        $n.html('<i class="fa fa-exchange"></i> <strong>' + ovpnInstanceLabel(to) + ' server.</strong> This package is on the ' + ovpnInstanceLabel(fromInstance)
            + ' server now. It will be built on the ' + ovpnInstanceLabel(to) + ' server (a new certificate) and its certificate on the '
            + ovpnInstanceLabel(fromInstance) + ' server is revoked, so the phone needs the new package.').show();
    } else {
        $n.hide().empty();
    }
}

var ovpnEditFromInstance = null;
function openEditPackageModal(filename, currentExt, currentMac, currentCipher, currentHasDataCiphers, currentInstance) {
    $('#edit_old_pkg').val(filename);
    $('#edit_ext').val(currentExt);
    $('#edit_mac').val(currentMac);
    $('#edit_cipher').val(currentCipher || 'AES-128-CBC');
    ovpnEditOriginalCipher = currentCipher || 'AES-128-CBC';
    ovpnEditFromInstance = currentInstance || ovpnInstanceForCipher(ovpnEditOriginalCipher);
    $('#edit_from_instance').val(ovpnEditFromInstance);
    updateEditCipherNotice();
    updateDataCiphersRow('edit_cipher', 'edit_data_ciphers_row', 'edit_include_data_ciphers', !!currentHasDataCiphers);
    ovpnServerNotice('edit_server_notice', $('#edit_cipher').val(), ovpnEditFromInstance);
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
function recalculateRange(inst) {
    var hostIp = $('#ovpn_host_ip-' + inst).val().trim();
    var cidr = parseInt($('#ovpn_cidr-' + inst).val()) || 24;
    if (cidr < 16) cidr = 16;
    if (cidr > 29) cidr = 29;
    var netmask = cidrToNetmaskJs(cidr);
    var longHost = ipToLong(hostIp);
    var longMask = ipToLong(netmask);
    var $notice = $('#host_ip_live_notice-' + inst);

    var clientIpCount = Math.max(0, (Math.pow(2, 32 - cidr) - 2) - 1);
    $('#client_ip_count-' + inst).text(clientIpCount);

    var octets = hostIp.split('.');
    var looksLikeIp = octets.length === 4 && octets.every(function(o) {
        return /^\d{1,3}$/.test(o) && parseInt(o, 10) <= 255;
    });

    if (!looksLikeIp || longHost === 0 || longMask === 0) {
        $('#range_start-' + inst).text('10.8.0.1'); $('#range_end-' + inst).text('10.8.0.254');
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
    $('#range_start-' + inst).text(longToIp(firstUsableLong));
    $('#range_end-' + inst).text(longToIp(lastUsableLong));

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
    ['modern', 'legacy'].forEach(function (inst) {
        if (document.getElementById('ovpn_host_ip-' + inst)) { recalculateRange(inst); }
    });
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

function updateFqdnNotice(inst) {
    var v = ($('#server_ip-' + inst).val() || '').trim();
    var isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.indexOf(':') !== -1;
    $('#fqdnNotice-' + inst).toggle(v !== '' && v !== 'Fetching...' && !isIp);
}
$(function() {
    ['modern', 'legacy'].forEach(function (inst) {
        $('#server_ip-' + inst).on('input change', function () { updateFqdnNotice(inst); });
    });
});
function setPrivateIp(inst) {
    $('#server_ip-' + inst).val(<?php echo json_encode($_SERVER['SERVER_ADDR'] ?? ''); ?>);
    updateFqdnNotice(inst);
}
function fetchPublicIp(inst) {
    $('#server_ip-' + inst).val('Fetching...');
    updateFqdnNotice(inst);
    $.get('config.php?display=ovpn_mgr&action=fetch_public_ip', function(ip) {
        $('#server_ip-' + inst).val(ip.trim());
        updateFqdnNotice(inst);
    }).fail(function() {
        $('#server_ip-' + inst).val(<?php echo json_encode($_SERVER['SERVER_ADDR'] ?? ''); ?>);
        updateFqdnNotice(inst);
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

function openCockpit(btn) {
    var port = btn.getAttribute('data-port');
    window.open('https://' + window.location.hostname + ':' + port + '/', '_blank', 'noopener');
}

function copySetupCommand(id) {
    var text = document.getElementById(id || 'setupCmd').innerText;
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

// Modern / Legacy tabs in the Server Settings heading: show one server's settings at a time (no reload);
// the chosen tab is remembered in this browser.
(function () {
    var STORE = 'ovpn_mgr_settings_tab';
    function show(inst) {
        var $tab = $('#ovpnSetTabs .ovpn-set-tab[data-instance="' + inst + '"]');
        if (!$tab.length) return;
        $('#ovpnSetTabs .ovpn-set-tab').removeClass('active').attr('aria-selected', 'false');
        $tab.addClass('active').attr('aria-selected', 'true');
        $('.ovpn-set-pane').hide().filter('[data-instance="' + inst + '"]').show();
        try { localStorage.setItem(STORE, inst); } catch (e) {}
    }
    $('#ovpnSetTabs').on('click', '.ovpn-set-tab', function (e) { e.preventDefault(); this.blur(); show($(this).data('instance')); });
    try { var saved = localStorage.getItem(STORE); if (saved) show(saved); } catch (e) {}
})();

// Server Settings forms (one per instance). Only the port and the VPN subnet (VPN Host IP / CIDR)
// need the OpenVPN daemon restarted; the server host / FQDN does not.
// "Save Settings" is always enabled and never restarts anything. When a
// restart-requiring field differs from what is saved (or an earlier save is
// still waiting for a restart), "Save & Restart Daemon" appears next to it.
// .defaultValue holds each input's original server-rendered value.
Array.prototype.forEach.call(document.querySelectorAll('.ovpn-settings-form'), function (settingsForm) {
    var inst = settingsForm.getAttribute('data-instance');
    var restartBtn = document.getElementById('ovpnSaveRestartBtn-' + inst);
    var restartHint = document.getElementById('ovpnRestartHint-' + inst);
    var restartFlag = document.getElementById('restart_daemon-' + inst);
    var pending = restartBtn && restartBtn.getAttribute('data-pending') === '1';
    var watched = ['ovpn_port-', 'ovpn_host_ip-', 'ovpn_cidr-'].map(function (id) { return document.getElementById(id + inst); }).filter(Boolean);

    function dirty() {
        return watched.some(function (el) { return el.value.trim() !== el.defaultValue.trim(); });
    }
    function refresh() {
        var d = dirty();
        var show = d || pending;
        if (restartBtn) restartBtn.style.display = show ? '' : 'none';
        if (restartHint) {
            restartHint.style.display = show ? '' : 'none';
            restartHint.textContent = d
                ? 'The port or VPN subnet changed. Save Settings stores it without touching the daemon; the change only takes effect after a daemon restart, which disconnects every phone on this server until it reconnects.'
                : 'Saved port / VPN subnet changes are waiting for a daemon restart to take effect.';
        }
    }
    watched.forEach(function (el) {
        el.addEventListener('input', refresh);
        el.addEventListener('change', refresh);
    });
    refresh();

    settingsForm.addEventListener('submit', function () {
        if (restartFlag) restartFlag.value = '0';
        showOvpnProgress('Saving settings, please wait...');
    });

    if (restartBtn) {
        restartBtn.addEventListener('click', function () {
            showOvpnConfirm(
                'Restarting the ' + ovpnInstanceLabel(inst) + ' OpenVPN daemon will disconnect every phone connected to it. They will reconnect on their own once it is back up. Continue?',
                function () {
                    if (restartFlag) restartFlag.value = '1';
                    showOvpnProgress('Saving settings and restarting the ' + ovpnInstanceLabel(inst) + ' OpenVPN daemon...');
                    settingsForm.submit();
                }
            );
        });
    }
});

// Edit Package form: under the current design a plain cipher/ext/MAC edit
// never needs a restart - EXCEPT the one-time case where crl-verify hasn't
// been wired into the server config yet, in which case this save's revoke
// is the one that adds it. Warn only in that (rare, usually one-time-ever)
// case, so routine edits stay silent.
(function () {
    var editForm = document.getElementById('editPackageForm');
    if (!editForm) return;
    editForm.addEventListener('submit', function (e) {
        var from = ovpnEditFromInstance;
        if (!from || OVPN_CRL_VERIFY_PRESENT[from] !== false) {
            showOvpnProgress('Saving, please wait...');
            return;
        }
        e.preventDefault();
        showOvpnConfirm(
            'This is the first time a certificate has been revoked on the ' + ovpnInstanceLabel(from) + ' server, which requires a one-time restart of its OpenVPN daemon to enable revocation checking. Every phone connected to it will be disconnected. Continue?',
            function () {
                showOvpnProgress('Saving, please wait...');
                editForm.submit();
            }
        );
    });
})();

// Generate Package form: the only thing here that can force a restart is
// ticking "Set as default cipher" for a legacy cipher while actually changing
// the legacy default (see syncServerCiphers). A modern default never restarts.
(function () {
    var genForm = document.getElementById('ovpnGenerateForm');
    var cipherSelect = document.getElementById('ovpn_cipher');
    var defaultBox = document.getElementById('ovpn_cipher_default');
    if (!genForm || !cipherSelect || !defaultBox) return;
    genForm.addEventListener('submit', function (e) {
        var inst = ovpnInstanceForCipher(cipherSelect.value);
        var currentDefault = cipherSelect.getAttribute('data-default-' + inst);
        var changingDefault = inst === 'legacy' && defaultBox.checked && !defaultBox.disabled && cipherSelect.value !== currentDefault;
        if (!changingDefault) { return; }
        e.preventDefault();
        showOvpnConfirm(
            'Changing the legacy default cipher requires restarting the Legacy OpenVPN daemon, which will disconnect every phone connected to it. They will reconnect on their own once it is back up. Continue?',
            function () {
                showOvpnProgress('Building package, please wait...');
                genForm.submit();
            }
        );
    });
})();

$(document).off('click.ovpnConfirm').on('click.ovpnConfirm', 'button[data-confirm-message], a[data-confirm-message]', function(e) {
    e.preventDefault();
    var $btn = $(this);
    var message = $btn.attr('data-confirm-message');
    var progressLabel = $btn.attr('data-progress-label') || 'Working, please wait...';
    var form = $btn[0].form || $btn.closest('form')[0];
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

$('.ovpn-service-form').on('submit', function() {
    showOvpnProgress('Applying service command, please wait...');
});

function toggleAllOvpnPkgCheckboxes(source) {
    $('.ovpn-pkg-checkbox').prop('checked', source.checked);
    updateOvpnPkgSelection();
}

function updateOvpnPkgSelection() {
    var $checked = $('.ovpn-pkg-checkbox:checked');
    var total = $('.ovpn-pkg-checkbox').length;
    $('#pkgDownloadSelectedBtn, #pkgOvpnSelectedBtn, #pkgRebuildCfgSelectedBtn, #pkgRevokeSelectedBtn, #pkgRebuildSelectedBtn, #pkgEditSelectedBtn').prop('disabled', $checked.length === 0);
    $('#pkgSelectedCount').text($checked.length > 0 ? ($checked.length + ' selected') : '');
    $('#pkgSelectAll').prop('checked', total > 0 && $checked.length === total);
}

// Edit Selected: one package selected = the same dialog as the pencil in the archive table;
// several selected = change all their ciphers at once.
function editSelectedOvpnPackages() {
    var $c = $('.ovpn-pkg-checkbox:checked');
    if ($c.length === 0) return;
    if ($c.length === 1) {
        var el = $c[0];
        $('#revokeModal').one('hidden.bs.modal', function () {
            openEditPackageModal(el.value, el.getAttribute('data-ext'), el.getAttribute('data-mac'), el.getAttribute('data-cipher'), el.getAttribute('data-datacipher') === '1', el.getAttribute('data-instance'));
        }).modal('hide');
        return;
    }
    var $inputs = $('#bulkCipherInputs').empty();
    var ciphers = {};
    $c.each(function () {
        $('<input>').attr({ type: 'hidden', name: 'pkgs[]', value: this.value }).appendTo($inputs);
        ciphers[this.getAttribute('data-cipher')] = true;
    });
    var names = Object.keys(ciphers);
    $('#bulkCipherSummary').text($c.length + ' packages selected. Every one gets the cipher you choose and keeps its extension, MAC, address and (unless it has to change server) its key.');
    $('#bulk_cipher').val(names.length === 1 ? names[0] : $('#bulk_cipher option:first').val());
    updateBulkCipherNotice();
    updateDataCiphersRow('bulk_cipher', 'bulk_data_ciphers_row', 'bulk_include_data_ciphers', false);
    $('#revokeModal').one('hidden.bs.modal', function () { $('#bulkCipherModal').modal('show'); }).modal('hide');
}
function updateBulkCipherNotice() {
    var cipher = $('#bulk_cipher').val();
    var to = ovpnInstanceForCipher(cipher), moving = 0, total = 0, exclude = {};
    $('.ovpn-pkg-checkbox:checked').each(function () {
        total++;
        var c = this.getAttribute('data-cipher');
        exclude[c] = (exclude[c] || 0) + 1;
        if (this.getAttribute('data-instance') !== to) moving++;
    });
    applyCipherNotice('bulk_cipher', 'bulk_cipher_notice', null, exclude);
    var $n = $('#bulk_server_notice');
    if (moving > 0) {
        $n.html('<i class="fa fa-exchange"></i> <strong>' + ovpnInstanceLabel(to) + ' server.</strong> ' + moving + ' of the ' + total + ' selected package(s) are on the other server now. '
            + 'They are built on the ' + ovpnInstanceLabel(to) + ' server (new certificates) and their old certificates are revoked.').show();
    } else {
        $n.hide().empty();
    }
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
    } else if (action === 'bulk_rebuild_config_packages') {
        showOvpnConfirm(
            'Rebuild the config for ' + selected.length + ' selected package(s)? Existing keys and ciphers are kept; the phones just need to download the updated package.',
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

var logInterval = null;
var ovpnLogInstance = <?php echo json_encode($ovpnInstanceList[0]); ?>;
var isInitialOpen = false;

var logInFlight = false;

function renderOpenVPNLog(text) {
    const $textarea = $('#logModalPre');
    const elem = $textarea[0];
    const isAtBottom = (elem.scrollHeight - elem.clientHeight - elem.scrollTop) <= 40;
    $textarea.val(text);
    if (isInitialOpen || isAtBottom) {
        elem.scrollTop = elem.scrollHeight;
        isInitialOpen = false;
    }
}

// Polls ajax.php (no per-request GPG module-signature check, unlike
// config.php), never overlaps requests, and skips hidden tabs. If ajax.php
// can't serve it, falls back to the original config.php endpoint.
var logUseFallback = false;
function fetchOpenVPNLog() {
    if (logInFlight || document.hidden) { return; }
    logInFlight = true;
    const req = logUseFallback
        ? { url: 'config.php', dataType: 'text', data: { display: 'ovpn_mgr', action: 'fetch_log', instance: ovpnLogInstance } }
        : { url: 'ajax.php', dataType: 'json', data: { module: 'ovpn_mgr', command: 'fetch_log', instance: ovpnLogInstance } };
    $.ajax({
        url: req.url, type: 'GET', dataType: req.dataType, timeout: 8000, data: req.data,
        success: function(response) {
            if (logUseFallback) { renderOpenVPNLog(response); }
            else if (response && response.status && typeof response.log === 'string') { renderOpenVPNLog(response.log); }
            else { logUseFallback = true; }
        },
        error: function() { logUseFallback = true; },
        complete: function() { logInFlight = false; }
    });
}

function addLogPageBreak() {
    $.ajax({
        url: 'config.php', type: 'POST',
        data: { display: 'ovpn_mgr', action: 'add_page_break', instance: ovpnLogInstance, csrf_token: OVPN_CSRF },
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
    logInterval = setInterval(fetchOpenVPNLog, 4000);
});
// One tab per server in the log viewer.
$('#logInstanceTabs').on('click', '.ovpn-set-tab', function (e) {
    e.preventDefault();
    this.blur();
    var inst = $(this).data('instance');
    if (inst === ovpnLogInstance) return;
    ovpnLogInstance = inst;
    $('#logInstanceTabs .ovpn-set-tab').removeClass('active').attr('aria-selected', 'false');
    $(this).addClass('active').attr('aria-selected', 'true');
    $('#logModalPre').val('Loading...');
    isInitialOpen = true;
    logInFlight = false;
    fetchOpenVPNLog();
});
$('#logModal').on('hidden.bs.modal', function () {
    if (logInterval) { clearInterval(logInterval); logInterval = null; }
});

// Keep cipher guidance visible and color-coded in both package forms.
var ovpnCipherGuidance = {
    'AES-128-CBC': { bg: '#fcf8e3', border: '#faebcc', color: '#8a6d3b', text: '<strong><span style="font-size: 1.5em;">&#9888;</span> Legacy compatibility:</strong> Uses AES-128-CBC and SHA1. Intended for older phones that cannot use modern OpenVPN data ciphers.' },
    'AES-256-CBC': { bg: '#fcf8e3', border: '#faebcc', color: '#8a6d3b', text: '<strong><span style=\"font-size: 1.5em;\">&#9888;</span> Legacy compatibility:</strong> Uses AES-256-CBC and SHA1. Stronger than AES-128-CBC, for older phones that cannot use modern OpenVPN data ciphers.' },
    'AES-128-GCM': { bg: '#d4edda', border: '#c3e6cb', color: '#155724', text: '<strong><span style="font-size: 1.4em;">&#10004;</span> Modern cipher:</strong> AES-128-GCM. Sent as a static cipher by default, which works even on many OpenVPN 2.4.x clients. Only check &ldquo;Include data-ciphers&rdquo; below if you have confirmed the phone runs OpenVPN 2.5+ - on 2.4.x that keyword fails to parse and the client won&rsquo;t start.' },
    'AES-256-GCM': { bg: '#d4edda', border: '#c3e6cb', color: '#155724', text: '<strong><span style="font-size: 1.4em;">&#10004;</span> Strong modern cipher:</strong> AES-256-GCM. Sent as a static cipher by default, which works even on many OpenVPN 2.4.x clients. Only check &ldquo;Include data-ciphers&rdquo; below if you have confirmed the phone runs OpenVPN 2.5+ - on 2.4.x that keyword fails to parse and the client won&rsquo;t start.' }
};
function applyCipherNotice(selectId, noticeId, ownCipher, excludeCounts) {
    var select = document.getElementById(selectId), notice = document.getElementById(noticeId);
    if (!select || !notice) return;
    var item = ovpnCipherGuidance[select.value] || ovpnCipherGuidance['AES-128-CBC'];
    var extra = '';
    // Older phones can't negotiate, so every legacy (CBC) package shares the
    // server's single fallback cipher. Warn when this choice would mix them.
    if (/-CBC$/.test(select.value)) {
        var others = [];
        for (var c in OVPN_CBC_IN_USE) {
            if (!OVPN_CBC_IN_USE.hasOwnProperty(c) || c === select.value) continue;
            var n = OVPN_CBC_IN_USE[c] - (excludeCounts ? (excludeCounts[c] || 0) : (ownCipher === c ? 1 : 0));
            if (n > 0) others.push(n + ' on ' + c);
        }
        if (others.length) {
            extra = '<br><strong>Heads up:</strong> older phones cannot negotiate, so all legacy packages share one server cipher. Existing legacy packages: ' + others.join(', ') + '. One group will not connect until every legacy package uses the same cipher.';
        }
    }
    notice.innerHTML = item.text + extra;
    notice.style.backgroundColor = item.bg;
    notice.style.borderColor = item.border;
    notice.style.color = item.color;
}
var ovpnEditOriginalCipher = null;
function updateEditCipherNotice() { applyCipherNotice('edit_cipher', 'edit_cipher_notice', ovpnEditOriginalCipher); }

// The "Include data-ciphers" checkbox only applies to GCM ciphers (CBC never
// uses data-ciphers at all - see buildClientPackage()). Hide + uncheck it for
// CBC so a stale checked box can't get submitted once the cipher is switched.
// presetChecked is only honored the first time the row becomes relevant for a
// given open of the form/modal (i.e. when explicitly passed in); ordinary
// user cipher changes always reset it unchecked, since it should not be
// silently carried from an unrelated cipher across a manual switch.
function updateDataCiphersRow(selectId, rowId, checkboxId, presetChecked) {
    var select = document.getElementById(selectId), row = document.getElementById(rowId), box = document.getElementById(checkboxId);
    if (!select || !row || !box) return;
    var isGcm = /-GCM$/.test(select.value);
    row.style.display = isGcm ? '' : 'none';
    if (!isGcm) {
        box.checked = false;
    } else if (typeof presetChecked !== 'undefined') {
        box.checked = presetChecked;
    }
}

(function () {
    var mainSelect = document.getElementById('ovpn_cipher');
    if (mainSelect) {
        // "Default" checkbox: checked + locked when the selected cipher already is
        // its server's default; otherwise tick it to make the selected cipher that server's new default.
        var defaultBox = document.getElementById('ovpn_cipher_default');
        var defaultText = document.getElementById('ovpn_cipher_default_text');
        var syncDefaultBox = function () {
            if (!defaultBox) return;
            var currentDefault = mainSelect.getAttribute('data-default-' + ovpnInstanceForCipher(mainSelect.value));
            var isDefault = (mainSelect.value === currentDefault);
            defaultBox.checked = isDefault;
            defaultBox.disabled = isDefault;
            if (defaultText) defaultText.textContent = isDefault ? 'Default' : 'Make default';
        };
        // Which server the chosen cipher connects to, and the address the package will carry.
        var syncTarget = function () {
            var inst = ovpnInstanceForCipher(mainSelect.value), d = OVPN_INSTANCES[inst];
            if (!d) return;
            $('#ovpn_target_label').text(d.label);
            $('#ovpn_target_hostport').text(d.ip + ':' + d.port);
            $('#ovpn_target_sip').text(d.hostIp + ':5060');
        };
        mainSelect.addEventListener('change', function () {
            applyCipherNotice('ovpn_cipher', 'ovpn_cipher_notice');
            syncDefaultBox();
            syncTarget();
            updateDataCiphersRow('ovpn_cipher', 'ovpn_data_ciphers_row', 'ovpn_include_data_ciphers');
        });
        applyCipherNotice('ovpn_cipher', 'ovpn_cipher_notice');
        syncDefaultBox();
        syncTarget();
        updateDataCiphersRow('ovpn_cipher', 'ovpn_data_ciphers_row', 'ovpn_include_data_ciphers');
    }
    var editSelect = document.getElementById('edit_cipher');
    if (editSelect) {
        editSelect.addEventListener('change', function () {
            updateEditCipherNotice();
            updateDataCiphersRow('edit_cipher', 'edit_data_ciphers_row', 'edit_include_data_ciphers');
            ovpnServerNotice('edit_server_notice', editSelect.value, ovpnEditFromInstance);
        });
        updateEditCipherNotice();
    }
    var bulkSelect = document.getElementById('bulk_cipher');
    if (bulkSelect) {
        bulkSelect.addEventListener('change', function () {
            updateBulkCipherNotice();
            updateDataCiphersRow('bulk_cipher', 'bulk_data_ciphers_row', 'bulk_include_data_ciphers');
        });
    }
    var bulkForm = document.getElementById('bulkCipherForm');
    if (bulkForm) {
        bulkForm.addEventListener('submit', function (e) {
            e.preventDefault();
            var n = $('#bulkCipherInputs input').length;
            showOvpnConfirm(
                'Change the cipher of ' + n + ' selected package(s) to ' + bulkSelect.value + '? Phones need to download the updated packages.',
                function () {
                    $('#bulkCipherModal').modal('hide');
                    showOvpnProgress('Changing ' + n + ' package(s), please wait...');
                    bulkForm.submit();
                }
            );
        });
    }
})();
// Sortable "Created Provisioning Archives" table (Extension / MAC / Cipher / Date Created).
// Purely client-side; the chosen sort is remembered in this browser.
(function () {
    var table = document.getElementById('ovpnPkgTable');
    if (!table || !table.tBodies.length) return;
    var tbody = table.tBodies[0];
    var headers = table.querySelectorAll('th.ovpn-sortable');
    var STORE_KEY = 'ovpn_mgr_pkg_sort';
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.forEach(function (r, i) { r._origIdx = i; });

    function cmpFor(key) {
        return function (a, b) {
            var av = a.getAttribute('data-' + key) || '', bv = b.getAttribute('data-' + key) || '';
            var r = 0;
            if (key === 'date') {
                r = (parseInt(av, 10) || 0) - (parseInt(bv, 10) || 0);
            } else if (key === 'ext' && /^\d+$/.test(av) && /^\d+$/.test(bv)) {
                r = parseInt(av, 10) - parseInt(bv, 10);
            } else {
                r = av < bv ? -1 : (av > bv ? 1 : 0);
            }
            return r !== 0 ? r : a._origIdx - b._origIdx;
        };
    }

    function applySort(key, dir) {
        var sorted = rows.slice().sort(cmpFor(key));
        if (dir < 0) sorted.reverse();
        sorted.forEach(function (r) { tbody.appendChild(r); });
        Array.prototype.forEach.call(headers, function (th) {
            var active = (th.getAttribute('data-sort') === key);
            var ind = th.querySelector('.ovpn-sort-ind');
            th.classList.toggle('ovpn-sorted', active);
            th.setAttribute('aria-sort', active ? (dir > 0 ? 'ascending' : 'descending') : 'none');
            if (ind) ind.textContent = active ? (dir > 0 ? '\u25B2' : '\u25BC') : '\u21C5';
        });
        try { localStorage.setItem(STORE_KEY, JSON.stringify({ key: key, dir: dir })); } catch (e) {}
    }

    var current = { key: null, dir: 1 };
    function onHeader(th) {
        var key = th.getAttribute('data-sort');
        // Newest-first is the natural first click for dates; A-Z / low-high for the rest.
        var dir = (current.key === key) ? -current.dir : (key === 'date' ? -1 : 1);
        current = { key: key, dir: dir };
        applySort(key, dir);
    }
    Array.prototype.forEach.call(headers, function (th) {
        var ind = th.querySelector('.ovpn-sort-ind');
        if (ind) ind.textContent = '\u21C5';
        th.addEventListener('click', function () { onHeader(th); });
        th.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onHeader(th); }
        });
    });

    try {
        var saved = JSON.parse(localStorage.getItem(STORE_KEY) || 'null');
        if (saved && /^(ext|mac|cipher|date)$/.test(saved.key) && (saved.dir === 1 || saved.dir === -1)) {
            current = { key: saved.key, dir: saved.dir };
            applySort(saved.key, saved.dir);
        }
    } catch (e) {}
})();
// Sortable column headers for "Connected OpenVPN Clients" and the Manage /
// Revoke Keys table, same behaviour as Created Provisioning Archives: click a
// header to sort, click again to reverse; the choice is remembered per table.
// Columns are sorted as natural text/numbers ("nat"), IPv4 address[:port]
// ("ip", falls back to text for host names) or plain text. A cell's
// data-sv attribute, when present, is the value used instead of its text.
(function () {
    function cellValue(row, col) {
        var td = row.cells[col];
        if (!td) return '';
        var sv = td.getAttribute('data-sv');
        return (sv !== null ? sv : td.textContent).replace(/\s+/g, ' ').trim();
    }
    function ipKey(v) {
        var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d+))?$/.exec(v);
        if (!m) return null;
        return (((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4]) * 65536 + (m[5] ? +m[5] : 0);
    }
    function compare(type, a, b) {
        if (type === 'ip') {
            var ka = ipKey(a), kb = ipKey(b);
            if (ka !== null && kb !== null) return ka - kb;
            if (ka !== null) return -1;
            if (kb !== null) return 1;
        }
        if (type === 'nat' || type === 'ip') {
            return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
        }
        return a < b ? -1 : (a > b ? 1 : 0);
    }
    function makeSortable(tableId, storeKey) {
        var table = document.getElementById(tableId);
        if (!table || !table.tBodies.length) return;
        var tbody = table.tBodies[0];
        var headers = table.querySelectorAll('th.ovpn-sortable');
        var rows = Array.prototype.slice.call(tbody.rows).filter(function (r) { return r.cells.length >= headers.length; });
        rows.forEach(function (r, i) { r._origIdx = i; });
        var current = { col: null, dir: 1 };

        function apply(col, dir) {
            var th0 = null;
            Array.prototype.forEach.call(headers, function (th) { if (+th.getAttribute('data-col') === col) th0 = th; });
            if (!th0) return;
            var type = th0.getAttribute('data-type') || 'text';
            var sorted = rows.slice().sort(function (a, b) {
                var r = compare(type, cellValue(a, col), cellValue(b, col));
                return r !== 0 ? r : a._origIdx - b._origIdx;
            });
            if (dir < 0) sorted.reverse();
            sorted.forEach(function (r) { tbody.appendChild(r); });
            Array.prototype.forEach.call(headers, function (th) {
                var active = (th === th0);
                var ind = th.querySelector('.ovpn-sort-ind');
                th.classList.toggle('ovpn-sorted', active);
                th.setAttribute('aria-sort', active ? (dir > 0 ? 'ascending' : 'descending') : 'none');
                if (ind) ind.textContent = active ? (dir > 0 ? '\u25B2' : '\u25BC') : '\u21C5';
            });
            try { localStorage.setItem(storeKey, JSON.stringify({ col: col, dir: dir })); } catch (e) {}
        }
        function onHeader(th) {
            var col = +th.getAttribute('data-col');
            var dir = (current.col === col) ? -current.dir : 1;
            current = { col: col, dir: dir };
            apply(col, dir);
        }
        Array.prototype.forEach.call(headers, function (th) {
            var ind = th.querySelector('.ovpn-sort-ind');
            if (ind) ind.textContent = '\u21C5';
            th.addEventListener('click', function () { onHeader(th); });
            th.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onHeader(th); }
            });
        });
        try {
            var saved = JSON.parse(localStorage.getItem(storeKey) || 'null');
            if (saved && Number.isInteger(saved.col) && (saved.dir === 1 || saved.dir === -1)) {
                current = { col: saved.col, dir: saved.dir };
                apply(saved.col, saved.dir);
            }
        } catch (e) {}
    }
    makeSortable('ovpnClientsTable', 'ovpn_mgr_clients_sort');
    makeSortable('ovpnRevokeTable', 'ovpn_mgr_revoke_sort');
})();
</script>
