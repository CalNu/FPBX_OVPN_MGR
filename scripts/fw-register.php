<?php
/**
 * ovpn_mgr/scripts/fw-register.php
 *
 * Registers every OpenVPN instance that exists (legacy and modern) with FreePBX Firewall, so a fresh
 * install is complete right after setup-root.sh and does not need a Restart from the GUI:
 *   - Services:   a custom service for the instance's UDP port (only created when missing)
 *   - Networks:   the VPN subnet in the Trusted zone, with a description (only an empty one is filled in)
 *   - Interfaces: a description for the instance's tunnel interface (tun0 legacy, tun1 modern; only an
 *                 empty one is filled in)
 * One firewall restart at the end, and only when something was added. Afterwards it checks that an
 * ACCEPT rule for each instance's UDP port really exists in iptables; if FreePBX did not produce one it
 * adds the module's own persistent rule (ovpnctl port-sync), so the port is open when this finishes.
 *
 * Runs as root from the CLI only: setup-root.sh, or `ovpnctl fw-register` through the sudoers rule.
 * Takes no arguments. Never removes or edits anything an administrator entered.
 */
if (PHP_SAPI !== 'cli' || posix_geteuid() !== 0) {
    fwrite(STDERR, "This helper must run as root from the CLI.\n");
    exit(1);
}

$bootstrap_settings = ['freepbx_auth' => false];
if (!@include_once '/etc/freepbx.conf') {
    fwrite(STDERR, "FreePBX is not installed here (/etc/freepbx.conf not found); nothing to do.\n");
    exit(0);
}
global $amp_conf;
$webRoot = rtrim((string)($amp_conf['AMPWEBROOT'] ?? '/var/www/html'), '/');
$sbin    = rtrim((string)($amp_conf['AMPSBIN'] ?? '/usr/sbin'), '/');
$fwc     = is_executable("{$sbin}/fwconsole") ? "{$sbin}/fwconsole" : '/usr/sbin/fwconsole';

try {
    if (!\FreePBX::Modules()->checkStatus('firewall')) {
        echo "FreePBX Firewall module is not enabled; nothing to do.\n";
        exit(0);
    }
    $fw = \FreePBX::Firewall();
} catch (\Throwable $e) {
    echo "FreePBX Firewall module is not usable (" . $e->getMessage() . "); nothing to do.\n";
    exit(0);
}

$instances = [
    'legacy' => ['conf' => 'legacy-vpn.conf', 'tun' => 'tun0', 'service' => 'OpenVPN Manager',          'label' => 'OpenVPN Legacy (AES-CBC) - ovpn_mgr'],
    'modern' => ['conf' => 'modern-vpn.conf', 'tun' => 'tun1', 'service' => 'OpenVPN Manager (modern)', 'label' => 'OpenVPN Modern (AES-GCM) - ovpn_mgr'],
];
$baseDir = "{$webRoot}/PhoneSettings/openvpn";
$changed = false;
$ports   = [];   // instance => UDP port, for the final iptables check

foreach ($instances as $name => $in) {
    $conf = "{$baseDir}/{$in['conf']}";
    if (!is_file($conf)) { continue; }
    $text = (string)file_get_contents($conf);

    $port = null; $cidr = null;
    if (preg_match('/^[ \t]*port[ \t]+(\d+)/mi', $text, $m)) { $port = (int)$m[1]; }
    if (preg_match('/^[ \t]*server[ \t]+((?:\d{1,3}\.){3}\d{1,3})[ \t]+((?:\d{1,3}\.){3}\d{1,3})/m', $text, $m)) {
        $ip = ip2long($m[1]); $mask = ip2long($m[2]);
        if ($ip !== false && $mask !== false) {
            $bin = sprintf('%032b', $mask & 0xffffffff);
            if (strpos($bin, '01') === false) {
                $cidr = long2ip($ip & $mask & 0xffffffff) . '/' . substr_count($bin, '1');
            }
        }
    }
    echo "[{$name}] port=" . ($port ?? '?') . " subnet=" . ($cidr ?? '?') . "\n";
    if ($port) { $ports[$name] = $port; }
    try {

    // --- Services: custom service for the UDP port -------------------------------------------------
    if ($port && method_exists($fw, 'addCustomService') && method_exists($fw, 'getAllCustomServices')) {
        $svcId = null; $svcPort = null; $svcProto = null;
        foreach ((array)$fw->getAllCustomServices() as $key => $svc) {
            $sv = (array)$svc;
            if (($sv['name'] ?? $sv['n'] ?? '') === $in['service']) {
                $svcId = $sv['id'] ?? $key;
                $cf = (array)($sv['custfw'] ?? []);
                $svcPort = isset($cf['port']) ? (string)$cf['port'] : null;
                $svcProto = isset($cf['protocol']) ? strtolower((string)$cf['protocol']) : null;
                break;
            }
        }
        if ($svcId === null) {
            $fw->addCustomService($in['service'], 'udp', $port);
            foreach ((array)$fw->getAllCustomServices() as $key => $svc) {
                $sv = (array)$svc;
                if (($sv['name'] ?? $sv['n'] ?? '') === $in['service']) { $svcId = $sv['id'] ?? $key; break; }
            }
            if ($svcId !== null && method_exists($fw, 'setCustomServiceZones')) {
                $fw->setCustomServiceZones($svcId, ['external', 'internal', 'other']);
            }
            echo "  added custom service '{$in['service']}' udp/{$port}\n";
            $changed = true;
        } elseif (($svcPort !== null && $svcPort !== (string)$port) || ($svcProto !== null && $svcProto !== 'udp')) {
            // Exists, but for another port (an older install, or the port was changed): correct it.
            $fw->editCustomService($svcId, $in['service'], 'udp', $port);
            echo "  custom service '{$in['service']}' was {$svcProto}/{$svcPort}; set to udp/{$port}\n";
            $changed = true;
        } else {
            echo "  custom service '{$in['service']}' already udp/{$port}\n";
        }
    }

    // --- Networks: trusted zone + description ------------------------------------------------------
    if ($cidr) {
        $maps = (array)$fw->getConfig('networkmaps');
        if (($maps[$cidr] ?? '') !== 'trusted') {
            $out = []; $rc = 0;
            exec(escapeshellarg($fwc) . ' firewall add trusted ' . escapeshellarg($cidr) . ' 2>&1', $out, $rc);
            echo "  added {$cidr} to Trusted (exit {$rc})\n";
            if ($rc === 0) { $changed = true; }
        }
        $descs = $fw->getConfig('descriptions', 'network');
        $descs = is_array($descs) ? $descs : [];
        if (trim((string)($descs[$cidr] ?? '')) === '') {
            $descs[$cidr] = $in['label'];
            $fw->setConfig('descriptions', $descs, 'network');
            echo "  described {$cidr}: {$in['label']}\n";
        }
    }

    // --- Interfaces: tunnel interface description ---------------------------------------------------
    $jsonFile = '/var/spool/asterisk/firewall/interface-zones.json';
    if (is_file($jsonFile)) {
        $d = json_decode((string)file_get_contents($jsonFile), true);
        $d = is_array($d) ? $d : [];
        $cur = trim((string)($d[$in['tun']]['DESCRIPTION'] ?? ''));
        if ($cur === '' || $cur === 'unset') {
            $e = (isset($d[$in['tun']]) && is_array($d[$in['tun']])) ? $d[$in['tun']] : [];
            if (empty($e['ZONE'])) { $e['ZONE'] = 'internal'; }
            $e['DESCRIPTION'] = $in['label'];
            $d[$in['tun']] = $e;
            $tmp = $jsonFile . '.' . getmypid();
            if (file_put_contents($tmp, json_encode($d)) !== false) {
                @chown($tmp, fileowner($jsonFile)); @chgrp($tmp, filegroup($jsonFile));
                @chmod($tmp, fileperms($jsonFile) & 0777);
                rename($tmp, $jsonFile);
                echo "  described {$in['tun']}: {$in['label']}\n";
            }
        }
    }
    } catch (\Throwable $e) {
        // One failing step must not stop the other instance or the firewall restart.
        echo "  ERROR for {$name}: " . $e->getMessage() . "\n";
    }
}

if ($changed) {
    echo "Restarting FreePBX Firewall to apply the changes...\n";
    passthru(escapeshellarg($fwc) . ' firewall restart 2>&1');
} else {
    echo "Firewall services, networks and descriptions are already in place.\n";
}

// --- Verify: is each instance's UDP port really accepted by iptables? ----------------------------
// FreePBX Firewall builds its rules from the custom service, but it may be disabled, still starting, or
// not produce a rule for it. The check looks for any UDP ACCEPT-style rule naming the port.
$ipt = [];
exec('iptables-save 2>/dev/null', $ipt, $iptRc);
if ($iptRc !== 0 || !$ipt) {
    echo "iptables-save is not available; skipping the open-port check.\n";
    exit(0);
}
$portOpen = function ($port) use ($ipt) {
    foreach ($ipt as $l) {
        if (strpos($l, '-A ') !== 0 || !preg_match('/-p udp\b/', $l)) { continue; }
        if (!preg_match('/--dports?\s+(\S+)/', $l, $m)) { continue; }
        if (!in_array((string)$port, explode(',', $m[1]), true)) { continue; }
        if (preg_match('/-j\s+(DROP|REJECT)\b/', $l)) { continue; }
        return true;
    }
    return false;
};
foreach ($ports as $name => $port) {
    if ($portOpen($port)) {
        echo "[{$name}] udp/{$port}: open in iptables.\n";
        continue;
    }
    echo "[{$name}] udp/{$port}: NO accepting rule found - adding the module's own persistent rule.\n";
    $out = []; $rc = 0;
    exec(escapeshellarg(__DIR__ . '/ovpnctl') . ' port-sync ' . (int)$port . ' ' . escapeshellarg($name) . ' 2>&1', $out, $rc);
    echo "  ovpnctl port-sync exit {$rc}" . ($out ? ': ' . implode(' ', $out) : '') . "\n";
}
exit(0);
