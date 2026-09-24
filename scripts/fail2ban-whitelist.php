<?php
/**
 * Idempotently add ovpn_mgr's OpenVPN IPv4 pool to Fail2Ban [DEFAULT] ignoreip.
 * Usage: php fail2ban-whitelist.php OPENVPN_CONF JAIL_LOCAL
 * Runs as root from setup-root.sh. PHP is used (not Python) because it is
 * always present on FreePBX, unlike python3 on some FreePBX 16 installs.
 */
if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This helper must run from the CLI.\n");
    exit(2);
}
if ($argc !== 3) {
    fwrite(STDERR, "Usage: {$argv[0]} OPENVPN_CONF JAIL_LOCAL\n");
    exit(2);
}
[$confPath, $jailPath] = [$argv[1], $argv[2]];

$confText = is_readable($confPath) ? file_get_contents($confPath) : false;
if ($confText === false) {
    fwrite(STDERR, "Cannot read OpenVPN config {$confPath}\n");
    exit(1);
}

// Find the first valid "server <network> <netmask>" line.
$network = null;
foreach (preg_split('/\r\n|\r|\n/', $confText) as $line) {
    if (!preg_match('/^\s*server\s+(\S+)\s+(\S+)/', $line, $m)) {
        continue;
    }
    $ipLong = filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? ip2long($m[1]) : false;
    $maskLong = filter_var($m[2], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? ip2long($m[2]) : false;
    if ($ipLong === false || $maskLong === false) {
        continue;
    }
    $maskBin = sprintf('%032b', $maskLong & 0xffffffff);
    if (strpos($maskBin, '01') !== false) { // non-contiguous netmask
        continue;
    }
    $network = long2ip(($ipLong & $maskLong) & 0xffffffff) . '/' . substr_count($maskBin, '1');
    break;
}
if ($network === null) {
    fwrite(STDERR, "Could not determine a valid IPv4 OpenVPN 'server <network> <netmask>' pool; Fail2Ban whitelist unchanged.\n");
    exit(1);
}

$original = '';
if (file_exists($jailPath)) {
    $read = is_readable($jailPath) ? file_get_contents($jailPath) : false;
    if ($read === false) {
        fwrite(STDERR, "Cannot read {$jailPath}\n");
        exit(1);
    }
    $original = $read;
}

$lines = ($original === '') ? [] : preg_split('/\r\n|\r|\n/', $original);
if (!empty($lines) && end($lines) === '') {
    array_pop($lines);
}

$sectionStart = $sectionEnd = null;
foreach ($lines as $idx => $line) {
    if (preg_match('/^\s*\[\s*DEFAULT\s*\]\s*(?:[;#].*)?$/i', $line)) {
        $sectionStart = $idx;
        $sectionEnd = count($lines);
        for ($j = $idx + 1; $j < count($lines); $j++) {
            if (preg_match('/^\s*\[/', $lines[$j])) {
                $sectionEnd = $j;
                break;
            }
        }
        break;
    }
}

if ($sectionStart === null) {
    if (!empty($lines) && trim(end($lines)) !== '') {
        $lines[] = '';
    }
    $lines[] = '[DEFAULT]';
    $lines[] = "ignoreip = 127.0.0.1/8 ::1 {$network}";
} else {
    $ignoreIdx = null;
    for ($idx = $sectionStart + 1; $idx < $sectionEnd; $idx++) {
        if (preg_match('/^\s*ignoreip\s*=/i', $lines[$idx])) {
            $ignoreIdx = $idx;
            break;
        }
    }
    if ($ignoreIdx === null) {
        array_splice($lines, $sectionEnd, 0, ["ignoreip = 127.0.0.1/8 ::1 {$network}"]);
    } else {
        // Keep any inline comment and all pre-existing ignore entries intact.
        $full = $lines[$ignoreIdx];
        $sep = '';
        $comment = '';
        $before = $full;
        $pos = strpos($full, '#');
        if ($pos === false) {
            $pos = strpos($full, ';');
        }
        if ($pos !== false) {
            $before = substr($full, 0, $pos);
            $sep = $full[$pos];
            $comment = substr($full, $pos + 1);
        }
        if (preg_match('/^(\s*ignoreip\s*=\s*)(.*)$/i', $before, $mm)) {
            $value = trim($mm[2]);
            $entries = $value === '' ? [] : preg_split('/\s+/', $value);
            if (!in_array($network, $entries, true)) {
                $lines[$ignoreIdx] = $mm[1] . ($value !== '' ? $value . ' ' : '') . $network;
                if ($sep !== '') {
                    $lines[$ignoreIdx] .= ' ' . $sep . $comment;
                }
            }
        }
    }
}

$updated = rtrim(implode("\n", $lines)) . "\n";
if ($updated === $original) {
    echo "Fail2Ban already includes OpenVPN pool {$network} in {$jailPath}.\n";
    echo $network . "\n";
    exit(0);
}

$dir = dirname($jailPath) ?: '.';
if (!is_dir($dir) && !mkdir($dir, 0755, true)) {
    fwrite(STDERR, "Cannot create {$dir}\n");
    exit(1);
}
if (file_exists($jailPath)) {
    $backup = $jailPath . '.ovpn_mgr.bak';
    if (!file_exists($backup)) {
        copy($jailPath, $backup);
    }
    $mode = fileperms($jailPath) & 0777;
} else {
    $mode = 0644;
}
$tmp = tempnam($dir, '.jail.local.');
if ($tmp === false || file_put_contents($tmp, $updated) === false) {
    if ($tmp !== false) { @unlink($tmp); }
    fwrite(STDERR, "Cannot write temporary file in {$dir}\n");
    exit(1);
}
chmod($tmp, $mode);
if (!rename($tmp, $jailPath)) {
    @unlink($tmp);
    fwrite(STDERR, "Cannot replace {$jailPath}\n");
    exit(1);
}
echo "Added OpenVPN pool {$network} to {$jailPath} [DEFAULT] ignoreip.\n";
echo $network . "\n";
