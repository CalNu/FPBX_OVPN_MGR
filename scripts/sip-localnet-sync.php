<?php
/**
 * Idempotently add ovpn_mgr's OpenVPN pool to FreePBX SIP Settings localnets.
 * Runs only as root via setup-root.sh or the restricted ovpnctl sudo wrapper.
 */
if (PHP_SAPI !== 'cli' || posix_geteuid() !== 0) {
    fwrite(STDERR, "This helper must run as root from the CLI.\n");
    exit(1);
}
$conf = $argv[1] ?? '';
if ($conf === '' || !is_file($conf) || !is_readable($conf)) {
    fwrite(STDERR, "OpenVPN config is missing or unreadable.\n");
    exit(1);
}
$text = file_get_contents($conf);
if (!preg_match('/^[ \\t]*server[ \\t]+((?:\\d{1,3}\\.){3}\\d{1,3})[ \\t]+((?:\\d{1,3}\\.){3}\\d{1,3})(?:[ \\t#]|$)/m', $text, $m)) {
    fwrite(STDERR, "Could not parse OpenVPN server network/netmask.\n");
    exit(1);
}
$ipLong = ip2long($m[1]);
$maskLong = ip2long($m[2]);
if ($ipLong === false || $maskLong === false) {
    fwrite(STDERR, "Invalid IPv4 network or netmask in OpenVPN config.\n");
    exit(1);
}
$maskBin = sprintf('%032b', $maskLong & 0xffffffff);
if (strpos($maskBin, '01') !== false) {
    fwrite(STDERR, "OpenVPN netmask is not contiguous.\n");
    exit(1);
}
$prefix = substr_count($maskBin, '1');
$networkLong = ($ipLong & $maskLong) & 0xffffffff;
$networkIp = long2ip($networkLong);
$target = ['net' => $networkIp, 'mask' => (string)$prefix];

// Remember only the exact entry this module previously inserted, so subnet
// changes can remove that stale entry without deleting administrator networks.
$stateDir = '/etc/ovpn_mgr';
$stateFile = $stateDir . '/sip-localnet-managed.json';
$previousManaged = null;
if (is_readable($stateFile)) {
    $state = json_decode((string)file_get_contents($stateFile), true);
    if (is_array($state) && isset($state['net'], $state['mask']) &&
        filter_var($state['net'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
        ctype_digit((string)$state['mask']) && (int)$state['mask'] >= 0 && (int)$state['mask'] <= 32) {
        $previousManaged = ['net' => (string)$state['net'], 'mask' => (string)(int)$state['mask']];
    }
}

$freepbxConf = '/etc/freepbx.conf';
if (!is_readable($freepbxConf)) {
    fwrite(STDERR, "FreePBX bootstrap /etc/freepbx.conf not found.\n");
    exit(1);
}
require_once $freepbxConf;
if (!class_exists('FreePBX')) {
    fwrite(STDERR, "FreePBX class unavailable after bootstrap.\n");
    exit(1);
}
try {
    $freepbx = FreePBX::Create();
    $ss = $freepbx->Sipsettings;
    $localnets = $ss->getConfig('localnets');
    if (is_string($localnets)) {
        $decoded = json_decode($localnets, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) $localnets = $decoded;
    }
    if (!is_array($localnets)) $localnets = [];
    $localnetsBefore = $localnets;

    // Remove only the exact stale entry previously recorded as module-managed.
    // Other Local Networks are administrator-owned and must remain untouched.
    if ($previousManaged !== null &&
        ($previousManaged['net'] !== $target['net'] || $previousManaged['mask'] !== $target['mask'])) {
        $localnets = array_values(array_filter($localnets, static function ($entry) use ($previousManaged) {
            if (!is_array($entry) || !isset($entry['net'], $entry['mask'])) return true;
            $net = (string)$entry['net'];
            $mask = (string)$entry['mask'];
            if (strpos($mask, '.') !== false) {
                $maskLong = ip2long($mask);
                if ($maskLong === false) return true;
                $maskBin = sprintf('%032b', $maskLong & 0xffffffff);
                if (strpos($maskBin, '01') !== false) return true;
                $mask = (string)substr_count($maskBin, '1');
            }
            return !($net === $previousManaged['net'] && $mask === $previousManaged['mask']);
        }));
    }

    // If an existing local network already contains the VPN pool, it is covered.
    $covered = false;
    foreach ($localnets as $entry) {
        if (!is_array($entry) || empty($entry['net']) || !isset($entry['mask'])) continue;
        $existingIp = ip2long((string)$entry['net']);
        if ($existingIp === false) continue;
        $existingMaskRaw = (string)$entry['mask'];
        if (strpos($existingMaskRaw, '.') !== false) {
            $existingMask = ip2long($existingMaskRaw);
            if ($existingMask === false) continue;
            $existingMaskBin = sprintf('%032b', $existingMask & 0xffffffff);
            if (strpos($existingMaskBin, '01') !== false) continue;
            $existingPrefix = substr_count($existingMaskBin, '1');
        } else {
            if (!ctype_digit($existingMaskRaw) || (int)$existingMaskRaw < 0 || (int)$existingMaskRaw > 32) continue;
            $existingPrefix = (int)$existingMaskRaw;
            $existingMask = $existingPrefix === 0 ? 0 : ((0xffffffff << (32 - $existingPrefix)) & 0xffffffff);
        }
        if ($existingPrefix <= $prefix && (($networkLong & $existingMask) === (($existingIp & $existingMask) & 0xffffffff))) {
            $covered = true;
            break;
        }
    }
    $targetIsManaged = ($previousManaged !== null &&
        $previousManaged['net'] === $target['net'] && $previousManaged['mask'] === $target['mask']);
    if (!$covered) {
        $localnets[] = $target;
        $targetIsManaged = true;
    }

    // fwconsole reload rebuilds chan_sip/PJSIP config and is expensive (often
    // several seconds). Only pay for it when the localnets array we're about
    // to persist actually differs from what's already in the DB - re-saving
    // identical settings (the common case) shouldn't trigger a full reload.
    $localnetsChanged = (
        json_encode(array_values($localnetsBefore), JSON_UNESCAPED_SLASHES) !==
        json_encode(array_values($localnets), JSON_UNESCAPED_SLASHES)
    );

    if ($localnetsChanged) {
        $ss->setConfig('localnets', $localnets);
    }
    if ($covered) {
        echo "OpenVPN pool {$networkIp}/{$prefix} is covered by FreePBX SIP Settings Local Networks.\n";
    } else {
        echo "Synchronized OpenVPN pool {$networkIp}/{$prefix} in FreePBX SIP Settings Local Networks.\n";
    }
    if ($localnetsChanged) {
        // Don't reload here - just flag FreePBX the same way every other
        // module does (needreload(), which sets admin.need_reload=true in
        // the DB), so the normal orange/red "Apply Config" bar shows up and
        // the admin applies it on their own schedule/batches it with other
        // pending changes, same as the rest of the PBX. This is a single
        // fast DB write, not a multi-second reload.
        if (function_exists('needreload')) {
            needreload();
            echo "Local Networks updated; flagged FreePBX for Apply Config.\n";
        } else {
            // needreload() should always be loaded by the /etc/freepbx.conf
            // bootstrap above, but if some environment doesn't have it,
            // set the identical flag directly rather than silently leaving
            // the change unflagged.
            $flaggedDirectly = false;
            try {
                $freepbx->Database->exec("UPDATE admin SET value = 'true' WHERE variable = 'need_reload'");
                $flaggedDirectly = true;
            } catch (Throwable $e) {
                // Fall through to the full reload below as a last resort -
                // slower, but guarantees the change actually takes effect
                // instead of silently sitting unapplied.
            }
            if ($flaggedDirectly) {
                echo "Local Networks updated; flagged FreePBX for Apply Config.\n";
            } else {
                exec('fwconsole reload 2>&1', $reloadOutput, $reloadCode);
                if ($reloadCode !== 0) {
                    fwrite(STDERR, "WARNING: local network was saved, but fwconsole reload failed:\n" . implode("\n", $reloadOutput) . "\n");
                    exit(2);
                }
                echo "FreePBX configuration reloaded.\n";
            }
        }
    } else {
        echo "Local Networks unchanged; nothing to flag.\n";
    }
    if (!is_dir($stateDir) && !@mkdir($stateDir, 0750, true) && !is_dir($stateDir)) {
        throw new RuntimeException('Could not create ovpn_mgr state directory for SIP Local Networks tracking.');
    }
    if ($targetIsManaged) {
        $stateTmp = $stateFile . '.tmp';
        $stateJson = json_encode(['net' => $networkIp, 'mask' => (string)$prefix], JSON_UNESCAPED_SLASHES) . "\n";
        if (@file_put_contents($stateTmp, $stateJson, LOCK_EX) === false || !@rename($stateTmp, $stateFile)) {
            @unlink($stateTmp);
            throw new RuntimeException('Could not persist managed SIP Local Networks state.');
        }
        @chmod($stateFile, 0600);
    } elseif (is_file($stateFile) && !@unlink($stateFile)) {
        throw new RuntimeException('Could not clear stale managed SIP Local Networks state.');
    }
    echo "SIP_LOCALNET_SYNC_OK\n";
} catch (Throwable $e) {
    fwrite(STDERR, "SIP Local Networks sync failed: " . $e->getMessage() . "\n");
    exit(1);
}
