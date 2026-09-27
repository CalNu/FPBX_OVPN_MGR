<?php
/**
 * ovpn_mgr/scripts/kill-client.php <management_socket_path> <client_id>
 *
 * Tiny, dependency-free client for OpenVPN's line-based management
 * protocol (https://openvpn.net/community-resources/management-interface/),
 * used only to send a single "client-kill <CID>" command and report
 * whether it succeeded. client-kill targets one specific connected
 * session by its status-file Client ID, rather than "kill <CN>" (which
 * would drop every session sharing that common name) - the server no
 * longer sets duplicate-cn, but this stays precise on purpose.
 *
 * Invoked exclusively by `ovpnctl kill-client <cid>`, itself only
 * reachable via the 'asterisk' sudoers rule installed by setup-root.sh.
 * Never reachable directly from a web request, and re-validates its own
 * argument regardless.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "cli only\n");
    exit(1);
}

$sockPath = $argv[1] ?? '';
$cid      = $argv[2] ?? '';

if ($sockPath === '' || !preg_match('/^[0-9]{1,10}$/', (string)$cid)) {
    fwrite(STDERR, "usage: kill-client.php <management_socket_path> <client_id>\n");
    exit(1);
}
if (!file_exists($sockPath)) {
    fwrite(STDERR, "management socket not found: {$sockPath} (is OpenVPN running?)\n");
    exit(1);
}

$fp = @stream_socket_client("unix://{$sockPath}", $errno, $errstr, 5);
if (!$fp) {
    fwrite(STDERR, "connect failed: {$errstr}\n");
    exit(1);
}
stream_set_timeout($fp, 5);

function readUntil($fp, array $markers, $timeoutSeconds) {
    $buf = '';
    $deadline = microtime(true) + $timeoutSeconds;
    while (!feof($fp) && microtime(true) < $deadline) {
        $chunk = fread($fp, 4096);
        if ($chunk === false || $chunk === '') {
            $meta = stream_get_meta_data($fp);
            if (!empty($meta['timed_out'])) { break; }
            usleep(50000);
            continue;
        }
        $buf .= $chunk;
        foreach ($markers as $marker) {
            if (strpos($buf, $marker) !== false) {
                return $buf;
            }
        }
    }
    return $buf;
}

// Drain the unsolicited ">INFO:OpenVPN Management Interface Version ..."
// banner every new connection gets before a command can be sent.
readUntil($fp, [">INFO:"], 5);

fwrite($fp, "client-kill {$cid}\n");
$response = readUntil($fp, ["SUCCESS:", "ERROR:"], 5);

fwrite($fp, "quit\n");
fclose($fp);

echo trim($response) . "\n";
exit(strpos($response, 'SUCCESS:') !== false ? 0 : 1);
