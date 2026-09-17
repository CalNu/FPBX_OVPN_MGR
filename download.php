<?php
/**
 * download.php
 *
 * NOTE ON CURRENT USE: as of this rewrite, nothing in page.ovpn_mgr.php
 * links to this script anymore - generated packages are served as plain
 * static files under /PhoneSettings/vpnkeys/ (see the "Created
 * Provisioning Archives" table), because phones fetch their own
 * provisioning package unauthenticated and can't do a FreePBX login.
 * That static-file path is inherently "secret filename" security, which
 * is why generate_package now appends a random token to each filename
 * instead of just "<mac>_<ext>_ovpn.tar" - a predictable name was the
 * real practical exposure, not this script.
 *
 * This script is kept (in case something still calls it, or you want to
 * route human/admin downloads through it later) but hardened:
 *   - input is strictly validated before touching the filesystem
 *   - the resolved path is verified to stay inside the expected directory
 *     (defense in depth even though the regex already blocks traversal)
 *   - a session is required, matching the rest of the FreePBX admin UI
 *
 * What this does NOT do: verify the session's user actually holds
 * ovpn_mgr module permissions specifically (as opposed to being any
 * logged-in FreePBX user). That requires calling your installed
 * FreePBX version's own ACL/Userman API, and I didn't want to guess at
 * an internal method name and give you a false sense of security. If
 * you tell me your FreePBX version I can wire in the exact call - until
 * then, don't rely on this script alone as the access boundary for
 * anything sensitive.
 */

if (!defined('FREEPBX_IS_AUTH')) {
    require_once '/var/www/html/config.php';
}

if (empty($_SESSION['AMP_user'])) {
    http_response_code(403);
    die('Access Denied.');
}

$tftpDir = '/tftpboot';
$mac = strtoupper(preg_replace('/[^a-fA-F0-9]/', '', (string)($_GET['mac'] ?? '')));

if (strlen($mac) !== 12) {
    http_response_code(400);
    die('Invalid MAC address.');
}

$filename = "{$mac}-vpn.tar";
$requestedPath = "{$tftpDir}/{$filename}";

// Defense in depth: even though $mac is already restricted to hex chars
// above (so no "../" is possible), confirm the resolved real path is
// still inside $tftpDir before ever opening it.
$realBase = realpath($tftpDir);
$realTarget = realpath($requestedPath);

if ($realBase === false || $realTarget === false || strpos($realTarget, $realBase . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(404);
    die('File not found.');
}

if (!is_file($realTarget)) {
    http_response_code(404);
    die('File not found.');
}

header('Content-Description: File Transfer');
header('Content-Type: application/x-tar');
header('Content-Disposition: attachment; filename="' . basename($realTarget) . '"');
header('Content-Length: ' . filesize($realTarget));
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

readfile($realTarget);
exit();
