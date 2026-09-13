<?php
// Initialize FreePBX environment minimally
define('FREEPBX_IS_AUTH', true);
require_once '/var/www/html/inc/bootstrap.php';

if (!isset($_SESSION['AMP_user'])) {
    die('Unauthorized access.');
}

$mac = isset($_GET['mac']) ? strtolower(preg_replace('/[^a-fA-F0-9]/', '', $_GET['mac'])) : '';
$file = "/tftpboot/{$mac}-vpn.tar";

if (!empty($mac) && file_exists($file)) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    header('Content-Description: File Transfer');
    header('Content-Type: application/x-tar');
    header('Content-Disposition: attachment; filename="' . $mac . '-vpn.tar"');
    header('Content-Length: ' . filesize($file));
    header('Pragma: public');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    readfile($file);
    exit;
} else {
    http_response_code(404);
    echo "File not found.";
    exit;
}