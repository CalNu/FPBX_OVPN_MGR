<?php
namespace FreePBX\modules;

class Ovpn_mgr implements \BMO {
    public $freepbx;
    // FreePBX requires every module to ship a <rawname>.class.php implementing BMO.
    // The page itself (page.ovpn_mgr.php) does the real work; this class only
    // provides the AJAX log viewer and the module hooks FreePBX expects.

    public function __construct($freepbx = null) {
        $this->freepbx = $freepbx;
    }

    // ------------------------------------------------------------------
    // AJAX (ajax.php?module=ovpn_mgr&command=fetch_log)
    //
    // The live log viewer polls this instead of config.php. Requests to
    // config.php run FreePBX's per-page module signature check (GPG),
    // which can time out when hit every few seconds; ajax.php skips it.
    // NOTE: FreePBX's BMO loader requires this file to be named
    // Ovpn_mgr.class.php (capital O) for ajax.php to find it.
    // ------------------------------------------------------------------
    public function ajaxRequest($req, &$setting) {
        return $req === 'fetch_log';
    }

    public function ajaxHandler() {
        $command = isset($_REQUEST['command']) ? $_REQUEST['command'] : '';
        if ($command === 'fetch_log') {
            // The page passes the server whose log it shows; anything but "modern" means legacy.
            $instance = (isset($_REQUEST['instance']) && $_REQUEST['instance'] === 'modern') ? 'modern' : 'legacy';
            return ['status' => true, 'log' => $this->getLogText($instance)];
        }
        return ['status' => false, 'message' => 'Unknown command'];
    }

    public function getLogText($instance = 'legacy') {
        $webRoot = '/var/www/html';
        try {
            $cfg = \FreePBX::Config()->get('AMPWEBROOT');
            if (!empty($cfg)) { $webRoot = rtrim($cfg, '/'); }
        } catch (\Throwable $e) {}
        require_once __DIR__ . '/lib/client_ops.php';
        $baseDir = "{$webRoot}/PhoneSettings/openvpn";
        $logDir  = ovpnLogDir($baseDir, $instance === 'modern' ? 'modern' : 'legacy');
        $logFile = "{$logDir}/openvpn.log";
        if (!file_exists($logFile)) {
            return 'No log output available.';
        }
        $markerFile = "{$logDir}/.line_break_pos";
        $marker = file_exists($markerFile) ? (int)trim((string)@file_get_contents($markerFile)) : null;
        $clean = [];
        foreach (explode("\n", tailFileFromMarker($logFile, $marker, 500)) as $line) {
            if (strpos($line, 'global-message-banner') === false && strpos($line, 'Unsigned Module') === false) {
                $clean[] = strip_tags($line);
            }
        }
        return trim(implode("\n", $clean));
    }

    // FreePBX calls this for any module that has a page.* file.
    public function doConfigPageInit($page) {}

    public function install() {}
    public function uninstall() {}
    public function backup() {}
    public function restore($backup) {}
}
