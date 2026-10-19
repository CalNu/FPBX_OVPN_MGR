<?php
namespace FreePBX\modules;

class Ovpn_mgr implements \BMO {
    public $freepbx;
    // NOTE: this class's own methods (getServiceStatus, buildYealinkTarball,
    // deletePackage, getGeneratedPackages) are not currently called anywhere -
    // page.ovpn_mgr.php reimplements this logic inline instead. This class
    // exists only to satisfy FreePBX's module convention (every module needs
    // a <rawname>.class.php implementing BMO). Paths kept in sync with the
    // rest of the module anyway, in case that ever changes.
    private $pkiDir = '/var/www/html/PhoneSettings/openvpn/legacy_pki';
    private $tftpDir = '/tftpboot';

    public function __construct($freepbx = null) {
        $this->freepbx = $freepbx;
    }

public function getServiceStatus() {
    $pidFile = '/var/www/html/PhoneSettings/openvpn/openvpn.pid';
    if (file_exists($pidFile)) {
        $pid = trim(file_get_contents($pidFile));
        if (!empty($pid) && posix_getpgid((int)$pid) !== false) {
            return true;
        }
    }
    // Fallback check
    exec("pgrep -f 'legacy-vpn.conf'", $pids);
    return !empty($pids);
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

    public function getGeneratedPackages() {
        $packages = [];
        if (is_dir($this->tftpDir)) {
            $files = glob("{$this->tftpDir}/*-vpn.tar");
            foreach ($files as $file) {
                $filename = basename($file);
                $mac = str_replace('-vpn.tar', '', $filename);
                $packages[] = [
                    'mac' => $mac,
                    'file' => $filename,
                    'size' => round(filesize($file) / 1024, 2) . ' KB',
                    'mtime' => date("Y-m-d H:i:s", filemtime($file))
                ];
            }
        }
        return $packages;
    }

    public function deletePackage($mac) {
        $macClean = strtolower(preg_replace('/[^a-fA-F0-9]/', '', $mac));
        if (empty($macClean)) {
            return ['success' => false, 'error' => 'Invalid MAC address provided.'];
        }

        $tarFile = "{$this->tftpDir}/{$macClean}-vpn.tar";

        if (file_exists($tarFile)) {
            exec("fuser -k " . escapeshellarg($tarFile) . " 2>&1");
            if (@unlink($tarFile)) {
                return ['success' => true];
            } else {
                return ['success' => false, 'error' => "Failed to delete file from {$tarFile}."];
            }
        }
        return ['success' => false, 'error' => 'Package file not found.'];
    }

    public function buildYealinkTarball($mac, $ext, $serverIp = '', $serverPort = '1194') {
        $macClean = strtolower(preg_replace('/[^a-fA-F0-9]/', '', $mac));
        $extClean = preg_replace('/[^0-9]/', '', $ext);

        if (empty($macClean) || empty($extClean)) {
            return ['success' => false, 'error' => 'Invalid MAC or Extension.'];
        }

        // Default IP to local server IP if omitted
        if (empty($serverIp)) {
            $serverIp = $_SERVER['SERVER_ADDR'] ?? '192.168.0.52';
        }

        // Default Port to 1194 if omitted
        $portClean = preg_replace('/[^0-9]/', '', $serverPort);
        if (empty($portClean)) {
            $portClean = '1194';
        }

        $stagingDir = "/tmp/vpn_build_{$macClean}";
        exec("rm -rf " . escapeshellarg($stagingDir));
        mkdir("{$stagingDir}/keys", 0755, true);

        $clientCert = "{$this->pkiDir}/issued/{$extClean}.crt";
        $clientKey = "{$this->pkiDir}/private/{$extClean}.key";
        $caCert = "{$this->pkiDir}/ca.crt";
        $caKey = "{$this->pkiDir}/private/ca.key";

        if (!file_exists($clientCert) || !file_exists($clientKey)) {
            $csr = "{$this->pkiDir}/{$extClean}.csr";
            $serial = time();

            exec("openssl req -new -nodes -batch -sha1 -newkey rsa:1024 -out " . escapeshellarg($csr) . " -keyout " . escapeshellarg($clientKey) . " -subj '/CN=client-{$extClean}/' 2>&1", $o1, $r1);
            if ($r1 !== 0) {
                return ['success' => false, 'error' => 'CSR creation failed: ' . implode("\n", $o1)];
            }

            exec("openssl x509 -req -days 3650 -sha1 -in " . escapeshellarg($csr) . " -CA " . escapeshellarg($caCert) . " -CAkey " . escapeshellarg($caKey) . " -set_serial {$serial} -out " . escapeshellarg($clientCert) . " 2>&1", $o2, $r2);
            if ($r2 !== 0) {
                return ['success' => false, 'error' => 'Cert signing failed: ' . implode("\n", $o2)];
            }
            @unlink($csr);
        }

        copy($caCert, "{$stagingDir}/keys/ca.crt");
        copy($clientCert, "{$stagingDir}/keys/client.crt");
        copy($clientKey, "{$stagingDir}/keys/client.key");

        // Build vpn.cnf with dynamic remote IP and port
        $vpnCnf = "client\n" .
                  "dev tun\n" .
                  "proto udp\n" .
                  "remote {$serverIp} {$portClean}\n" .
                  "resolv-retry infinite\n" .
                  "nobind\n" .
                  "persist-key\n" .
                  "persist-tun\n" .
                  "reneg-sec 0\n" .
                  "ca /config/openvpn/keys/ca.crt\n" .
                  "cert /config/openvpn/keys/client.crt\n" .
                  "key /config/openvpn/keys/client.key\n" .
                  "cipher AES-128-CBC\n" .
                  "auth SHA1\n";

        file_put_contents("{$stagingDir}/vpn.cnf", $vpnCnf);

        $outputTar = "{$this->tftpDir}/{$macClean}-vpn.tar";
        exec("cd " . escapeshellarg($stagingDir) . " && tar -cf " . escapeshellarg($outputTar) . " vpn.cnf keys/ 2>&1", $o3, $r3);
        exec("rm -rf " . escapeshellarg($stagingDir));

        if ($r3 === 0 && file_exists($outputTar)) {
            chmod($outputTar, 0775);
            return ['success' => true];
        }

        return ['success' => false, 'error' => 'Failed to create tar archive.'];
    }
}