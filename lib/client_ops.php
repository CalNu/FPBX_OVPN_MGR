<?php
/**
 * ovpn_mgr/lib/client_ops.php
 *
 * Shared client-certificate / client-package operations for the legacy
 * OpenVPN PKI this module manages under PhoneSettings/openvpn/legacy_pki.
 *
 * This file is intentionally a plain function library with NO top-level
 * side effects (no output, no action routing, no session/CSRF handling)
 * so it is safe for any code to require_once() - both page.ovpn_mgr.php
 * (this module's own admin UI) and other FreePBX modules that want to
 * generate or revoke an OpenVPN client package without reimplementing
 * this module's PKI logic themselves.
 *
 * Callers are responsible for:
 *   - Deciding whether ovpn_mgr is installed/enabled before requiring
 *     this file (see ovpn_mgr_client_ops_path() below for a helper).
 *   - Resolving the paths these functions take as parameters (see
 *     ovpn_mgr_resolve_paths() below - it derives every path from
 *     AMPWEBROOT the same way install.php / page.ovpn_mgr.php do).
 *   - Any authorization/CSRF checks appropriate to their own context;
 *     none of that is duplicated here.
 */

if (!defined('OVPN_MGR_CLIENT_OPS_LOADED')) {
    define('OVPN_MGR_CLIENT_OPS_LOADED', 1);

    /**
     * Returns the absolute path to this file inside an ovpn_mgr module
     * install, given AMPWEBROOT. Callers use this (plus is_dir()/
     * file_exists() checks against the module directory and this path)
     * to confirm ovpn_mgr is actually present before requiring it -
     * this helper does not itself check the module's enabled status.
     */
    function ovpn_mgr_client_ops_path($ampWebRoot) {
        $ampWebRoot = rtrim($ampWebRoot, '/');
        return "{$ampWebRoot}/admin/modules/ovpn_mgr/lib/client_ops.php";
    }

    /**
     * Derives paths under the real AMPWEBROOT/PhoneSettings directory.
     * Callers reject a symlinked PhoneSettings path so private data stays
     * out of /tftpboot.
     */
    function ovpn_mgr_resolve_paths($ampWebRoot) {
        $ampWebRoot = rtrim($ampWebRoot, '/');
        $phoneSettingsDir = "{$ampWebRoot}/PhoneSettings";
        $baseDir = "{$phoneSettingsDir}/openvpn";
        $pkiDir  = "{$baseDir}/legacy_pki";

        return [
            'ampWebRoot'        => $ampWebRoot,
            'phoneSettingsDir'  => $phoneSettingsDir,
            'baseDir'           => $baseDir,
            'pkgDir'            => "{$phoneSettingsDir}/vpnkeys",
            'pkiDir'            => $pkiDir,
            'serverConf'        => "{$baseDir}/legacy-vpn.conf",
            'crlFile'           => "{$pkiDir}/crl.pem",
            'serverKey'         => "{$pkiDir}/private/server.key",
            'ovpnctl'           => "{$ampWebRoot}/admin/modules/ovpn_mgr/scripts/ovpnctl",
        ];
    }

    function tailFile($path, $lines = 200, $maxBytes = 2000000) {
        if (!file_exists($path)) { return ''; }
        $size = filesize($path);
        if ($size <= $maxBytes) {
            $content = (string)@file_get_contents($path);
        } else {
            $fp = @fopen($path, 'r');
            if (!$fp) { return ''; }
            fseek($fp, -$maxBytes, SEEK_END);
            $content = (string)fread($fp, $maxBytes);
            fclose($fp);
        }
        $arr = explode("\n", $content);
        return implode("\n", array_slice($arr, -$lines));
    }

    function getOpenVpnVersion() {
        $openvpnBin = file_exists('/usr/sbin/openvpn') ? '/usr/sbin/openvpn' : '/usr/local/sbin/openvpn';
        exec(escapeshellarg($openvpnBin) . " --version 2>&1", $output);
        if (!empty($output[0]) && preg_match('/OpenVPN\s+([0-9]+\.[0-9]+\.[0-9]+)/i', $output[0], $matches)) {
            return $matches[1];
        }
        return '2.4.0';
    }

    function getActiveServerSettings($serverConf) {
        $ip = $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname()) ?? '127.0.0.1';
        $port = '1194';
        $hostIp = '10.8.0.1';
        $netMask = '255.255.255.0';

        if (file_exists($serverConf)) {
            $content = (string)@file_get_contents($serverConf);
            if (preg_match('/^[ \t]*port[ \t]+(\d+)(?:[ \t]+#.*)?[ \t]*$/mi', $content, $mPort)) {
                $port = trim($mPort[1]);
            }
            if (preg_match('/^# client-remote-host (.+)/m', $content, $mIp)) {
                $ip = trim($mIp[1]);
            }
            if (preg_match('/^# vpn-host-ip (.+)/m', $content, $mHost)) {
                $hostIp = trim($mHost[1]);
            } elseif (preg_match('/^server\s+([0-9\.]+)\s+([0-9\.]+)/m', $content, $mNet)) {
                $parsedNet = trim($mNet[1]);
                $longNet = ip2long($parsedNet);
                if ($longNet !== false) {
                    $hostIp = long2ip($longNet + 1);
                }
            }
            if (preg_match('/^server\s+([0-9\.]+)\s+([0-9\.]+)/m', $content, $mNet)) {
                $netMask = trim($mNet[2]);
            }
        }
        return ['ip' => $ip, 'port' => $port, 'host_ip' => $hostIp, 'net_mask' => $netMask];
    }

    /**
     * Issues (if missing) a client cert/key under $pkiDir for $ext, and
     * builds the .tar package a Yealink/legacy client expects at
     * $pkgDir/{mac}_{ext}_ovpn.tar. Returns the tar path on success, or
     * null on failure. This is ovpn_mgr's own client-generation logic -
     * used by this module's "Generate Package" button and by any other
     * module (e.g. yealink_epm's per-device VPN toggle) that wants a
     * package built the same way, against the same PKI, instead of
     * maintaining a second implementation.
     */
    function buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $serverIp, $port, $cipher = "AES-128-CBC") {
        $allowedCiphers = ["AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM"];
        if (!in_array($cipher, $allowedCiphers, true)) { $cipher = "AES-128-CBC"; }
        if (!file_exists($pkgDir)) {
            @mkdir($pkgDir, 0775, true);
        }

        $clientKey = "{$pkiDir}/private/{$ext}.key";
        $clientCrt = "{$pkiDir}/issued/{$ext}.crt";
        $clientCsr = "{$pkiDir}/{$ext}.csr";

        if (!file_exists($clientCrt)) {
            exec("openssl req -new -nodes -batch -sha1 -newkey rsa:1024 -out " . escapeshellarg($clientCsr) . " -keyout " . escapeshellarg($clientKey) . " -subj " . escapeshellarg("/CN={$ext}/") . " 2>&1");
            exec("openssl x509 -req -days 3650 -sha1 -in " . escapeshellarg($clientCsr) . " -CA " . escapeshellarg("{$pkiDir}/ca.crt") . " -CAkey " . escapeshellarg("{$pkiDir}/private/ca.key") . " -set_serial " . random_int(100, 99999) . " -out " . escapeshellarg($clientCrt) . " 2>&1");
            @unlink($clientCsr);
        }

        $buildDir = "{$baseDir}/build_{$ext}";
        $keysSubDir = "{$buildDir}/keys";
        @mkdir($keysSubDir, 0775, true);

        @copy("{$pkiDir}/ca.crt", "{$keysSubDir}/ca.crt");
        @copy($clientCrt, "{$keysSubDir}/client.crt");
        @copy($clientKey, "{$keysSubDir}/client.key");

        // Legacy phones (AES-128-CBC) run an OpenVPN build that predates
        // data-ciphers / data-ciphers-fallback and rejects them as unknown
        // options, so those two lines are only emitted for other ciphers.
        $dataCipherLines = ($cipher === "AES-128-CBC")
            ? ""
            : "data-ciphers {$cipher}\n" . "data-ciphers-fallback {$cipher}\n";

        $vpnCnf = "client\n"
                . "nobind\n"
                . "remote {$serverIp} {$port}\n"
                . "proto udp\n"
                . "dev tun\n"
                . "ca /config/openvpn/keys/ca.crt\n"
                . "cert /config/openvpn/keys/client.crt\n"
                . "key /config/openvpn/keys/client.key\n"
                . "cipher {$cipher}\n"
                . $dataCipherLines
                . "auth SHA1\n"
                . "verb 3\n"
                . "explicit-exit-notify 0\n"
                . "script-security 2\n";
        @file_put_contents("{$buildDir}/vpn.cnf", $vpnCnf);

        $members = [];
        foreach (['keys', 'vpn.cnf'] as $member) {
            if (file_exists("{$buildDir}/{$member}")) {
                $members[] = $member;
            }
        }

        $tarPath = "{$pkgDir}/{$mac}_{$ext}_ovpn.tar";

        foreach (glob("{$pkgDir}/{$mac}_{$ext}_*_ovpn.tar") as $oldTokenPkg) {
            if (basename($oldTokenPkg) !== basename($tarPath)) {
                @unlink($oldTokenPkg);
            }
        }

        $tarCmd = "tar -cf " . escapeshellarg($tarPath) . " -C " . escapeshellarg($buildDir);
        foreach ($members as $member) {
            $tarCmd .= ' ' . escapeshellarg($member);
        }
        exec($tarCmd . ' 2>&1', $tarOut, $tarRc);

        $ok = ($tarRc === 0 && file_exists($tarPath));
        if ($ok) {
            @chmod($tarPath, 0644);
        } else {
            @unlink($tarPath);
        }

        exec("rm -rf " . escapeshellarg($buildDir));
        return $ok ? $tarPath : null;
    }

    /**
     * Revokes $revokeExt's client cert against ovpn_mgr's own CA,
     * regenerates crl.pem, wires crl-verify into $serverConf if it
     * isn't already there, deletes the cert/key and any built packages
     * for that extension. This is the ONLY correct way to revoke a
     * client issued by this module's PKI - the daemon ($ovpnctl / the
     * openvpn process it manages) checks $crlFile, so anything that
     * deletes a client's cert/key without going through this function
     * leaves a still-valid, still-connectable client as far as OpenVPN
     * itself is concerned.
     */
    function revokeExtension($pkiDir, $serverConf, $crlFile, $pkgDir, $revokeExt) {
        $targetCrt = "{$pkiDir}/issued/{$revokeExt}.crt";
        $targetKey = "{$pkiDir}/private/{$revokeExt}.key";

        if (!file_exists($targetCrt)) {
            return;
        }

        $tmpCnf = "{$pkiDir}/crl_openssl.cnf";
        $cnfData = "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {$pkiDir}\ndefault_md = sha256\n";
        @file_put_contents($tmpCnf, $cnfData);

        if (!file_exists("{$pkiDir}/index.txt")) { @touch("{$pkiDir}/index.txt"); }
        if (!file_exists("{$pkiDir}/crlnumber")) { @file_put_contents("{$pkiDir}/crlnumber", "01\n"); }

        exec("OPENSSL_CONF=" . escapeshellarg($tmpCnf) . " openssl ca -revoke " . escapeshellarg($targetCrt) . " -keyfile " . escapeshellarg("{$pkiDir}/private/ca.key") . " -cert " . escapeshellarg("{$pkiDir}/ca.crt") . " -config " . escapeshellarg($tmpCnf) . " 2>&1");
        exec("OPENSSL_CONF=" . escapeshellarg($tmpCnf) . " openssl ca -gencrl -keyfile " . escapeshellarg("{$pkiDir}/private/ca.key") . " -cert " . escapeshellarg("{$pkiDir}/ca.crt") . " -out " . escapeshellarg($crlFile) . " -config " . escapeshellarg($tmpCnf) . " 2>&1");
        @unlink($tmpCnf);

        $confContent = (string)@file_get_contents($serverConf);
        if (strpos($confContent, 'crl-verify') === false) {
            $confContent .= "\ncrl-verify {$crlFile}\n";
            @file_put_contents($serverConf, $confContent);
        }

        @unlink($targetCrt);
        @unlink($targetKey);

        foreach (glob("{$pkgDir}/*_{$revokeExt}_*_ovpn.tar") as $matchingTar) { @unlink($matchingTar); }
        foreach (glob("{$pkgDir}/*_{$revokeExt}_ovpn.tar") as $matchingTar) { @unlink($matchingTar); }
    }

    /**
     * Starts the daemon via the scoped, sudoers-limited ovpnctl helper
     * (a no-op if setup-root.sh was never run - see that script). Also
     * makes sure crl.pem exists before start so a freshly-installed
     * server doesn't start without one, and normalizes serverConf for
     * the installed OpenVPN version.
     */
    function startOpenVpnServer($ovpnctl, $serverConf, $baseDir, $serverKey) {
        $logDir = "{$baseDir}/logs";
        $logFile = "{$logDir}/openvpn.log";
        $pkiDir = "{$baseDir}/legacy_pki";
        $crlFile = "{$pkiDir}/crl.pem";

        if (!file_exists($logDir)) {
            @mkdir($logDir, 0775, true);
        }

        if (file_exists($logFile) && filesize($logFile) > 5242880) {
            $tail = tailFile($logFile, 2000);
            @file_put_contents($logFile, $tail . "\n");
        }

        if (!file_exists($crlFile) && file_exists("{$pkiDir}/ca.crt") && file_exists("{$pkiDir}/private/ca.key")) {
            if (!file_exists("{$pkiDir}/index.txt")) { @touch("{$pkiDir}/index.txt"); }
            if (!file_exists("{$pkiDir}/crlnumber")) { @file_put_contents("{$pkiDir}/crlnumber", "01\n"); }

            $tmpCnf = "{$pkiDir}/crl_openssl.cnf";
            $cnfData = "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {$pkiDir}\ndefault_md = sha256\n";
            @file_put_contents($tmpCnf, $cnfData);

            exec("OPENSSL_CONF=" . escapeshellarg($tmpCnf) . " openssl ca -gencrl -keyfile " . escapeshellarg("{$pkiDir}/private/ca.key") . " -cert " . escapeshellarg("{$pkiDir}/ca.crt") . " -out " . escapeshellarg($crlFile) . " -config " . escapeshellarg($tmpCnf) . " 2>&1");
            @unlink($tmpCnf);
        }

        $installedVersion = getOpenVpnVersion();
        $isLegacy = version_compare($installedVersion, '2.5.0', '<');

        if (file_exists($serverConf)) {
            $lines = explode("\n", (string)@file_get_contents($serverConf));
            $cleanLines = [];
            foreach ($lines as $line) {
                $trimmed = trim($line);
                if (strpos($trimmed, 'crl-verify') === 0 && !file_exists($crlFile)) {
                    continue;
                }
                if ($isLegacy) {
                    if (strpos($trimmed, 'data-ciphers') === 0 || strpos($trimmed, 'data-ciphers-fallback') === 0 ||
                        strpos($trimmed, 'providers') === 0 || strpos($trimmed, 'ignore-unknown-option') === 0) {
                        continue;
                    }
                } else {
                    if (strpos($trimmed, 'ncp-disable') === 0) {
                        continue;
                    }
                }
                $cleanLines[] = $line;
            }
            $cleanContent = implode("\n", $cleanLines);

            if ($isLegacy) {
                if (strpos($cleanContent, 'cipher ') === false) {
                    $cleanContent .= "\ncipher AES-128-CBC\n";
                }
            } else {
                if (strpos($cleanContent, 'data-ciphers ') === false) {
                    $cleanContent .= "\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305\n";
                }
            }
            if (strpos($cleanContent, 'verb ') === false) {
                $cleanContent .= "\nverb 3\n";
            }
            @file_put_contents($serverConf, $cleanContent);
        }

        if (file_exists($serverKey)) {
            @chmod($serverKey, 0600);
        }

        exec('sudo -n ' . escapeshellarg($ovpnctl) . ' start 2>&1', $output, $returnCode);
        if ($returnCode !== 0 && !empty($output)) {
            @file_put_contents($logFile, "\n[GUI START ATTEMPT Exit Code: {$returnCode}]\n" . implode("\n", $output) . "\n", FILE_APPEND);
        }
    }

    function stopOpenVpnServer($ovpnctl) {
        exec('sudo -n ' . escapeshellarg($ovpnctl) . ' stop 2>&1');
        clearstatcache();
    }

    /**
     * Convenience wrapper: revoke $ext, then restart the daemon the same
     * way ovpn_mgr's own "Revoke" button does (skipped if the admin has
     * deliberately stopped the server, tracked by the .stopped sentinel
     * file under $baseDir) so the new CRL is actually picked up.
     */
    function revokeExtensionAndRestart($paths, $revokeExt) {
        revokeExtension($paths['pkiDir'], $paths['serverConf'], $paths['crlFile'], $paths['pkgDir'], $revokeExt);
        if (!file_exists("{$paths['baseDir']}/.stopped")) {
            stopOpenVpnServer($paths['ovpnctl']);
            startOpenVpnServer($paths['ovpnctl'], $paths['serverConf'], $paths['baseDir'], $paths['serverKey']);
        }
    }

    /**
     * Extracts [mac, ext] from a generated client package filename
     * (<mac>_<ext>_ovpn.tar or the older <mac>_<ext>_<8hex>_ovpn.tar).
     * Returns null for anything else.
     */
    function ovpnParsePackageName($filename) {
        $filename = basename((string)$filename);
        if (preg_match('/^([a-f0-9]+)_(\d+)_[a-f0-9]{8}_ovpn\.tar$/i', $filename, $m)
            || preg_match('/^([a-f0-9]+)_(\d+)_ovpn\.tar$/i', $filename, $m)) {
            return ['mac' => strtolower($m[1]), 'ext' => $m[2]];
        }
        return null;
    }

    /**
     * Reads the cipher a package's vpn.cnf currently uses. Falls back to
     * AES-128-CBC if it can't be read or isn't one of the allowed ciphers.
     */
    function getPackageCipher($pkgPath) {
        $allowed = ['AES-128-CBC', 'AES-256-CBC', 'AES-128-GCM', 'AES-256-GCM'];
        $cnf = @shell_exec('tar -xOf ' . escapeshellarg($pkgPath) . ' vpn.cnf 2>/dev/null');
        if (is_string($cnf)) {
            if (preg_match('/^cipher\s+([^\s]+)/m', $cnf, $m) && in_array(trim($m[1]), $allowed, true)) {
                return trim($m[1]);
            }
            if (preg_match('/^data-ciphers\s+([^\s]+)/m', $cnf, $m)) {
                $first = trim(explode(':', $m[1])[0]);
                if (in_array($first, $allowed, true)) {
                    return $first;
                }
            }
        }
        return 'AES-128-CBC';
    }

    /**
     * Rewrites vpn.cnf and re-tars existing client packages WITHOUT revoking
     * anything: each phone keeps its current key and certificate, and keeps
     * the cipher its package already uses. Only the server address/port and
     * the config template change. Packages whose key/cert are no longer in
     * the PKI are skipped (rebuilding them would silently issue a new key).
     * Returns ['rebuilt' => int, 'skipped' => [package filenames]].
     */
    function rebuildPackagesConfigOnly($pkiDir, $pkgDir, $baseDir, $serverIp, $port, array $pkgFilenames) {
        $rebuilt = 0;
        $skipped = [];
        $seen = [];
        foreach ($pkgFilenames as $name) {
            $name = basename((string)$name);
            $id = ovpnParsePackageName($name);
            $pkgPath = "{$pkgDir}/{$name}";
            if ($id === null || !file_exists($pkgPath)) {
                continue;
            }
            $key = $id['mac'] . '_' . $id['ext'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;

            if (!file_exists("{$pkiDir}/issued/{$id['ext']}.crt") || !file_exists("{$pkiDir}/private/{$id['ext']}.key")) {
                $skipped[] = $name;
                continue;
            }
            $cipher = getPackageCipher($pkgPath);
            if (buildClientPackage($pkiDir, $pkgDir, $baseDir, $id['ext'], $id['mac'], $serverIp, $port, $cipher)) {
                $rebuilt++;
            } else {
                $skipped[] = $name;
            }
        }
        return ['rebuilt' => $rebuilt, 'skipped' => $skipped];
    }
}
