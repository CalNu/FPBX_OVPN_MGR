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

    /**
     * Returns only the part of an OpenVPN log that belongs to the most
     * recent launch: everything from the last version banner line
     * ("... OpenVPN 2.6.x ... [SSL ...") onward. OpenVPN prints that banner at
     * the top of every start, so errors from earlier failed attempts that are
     * still sitting in the shared, append-only log don't count against a
     * daemon that has since started cleanly. If no banner is in the window,
     * the whole text is returned unchanged.
     */
    function ovpnLogSinceLastStart($logContent) {
        if (preg_match_all('/^.*OpenVPN \d+\.\d+\.\d+ .*\[SSL.*$/m', $logContent, $m, PREG_OFFSET_CAPTURE) && !empty($m[0])) {
            $last = end($m[0]);
            return (string)substr($logContent, $last[1]);
        }
        return $logContent;
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

    /**
     * Like tailFile(), but treats $markerBytePos (a byte offset recorded
     * when a "line break" divider was inserted - see page.ovpn_mgr.php's
     * add_page_break handler) as a floor on how far the window is allowed
     * to advance: it never starts reading later than the marker, so the
     * divider can't scroll out of view just because ordinary logging
     * continues underneath it. It is NOT a forced starting point - the
     * window still includes the normal $minLines of tail context even
     * when that's further back than the marker (e.g. right after the
     * marker was just added), so adding a break never makes the view jump
     * forward and hide everything above it. $maxLines caps runaway growth
     * so an old, never-cleared marker can't force an unbounded render.
     *
     * Falls back to a plain tailFile($minLines) when there's no marker, or
     * the recorded offset no longer makes sense against the current file
     * (e.g. the log was trimmed/restarted since, or has grown so much
     * that the marker fell outside the $maxBytes window entirely) - the
     * caller doesn't need to know which case applies.
     */
    function tailFileFromMarker($path, $markerBytePos, $minLines = 500, $maxLines = 5000, $maxBytes = 2000000) {
        if (!file_exists($path)) { return ''; }
        $size = filesize($path);
        $windowStart = max(0, $size - $maxBytes);

        if ($size <= $maxBytes) {
            $content = (string)@file_get_contents($path);
        } else {
            $fp = @fopen($path, 'r');
            if (!$fp) { return ''; }
            fseek($fp, $windowStart, SEEK_SET);
            $content = (string)fread($fp, $size - $windowStart);
            fclose($fp);
        }
        $arr = explode("\n", $content);
        $normalStart = max(0, count($arr) - $minLines);

        $markerValid = $markerBytePos !== null && $markerBytePos >= $windowStart && $markerBytePos < $size;
        if (!$markerValid) {
            return implode("\n", array_slice($arr, $normalStart));
        }

        $markerLineIndex = substr_count(substr($content, 0, $markerBytePos - $windowStart), "\n");
        $startIndex = min($normalStart, $markerLineIndex);
        $startIndex = max($startIndex, count($arr) - $maxLines);

        return implode("\n", array_slice($arr, $startIndex));
    }

    function getOpenVpnVersion() {
        $openvpnBin = file_exists('/usr/sbin/openvpn') ? '/usr/sbin/openvpn' : '/usr/local/sbin/openvpn';
        exec(escapeshellarg($openvpnBin) . " --version 2>&1", $output);
        if (!empty($output[0]) && preg_match('/OpenVPN\s+([0-9]+\.[0-9]+\.[0-9]+)/i', $output[0], $matches)) {
            return $matches[1];
        }
        return '2.4.0';
    }

    /**
     * The PBX's own LAN address, detected the same way install.php does
     * (source address of the default route). Only used when the config has
     * no record of it yet.
     */
    function ovpnDetectLanIp() {
        $out = [];
        $cmd = "ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if (\$i==\"src\") {print \$(i+1); exit}}'";
        @exec($cmd, $out);
        $ip = trim((string)($out[0] ?? ''));
        if (filter_var($ip, FILTER_VALIDATE_IP) && strpos($ip, '127.') !== 0) {
            return $ip;
        }
        $ip = (string)($_SERVER['SERVER_ADDR'] ?? '');
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    /**
     * True when an address clients connect to is the PBX's own LAN address -
     * either literally, or a hostname that resolves to it.
     */
    function ovpnRemoteIsServerLan($remoteHost, $lanIp) {
        $remote = strtolower(trim((string)$remoteHost));
        if ($remote === '' || $lanIp === '') { return false; }
        if ($remote === $lanIp) { return true; }
        if (!filter_var($remote, FILTER_VALIDATE_IP)) {
            static $dnsCache = [];
            if (!isset($dnsCache[$remote])) {
                $dnsCache[$remote] = @gethostbyname($remote); // returns the input unchanged on failure
            }
            if ($dnsCache[$remote] !== $remote && $dnsCache[$remote] === $lanIp) { return true; }
        }
        return false;
    }

    /**
     * The PBX's LAN address that the per-client route points at: recorded in
     * the "# push-route-host" marker, else taken from an existing pushed /32
     * route line (active or commented out), else detected.
     */
    function ovpnRouteLanIp($text) {
        $text = (string)$text;
        if (preg_match('/^# push-route-host[ \t]+(\S+)[ \t]*$/m', $text, $m) && filter_var($m[1], FILTER_VALIDATE_IP)) {
            return $m[1];
        }
        if (preg_match('/^[ \t#]*push[ \t]+"route[ \t]+(\d{1,3}(?:\.\d{1,3}){3})[ \t]+255\.255\.255\.255"[ \t]*$/m', $text, $m)) {
            return $m[1];
        }
        return ovpnDetectLanIp();
    }

    /**
     * Route to the PBX's LAN address, decided per client.
     *
     * Remote phones (connecting to a public IP / DNS name) need a route to
     * the PBX's LAN address through the tunnel. Phones on the PBX's own LAN
     * that connect to that same address must NOT get it: the route points
     * the phone's own encrypted traffic to the server back into the tunnel (a
     * routing loop). The handshake succeeds, then the phone goes silent and
     * the server drops it after ping-restart. Both kinds can exist on one
     * server, so this is no longer a global "push": each client's ccd file
     * (client-config-dir, named after the certificate CN) pushes the route
     * or not, according to the address that client's package connects to.
     *
     * This rewrites the server config for that: removes any global pushed
     * route to the LAN address (active, or commented out by hand), records
     * the address in a "# push-route-host" marker and points
     * client-config-dir at $ccdDir. If the ccd directory can't be created or
     * written, nothing is changed (the old global push keeps working).
     * Returns ['text' => new config text, 'lan_ip' => address, or '' if not applied].
     */
    function ovpnPrepareRoutePolicy($text, $ccdDir) {
        $text = (string)$text;
        if (!is_dir($ccdDir)) { @mkdir($ccdDir, 0775, true); }
        if (!is_dir($ccdDir) || !is_writable($ccdDir)) { return ['text' => $text, 'lan_ip' => '']; }
        $lanIp = ovpnRouteLanIp($text);
        if (!filter_var($lanIp, FILTER_VALIDATE_IP)) { return ['text' => $text, 'lan_ip' => '']; }

        $marker  = "# push-route-host {$lanIp}";
        $routeRe = '/^[ \t#]*push[ \t]+"route[ \t]+' . preg_quote($lanIp, '/') . '[ \t]+255\.255\.255\.255"[ \t]*$/';
        $out = [];
        $placed = false;
        foreach (preg_split('/\r?\n/', $text) as $line) {
            if (preg_match('/^# push-route-host[ \t]+\S+[ \t]*$/', $line) || preg_match($routeRe, $line)) {
                if (!$placed) { $out[] = $marker; $placed = true; }
                continue;
            }
            $out[] = $line;
        }
        if (!$placed) {
            while (!empty($out) && end($out) === '') { array_pop($out); }
            $out[] = $marker;
            $out[] = '';
        }
        $text = ovpnSetServerDirective(implode("\n", $out), 'client-config-dir', $ccdDir);
        return ['text' => $text, 'lan_ip' => $lanIp];
    }

    /** The address a built package's vpn.cnf connects to ("remote <host> <port>"), or ''. */
    function getPackageRemote($pkgPath) {
        $cnf = @shell_exec('tar -xOf ' . escapeshellarg($pkgPath) . ' vpn.cnf 2>/dev/null');
        if (is_string($cnf) && preg_match('/^remote[ \t]+(\S+)/m', $cnf, $m)) {
            return trim($m[1]);
        }
        return '';
    }

    /**
     * (Re)writes the per-client ccd files described at ovpnPrepareRoutePolicy():
     * one file per issued client certificate, containing the route to the
     * PBX's LAN address - or just a comment when that client's package connects
     * to the LAN address directly. A client with several packages is treated
     * as same-LAN if ANY of them targets the LAN address (a missing route is
     * harmless, a loop is not); a client with no readable package keeps the old
     * behaviour (route pushed). OpenVPN reads a client's ccd file when it
     * connects, so changes need no daemon restart.
     *
     * $onlyExt limits the work to one extension (used right after building its
     * package); otherwise every issued certificate is handled and stale
     * module-written files are removed.
     */
    function ovpnSyncCcdFiles($baseDir, $pkiDir, $pkgDir, $lanIp = '', $onlyExt = null) {
        $ccdDir = "{$baseDir}/ccd";
        if ($lanIp === '') {
            $lanIp = ovpnRouteLanIp((string)@file_get_contents("{$baseDir}/legacy-vpn.conf"));
        }
        if (!filter_var($lanIp, FILTER_VALIDATE_IP)) { return false; }
        if ($onlyExt !== null && !preg_match('/^[A-Za-z0-9_-]{1,64}$/', (string)$onlyExt)) { return false; }
        if (!is_dir($ccdDir)) { @mkdir($ccdDir, 0775, true); }
        if (!is_dir($ccdDir) || !is_writable($ccdDir)) { return false; }

        $header = '# managed by ovpn_mgr: rewritten on every daemon start and package build';
        $exts = [];
        $targetsLan = [];
        if ($onlyExt !== null) {
            $exts[(string)$onlyExt] = true;
            $tars = glob("{$pkgDir}/*_{$onlyExt}_*ovpn.tar") ?: [];
        } else {
            $tars = glob("{$pkgDir}/*_ovpn.tar") ?: [];
            foreach (glob("{$pkiDir}/issued/*.crt") ?: [] as $crt) {
                $exts[basename($crt, '.crt')] = true;
            }
        }
        foreach ($tars as $tar) {
            $id = ovpnParsePackageName($tar);
            if ($id === null) { continue; }
            if ($onlyExt !== null && $id['ext'] !== (string)$onlyExt) { continue; }
            $exts[$id['ext']] = true;
            $remote = getPackageRemote($tar);
            if ($remote !== '' && ovpnRemoteIsServerLan($remote, $lanIp)) {
                $targetsLan[$id['ext']] = true;
            }
        }

        $known = [];
        foreach (array_keys($exts) as $cn) {
            $cn = (string)$cn;
            if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $cn) || $cn === 'server') { continue; }
            $known[$cn] = true;
            $body = $header . "\n";
            if (!empty($targetsLan[$cn])) {
                $body .= "# This client connects to the PBX LAN address ({$lanIp}) directly, so no route to it\n"
                       . "# is pushed: it would send the phone's own tunnel traffic back into the tunnel.\n";
            } else {
                $body .= "push \"route {$lanIp} 255.255.255.255\"\n";
            }
            $file = "{$ccdDir}/{$cn}";
            if (@file_get_contents($file) !== $body) {
                @file_put_contents($file, $body, LOCK_EX);
                @chmod($file, 0644);
            }
        }

        if ($onlyExt === null) {
            foreach (glob("{$ccdDir}/*") ?: [] as $f) {
                if (!is_file($f) || isset($known[basename($f)])) { continue; }
                // Only ever remove files this module wrote.
                if (strpos((string)@file_get_contents($f), $header) === 0) { @unlink($f); }
            }
        }
        return true;
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
     * Ciphers the UI offers, weakest to strongest as shown, plus the order
     * used when writing the server's data-ciphers list (strongest first).
     */
    function ovpnAllowedCiphers() {
        return ['AES-128-CBC', 'AES-256-CBC', 'AES-128-GCM', 'AES-256-GCM'];
    }

    function ovpnIsCbcCipher($cipher) {
        return substr((string)$cipher, -4) === '-CBC';
    }

    /**
     * The default cipher pre-selected for new packages. Stored as a
     * "# default-cipher X" comment in the server config (same pattern as
     * "# client-remote-host"). Until one is set the initial default is
     * AES-256-CBC.
     */
    function getDefaultCipher($serverConf) {
        if (is_readable($serverConf)) {
            $content = (string)@file_get_contents($serverConf);
            if (preg_match('/^# default-cipher[ \t]+([A-Za-z0-9\-]+)/m', $content, $m)
                && in_array($m[1], ovpnAllowedCiphers(), true)) {
                return $m[1];
            }
            // No explicit default has ever been set via "Set as default
            // cipher" - fall back to whatever data-ciphers-fallback/cipher
            // is CURRENTLY in the config, not a hardcoded literal. Otherwise
            // syncServerCiphers() would rewrite that directive to a fixed
            // guess that doesn't match what's actually there on every single
            // call, making every save look like a real config change and
            // forcing a restart no matter what cipher was actually picked.
            if (preg_match('/^data-ciphers-fallback[ \t]+([A-Za-z0-9\-]+)/m', $content, $m2)
                && in_array($m2[1], ovpnAllowedCiphers(), true)) {
                return $m2[1];
            }
            if (preg_match('/^cipher[ \t]+([A-Za-z0-9\-]+)/m', $content, $m3)
                && in_array($m3[1], ovpnAllowedCiphers(), true)) {
                return $m3[1];
            }
        }
        return 'AES-256-CBC';
    }

    function setDefaultCipher($serverConf, $cipher) {
        if (!in_array($cipher, ovpnAllowedCiphers(), true)) { return false; }
        if (!is_readable($serverConf) || !is_writable($serverConf)) { return false; }
        $content = (string)file_get_contents($serverConf);
        if (preg_match('/^# default-cipher[ \t].*$/m', $content)) {
            $content = preg_replace('/^# default-cipher[ \t].*$/m', "# default-cipher {$cipher}", $content, 1);
        } else {
            $content = rtrim($content, "\r\n") . "\n# default-cipher {$cipher}\n";
        }
        return file_put_contents($serverConf, $content) !== false;
    }

    /**
     * Sets a single-valued directive in server config text: replaces the
     * first occurrence, drops any duplicates (older builds appended a new
     * data-ciphers line on every package build), or appends it if missing.
     */
    function ovpnSetServerDirective($text, $name, $value) {
        $pattern = '/^[ \t]*' . preg_quote($name, '/') . '[ \t]+.*$/m';
        $line = "{$name} {$value}";
        if (!preg_match($pattern, $text)) {
            return rtrim($text, "\r\n") . "\n{$line}\n";
        }
        $seen = false;
        $text = preg_replace_callback($pattern, function () use (&$seen, $line) {
            if ($seen) { return ''; }
            $seen = true;
            return $line;
        }, $text);
        return preg_replace("/\n{3,}/", "\n\n", $text);
    }

    /**
     * Keeps the server's cipher directives in sync with the admin's chosen
     * default - and nothing else:
     *   - data-ciphers: statically every allowed cipher, always. This is a
     *     process-wide directive (one daemon serves every extension), so
     *     recalculating it from "what packages currently exist" meant that
     *     editing or rebuilding a single extension's package could change a
     *     server-wide setting and force a restart that dropped every other
     *     connected client - and, worse, a save that removed the last
     *     package using a given cipher would silently stop the server from
     *     offering it at all, breaking any client whose own config (not yet
     *     rebuilt/reprovisioned) still expected it. Advertising every cipher
     *     unconditionally means no per-extension edit ever needs to touch
     *     this directive, and no client can be locked out by another
     *     client's unrelated change.
     *   - data-ciphers-fallback / cipher: the admin's chosen default cipher
     *     only, changed solely via the explicit "Set as default cipher"
     *     checkbox - not a side effect of any particular package's cipher.
     *     Every package this module builds already pins its own explicit
     *     "cipher" line (see buildClientPackage()), so this fallback is only
     *     ever exercised by a client that both skips NCP negotiation and
     *     sends no cipher preference of its own - not a case this module's
     *     generated packages produce.
     * Returns true if the file changed (the daemon then needs a restart).
     */
    function syncServerCiphers($serverConf, $pkgDir, array $extraCiphers = []) {
        if (!is_readable($serverConf) || !is_writable($serverConf)) { return false; }
        $original = (string)file_get_contents($serverConf);
        $fallback = getDefaultCipher($serverConf);

        $text = ovpnSetServerDirective($original, 'data-ciphers', implode(':', ovpnAllowedCiphers()));
        $text = ovpnSetServerDirective($text, 'data-ciphers-fallback', $fallback);
        $text = ovpnSetServerDirective($text, 'cipher', $fallback);

        if ($text === $original) { return false; }
        return file_put_contents($serverConf, $text) !== false;
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
    function buildClientPackage($pkiDir, $pkgDir, $baseDir, $ext, $mac, $serverIp, $port, $cipher = null, $syncServer = true, $includeDataCiphers = false) {
        // No (or an invalid) cipher means "the server's default cipher".
        $allowedCiphers = ovpnAllowedCiphers();
        if (!in_array($cipher, $allowedCiphers, true)) { $cipher = getDefaultCipher("{$baseDir}/legacy-vpn.conf"); }
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

        // data-ciphers / data-ciphers-fallback require an OpenVPN 2.5+ client
        // (the keyword itself doesn't parse on 2.4.x - it fails the whole
        // config, it doesn't just skip negotiation). GCM does NOT imply a
        // client is new enough: some 2.4.x builds (e.g. Yealink's) negotiate
        // GCM fine via the static "cipher" line below but don't understand
        // "data-ciphers" at all. So these lines are never emitted by default,
        // even for GCM ciphers - only when the caller has explicitly opted
        // in (the "Include data-ciphers" checkbox in the UI), confirming the
        // client is known to be 2.5+.
        $dataCipherLines = (!ovpnIsCbcCipher($cipher) && $includeDataCiphers)
            ? "data-ciphers {$cipher}\n" . "data-ciphers-fallback {$cipher}\n"
            : "";

        // The HMAC only matters for CBC ciphers (and must match the server's
        // auth). GCM authenticates itself, so SHA1 is not emitted for it.
        $authLine = ovpnIsCbcCipher($cipher) ? "auth SHA1\n" : "";

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
                . $authLine
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
            // Per-client route policy (see ovpnPrepareRoutePolicy): this
            // package's target decides whether the client is pushed a route
            // to the PBX's LAN address. Never fail a build over it.
            try {
                ovpnSyncCcdFiles($baseDir, $pkiDir, $pkgDir, '', (string)$ext);
            } catch (\Throwable $e) {
                // best effort
            }
            // Other callers (e.g. yealink_epm) get the server's cipher lines
            // kept in step automatically. They still need to restart the
            // daemon for a changed data-ciphers to take effect. This
            // module's own handlers pass $syncServer=false and sync once
            // themselves (so they can restart only when something changed).
            if ($syncServer) {
                syncServerCiphers("{$baseDir}/legacy-vpn.conf", $pkgDir, [$cipher]);
            }
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

        if (!file_exists("{$pkiDir}/index.txt")) { @touch("{$pkiDir}/index.txt"); }
        if (!file_exists("{$pkiDir}/crlnumber")) { @file_put_contents("{$pkiDir}/crlnumber", "01\n"); }

        // "dir" alone isn't enough for openssl's "ca" command - "database"
        // and "crlnumber" (which -revoke and -gencrl both need) aren't
        // derived from it, they have to be spelled out, or every call fails
        // with "variable lookup failed for CA_default::database".
        $tmpCnf = "{$pkiDir}/crl_openssl.cnf";
        $cnfData = "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {$pkiDir}\ndatabase = {$pkiDir}/index.txt\ncrlnumber = {$pkiDir}/crlnumber\ndefault_md = sha256\ndefault_crl_days = 3650\n";
        @file_put_contents($tmpCnf, $cnfData);

        $revokeOut = []; $revokeRc = 0;
        $gencrlOut = []; $gencrlRc = 0;
        exec("OPENSSL_CONF=" . escapeshellarg($tmpCnf) . " openssl ca -revoke " . escapeshellarg($targetCrt) . " -keyfile " . escapeshellarg("{$pkiDir}/private/ca.key") . " -cert " . escapeshellarg("{$pkiDir}/ca.crt") . " -config " . escapeshellarg($tmpCnf) . " 2>&1", $revokeOut, $revokeRc);
        exec("OPENSSL_CONF=" . escapeshellarg($tmpCnf) . " openssl ca -gencrl -keyfile " . escapeshellarg("{$pkiDir}/private/ca.key") . " -cert " . escapeshellarg("{$pkiDir}/ca.crt") . " -out " . escapeshellarg($crlFile) . " -config " . escapeshellarg($tmpCnf) . " 2>&1", $gencrlOut, $gencrlRc);
        @unlink($tmpCnf);

        // These two commands previously ran unchecked - a failure was
        // completely silent. In particular, if -gencrl fails, $crlFile never
        // gets (re)written, which - combined with startOpenVpnServer()'s own
        // defensive strip of crl-verify when that file is missing - can
        // silently undo the crl-verify line added below on the very next
        // restart, making it look like it "never sticks". Surface it instead.
        if ($gencrlRc !== 0 || !file_exists($crlFile)) {
            $_SESSION['ovpn_mgr_crl_warning'] = "Generating the CRL failed (exit {$gencrlRc}), so revocation checking is not active for this change: "
                . trim(implode(' ', $gencrlOut));
        } elseif ($revokeRc !== 0) {
            // gencrl still ran (it always writes a CRL reflecting whatever
            // index.txt currently has), but the revoke itself didn't record -
            // this extension's cert may not actually end up on the CRL.
            $_SESSION['ovpn_mgr_crl_warning'] = "Revoking extension {$revokeExt}'s certificate reported an error (exit {$revokeRc}): "
                . trim(implode(' ', $revokeOut));
        }

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
            // Any previously-recorded "line break" byte offset now points
            // into a file that no longer exists in that shape - drop it
            // rather than let tailFileFromMarker() fall back on its own
            // (harmless, since it already treats an out-of-range offset as
            // "no marker", but this keeps the sidecar file from lingering
            // indefinitely with a stale value).
            @unlink("{$logDir}/.line_break_pos");
        }

        if (!file_exists($crlFile) && file_exists("{$pkiDir}/ca.crt") && file_exists("{$pkiDir}/private/ca.key")) {
            if (!file_exists("{$pkiDir}/index.txt")) { @touch("{$pkiDir}/index.txt"); }
            if (!file_exists("{$pkiDir}/crlnumber")) { @file_put_contents("{$pkiDir}/crlnumber", "01\n"); }

            // See revokeExtension() - "dir" alone isn't enough for openssl's
            // "ca" command, "database"/"crlnumber" have to be spelled out too.
            $tmpCnf = "{$pkiDir}/crl_openssl.cnf";
            $cnfData = "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {$pkiDir}\ndatabase = {$pkiDir}/index.txt\ncrlnumber = {$pkiDir}/crlnumber\ndefault_md = sha256\ndefault_crl_days = 3650\n";
            @file_put_contents($tmpCnf, $cnfData);

            $gencrlOut = []; $gencrlRc = 0;
            exec("OPENSSL_CONF=" . escapeshellarg($tmpCnf) . " openssl ca -gencrl -keyfile " . escapeshellarg("{$pkiDir}/private/ca.key") . " -cert " . escapeshellarg("{$pkiDir}/ca.crt") . " -out " . escapeshellarg($crlFile) . " -config " . escapeshellarg($tmpCnf) . " 2>&1", $gencrlOut, $gencrlRc);
            @unlink($tmpCnf);

            if (($gencrlRc !== 0 || !file_exists($crlFile)) && empty($_SESSION['ovpn_mgr_crl_warning'])) {
                // Without a valid crl.pem, crl-verify gets stripped from the
                // config below on every start (OpenVPN would otherwise refuse
                // to start pointing at a missing file) - so this is the other
                // place a broken CA/index.txt state can make crl-verify look
                // like it never sticks.
                $_SESSION['ovpn_mgr_crl_warning'] = "Generating the CRL failed (exit {$gencrlRc}): " . trim(implode(' ', $gencrlOut));
            }
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
                // Configs from before this existed may still have
                // "duplicate-cn", which is what let a reconnecting phone's
                // old session linger (as a ghost row in the Connected
                // OpenVPN Clients table) instead of being replaced
                // immediately - see the comment in install.php's config
                // template for the full explanation. Strip it on every
                // start so existing installs self-heal without a manual
                // migration step.
                if ($trimmed === 'duplicate-cn') {
                    continue;
                }
                // A bare "log <path>" directive truncates the file on every
                // OpenVPN start, unlike ovpnctl's own "--log-append" CLI
                // flag (see the "start" case) - and per OpenVPN's option
                // parsing, whichever of the two actually wins is the one
                // that opens the file first, not simply "last one on the
                // command line", so having both present is not just
                // redundant but actively destructive: it silently wipes the
                // log (including any "Add Line Break" markers) on every
                // restart. Configs from before this was understood may
                // still have this line; strip it so existing installs
                // self-heal without a manual edit, the same way
                // "duplicate-cn" is handled above. (Matched with a
                // trailing space so this never touches "log-append ...".)
                if (strpos($trimmed, 'log ') === 0) {
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
                    $cleanContent .= "\ncipher " . getDefaultCipher($serverConf) . "\n";
                }
            } else {
                if (strpos($cleanContent, 'data-ciphers ') === false) {
                    $cleanContent .= "\ndata-ciphers " . getDefaultCipher($serverConf) . "\n";
                }
            }
            if (strpos($cleanContent, 'verb ') === false) {
                $cleanContent .= "\nverb 3\n";
            }
            // Same self-heal as the duplicate-cn strip above: configs from
            // before this existed lack these, so every start brings them
            // in line with what a fresh install.php now generates. Needed
            // for the Connected OpenVPN Clients table (reads the live
            // session list instead of the log) and the "Kill Connection"
            // button (issues client-kill over this socket).
            $cleanContent = ovpnSetServerDirective($cleanContent, 'status-version', '3');
            $cleanContent = ovpnSetServerDirective($cleanContent, 'management', '/run/ovpn_mgr/mgmt.sock unix');
            $cleanContent = ovpnSetServerDirective($cleanContent, 'management-client-user', 'asterisk');
            // Installs from before crl-verify was part of install.php's
            // baseline template only ever got it added reactively, by
            // revokeExtension(), on whichever save first revoked a cert -
            // meaning that one save needed a restart to activate it. Ensure
            // it here too, on every start, so an existing install converges
            // to the same "always present" guarantee a fresh install now
            // gets immediately - after which no revoke, ever, needs a
            // restart, matching how any standard OpenVPN CRL setup behaves.
            if (file_exists($crlFile)) {
                $cleanContent = ovpnSetServerDirective($cleanContent, 'crl-verify', $crlFile);
            }
            // Route to the PBX's LAN address: pushed per client (ccd files),
            // not globally, so phones on the PBX's own LAN and remote phones
            // can share one server. See ovpnPrepareRoutePolicy().
            $routePolicy = ovpnPrepareRoutePolicy($cleanContent, "{$baseDir}/ccd");
            $cleanContent = $routePolicy['text'];
            @file_put_contents($serverConf, $cleanContent);
            if ($routePolicy['lan_ip'] !== '') {
                ovpnSyncCcdFiles($baseDir, $pkiDir, dirname($baseDir) . '/vpnkeys', $routePolicy['lan_ip']);
            }
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
     * Whether a package's vpn.cnf currently includes the data-ciphers /
     * data-ciphers-fallback lines (see the note in buildClientPackage() on
     * why this is opt-in rather than automatic for GCM ciphers).
     */
    function packageHasDataCiphers($pkgPath) {
        $cnf = @shell_exec('tar -xOf ' . escapeshellarg($pkgPath) . ' vpn.cnf 2>/dev/null');
        return is_string($cnf) && preg_match('/^data-ciphers\s+\S/m', $cnf) === 1;
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
            $includeDataCiphers = packageHasDataCiphers($pkgPath);
            if (buildClientPackage($pkiDir, $pkgDir, $baseDir, $id['ext'], $id['mac'], $serverIp, $port, $cipher, false, $includeDataCiphers)) {
                $rebuilt++;
            } else {
                $skipped[] = $name;
            }
        }
        return ['rebuilt' => $rebuilt, 'skipped' => $skipped];
    }
}
