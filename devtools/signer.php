#!/usr/bin/env php
<?php
// Standalone FreePBX Module Signer & Alert Purger
if (php_sapi_name() !== 'cli') {
    die("This script can only be run from the command line.\n");
}

// Default to parent directory if no path argument is provided
$moduleDir = $argv[1] ?? dirname(__DIR__);

if (!$moduleDir || !is_dir($moduleDir)) {
    echo "Usage: php signer.php [/path/to/module/directory]\n";
    exit(1);
}

$moduleDir = rtrim(realpath($moduleDir), '/');
$moduleName = basename($moduleDir);

echo "=== 1. CLEANING OLD SIGNATURES ===\n";
exec("find " . escapeshellarg($moduleDir) . " -name 'module.sig' -delete 2>&1");

echo "=== 2. GENERATING NATIVE FILE HASHES ===\n";
$hashes = [];
$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($moduleDir));

foreach ($rii as $file) {
    if ($file->isDir()) {
        continue;
    }
    
    $path = $file->getPathname();
    
    // Exclude module.sig, git metadata, and the devtools subfolder itself
    if (
        strpos($path, 'module.sig') !== false || 
        strpos($path, '.git') !== false || 
        strpos($path, '/devtools/') !== false || 
        strpos($path, '.tmp') !== false
    ) {
        continue;
    }
    
    $relativePath = ltrim(substr($path, strlen($moduleDir)), '/');
    $hashes[$relativePath] = hash_file('sha256', $path);
}

$sigData = json_encode([
    'hashes'    => $hashes,
    'signed_by' => 'Local PBX Admin',
    'timestamp' => time()
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

$sigFile = "{$moduleDir}/module.sig";
file_put_contents($sigFile, $sigData);
@chmod($sigFile, 0644);

echo "[SUCCESS] Generated module.sig with " . count($hashes) . " file hashes.\n";

echo "=== 3. PURGING FRAMEWORK NOTIFICATIONS & RELOADING ===\n";
$fwbin = shell_exec("which fwconsole 2>/dev/null") ? trim(shell_exec("which fwconsole")) : '/usr/bin/fwconsole';

exec("{$fwbin} notification delete core SIGNATURE_NOT_VALID 2>&1");
exec("{$fwbin} notification delete framework TAMPERED_FILES 2>&1");
exec("{$fwbin} ma refreshsignatures 2>&1");
exec("{$fwbin} reload 2>&1");

echo "=== PROCESS COMPLETE FOR {$moduleName} ===\n";