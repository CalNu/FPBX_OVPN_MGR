#!/usr/bin/env php
<?php
// Standalone FreePBX Module Signer (Optimized for Instant Execution)
if (php_sapi_name() !== 'cli') {
    die("This script can only be run from the command line.\n");
}

$moduleDir = $argv[1] ?? dirname(__DIR__);

if (!$moduleDir || !is_dir($moduleDir)) {
    echo "Usage: php signer.php [/path/to/module/directory]\n";
    exit(1);
}

$moduleDir = rtrim(realpath($moduleDir), '/');
$moduleName = basename($moduleDir);

// 1. Clean old signature
@unlink("{$moduleDir}/module.sig");

// 2. Generate file hashes
$hashes = [];
$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($moduleDir));

foreach ($rii as $file) {
    if ($file->isDir()) {
        continue;
    }
    
    $path = $file->getPathname();
    
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