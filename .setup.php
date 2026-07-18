<?php
include(__DIR__ . "/modules/system.php");

$projectName = "VulnScan";
$sourceDir = __DIR__;

function isRootUser() {
  if (function_exists("posix_geteuid")) {
    return posix_geteuid() === 0;
  }
  return false;
}

function getUserHomeDir() {
  foreach (["HOME", "USERPROFILE", "HOMEDRIVE"] as $envVar) {
    $value = getenv($envVar);
    if (!empty($value)) {
      return $value;
    }
  }
  return null;
}

$homeDir = getUserHomeDir();

if ($system == "termux") {
  $targetRoot = "/data/data/com.termux/files/usr";
  $binDir = "/data/data/com.termux/files/usr/bin";
  $manDir = "/data/data/com.termux/files/usr/share/man/man1";
} elseif (isRootUser()) {
  $targetRoot = "/usr";
  $binDir = "/usr/bin";
  $manDir = "/usr/share/man/man1";
} elseif ($homeDir !== null) {
  $targetRoot = $homeDir . "/.local";
  $binDir = $homeDir . "/.local/bin";
  $manDir = $homeDir . "/.local/share/man/man1";
} else {
  $targetRoot = __DIR__;
  $binDir = __DIR__;
  $manDir = __DIR__ . "/man";
}

$targetDir = $targetRoot . "/share/{$projectName}";
$binPath = $binDir . "/vulnscan";

function runCommand($cmd) {
  echo "[+] $cmd\n";
  system($cmd, $exitCode);
  if ($exitCode !== 0) {
    echo "[!] La commande a échoué (code $exitCode) : $cmd\n";
    exit($exitCode);
  }
}

if (is_dir($targetDir)) {
  runCommand("rm -rf " . escapeshellarg($targetDir));
}
if (file_exists($binPath)) {
  @unlink($binPath);
}

runCommand("mkdir -p " . escapeshellarg($targetDir));
runCommand("mkdir -p " . escapeshellarg($binDir));
runCommand("mkdir -p " . escapeshellarg($manDir));
runCommand("mkdir -p " . escapeshellarg($targetDir . "/reports"));
runCommand("cp -r " . escapeshellarg($sourceDir . "/modules") . " " . escapeshellarg($targetDir . "/modules"));
runCommand("cp " . escapeshellarg($sourceDir . "/README.md") . " " . escapeshellarg($targetDir . "/README.md"));
runCommand("cp " . escapeshellarg($sourceDir . "/man/vulnscan.1") . " " . escapeshellarg($manDir . "/vulnscan.1"));
if (file_exists($sourceDir . "/VERSION")) {
  runCommand("cp " . escapeshellarg($sourceDir . "/VERSION") . " " . escapeshellarg($targetDir . "/VERSION"));
}
runCommand("cp " . escapeshellarg($sourceDir . "/install") . " " . escapeshellarg($targetDir . "/install"));
runCommand("cp " . escapeshellarg($sourceDir . "/.setup.php") . " " . escapeshellarg($targetDir . "/.setup.php"));
runCommand("cp " . escapeshellarg($sourceDir . "/modules/vulnscan") . " " . escapeshellarg($binPath));
runCommand("chmod +x " . escapeshellarg($binPath));
runCommand("chmod +x " . escapeshellarg($targetDir . "/install"));

echo "\n[OK] VulnScan installé avec succès.\n";
echo "Utilisation :\n";
echo "  vulnscan --target 192.168.1.1\n";
echo "  vulnscan --target example.com --output /tmp/rapport.html\n";
