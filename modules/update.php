<?php

/**
 * -------------------------------------------------------------------------
 * VulnScan Update Manager
 * -------------------------------------------------------------------------
 * Vérifie automatiquement les mises à jour depuis GitHub.
 *
 * Si VulnScan est installé via Git :
 *      → git pull origin main
 *
 * Sinon :
 *      → Vérifie la dernière version disponible
 *      → Télécharge la dernière archive GitHub
 *      → Installe automatiquement la mise à jour
 *
 * Auteur : KADJO ALLOUAN MOISE BIENVENUE
 * GitHub : https://github.com/KAMB02/VulnScan
 * -------------------------------------------------------------------------
 */

define("VULNSCAN_NAME", "VulnScan");
define("VULNSCAN_VERSION", "1.1.0");

define("VULNSCAN_OWNER", "KAMB02");
define("VULNSCAN_REPO", "VulnScan");
define("VULNSCAN_BRANCH", "main");

define(
    "VULNSCAN_GITHUB",
    "https://github.com/" .
    VULNSCAN_OWNER .
    "/" .
    VULNSCAN_REPO
);

define(
    "VULNSCAN_GIT",
    VULNSCAN_GITHUB . ".git"
);

define(
    "VULNSCAN_RAW",
    "https://raw.githubusercontent.com/" .
    VULNSCAN_OWNER .
    "/" .
    VULNSCAN_REPO .
    "/" .
    VULNSCAN_BRANCH
);

define(
    "VULNSCAN_CODELOAD",
    "https://codeload.github.com/" .
    VULNSCAN_OWNER .
    "/" .
    VULNSCAN_REPO .
    "/zip/refs/heads/" .
    VULNSCAN_BRANCH
);

define(
    "VULNSCAN_RELEASE_API",
    "https://api.github.com/repos/" .
    VULNSCAN_OWNER .
    "/" .
    VULNSCAN_REPO .
    "/releases/latest"
);

define(
    "VULNSCAN_VERSION_URL",
    VULNSCAN_RAW . "/VERSION"
);

// Helpers pour la mise à jour
function vs_command_exists($cmd)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $check = $isWin ? 'where' : 'command -v';
    @exec(sprintf('%s %s 2> %s', $check, escapeshellarg($cmd), $isWin ? 'nul' : '/dev/null'), $out, $ret);
    return isset($ret) && $ret === 0;
}

function vs_run($cmd)
{
    $out = [];
    $ret = 0;
    exec($cmd . ' 2>&1', $out, $ret);
    return ['code' => $ret, 'output' => implode("\n", $out)];
}

function vs_is_git_repo($dir)
{
    return is_dir($dir . DIRECTORY_SEPARATOR . '.git');
}

function vs_fetch_url($url)
{
    $opts = [
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: " . VULNSCAN_NAME . "\r\n",
            'timeout' => 15,
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ];
    $context = stream_context_create($opts);
    // try file_get_contents first
    $data = @file_get_contents($url, false, $context);
    if ($data !== false) {
        return $data;
    }
    // fallback to curl if available
    if (function_exists('curl_version')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, VULNSCAN_NAME);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }
    return false;
}

function vs_get_remote_version()
{
    $data = vs_fetch_url(VULNSCAN_VERSION_URL);
    if ($data === false) {
        return null;
    }
    $ver = trim($data);
    return $ver === '' ? null : $ver;
}

function vs_get_local_version($cwd)
{
    $versionFile = rtrim($cwd, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'VERSION';
    if (!is_file($versionFile)) {
        return null;
    }
    $v = trim(@file_get_contents($versionFile));
    return $v === '' ? null : $v;
}

function vs_get_latest_release()
{
    $data = vs_fetch_url(VULNSCAN_RELEASE_API);
    if ($data === false) {
        return null;
    }
    $json = @json_decode($data, true);
    if (!is_array($json)) {
        return null;
    }
    // Prefer zipball_url if present
    if (!empty($json['zipball_url'])) {
        return ['zip' => $json['zipball_url'], 'tag' => $json['tag_name'] ?? ($json['name'] ?? null)];
    }
    return null;
}

function vs_download_file($url, $dest)
{
    // Prefer curl with progress if available
    if (function_exists('curl_version')) {
        $fp = @fopen($dest, 'w');
        if ($fp === false) return false;
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, VULNSCAN_NAME);
        curl_setopt($ch, CURLOPT_TIMEOUT, 0);
        // Enable progress
        curl_setopt($ch, CURLOPT_NOPROGRESS, false);
        $lastProgress = 0;
        curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, function ($resource, $download_size, $downloaded, $upload_size, $uploaded) use (&$lastProgress) {
            if ($download_size > 0) {
                $percent = (int) (($downloaded / $download_size) * 100);
                if ($percent !== $lastProgress) {
                    $lastProgress = $percent;
                    $barLen = 30;
                    $filled = (int) round($barLen * $percent / 100);
                    $bar = str_repeat('=', $filled) . str_repeat(' ', $barLen - $filled);
                    fwrite(STDERR, "\r[Download] [{$bar}] {$percent}%");
                    if ($percent === 100) fwrite(STDERR, "\n");
                }
            } else {
                // unknown total size; show downloaded bytes
                if ($downloaded % 4096 === 0) {
                    fwrite(STDERR, "\r[Download] {$downloaded} bytes");
                }
            }
        });
        $res = curl_exec($ch);
        curl_close($ch);
        fclose($fp);
        if ($res === false) {
            return false;
        }
        return true;
    }

    // Fallback to basic fetch
    $data = vs_fetch_url($url);
    if ($data === false) {
        return false;
    }
    if (@file_put_contents($dest, $data) === false) {
        return false;
    }
    return true;
}

function vs_rrmdir_copy($src, $dst)
{
    $dir = opendir($src);
    @mkdir($dst, 0755, true);
    while (false !== ($file = readdir($dir))) {
        if (($file !== '.') && ($file !== '..')) {
            $s = $src . DIRECTORY_SEPARATOR . $file;
            $d = $dst . DIRECTORY_SEPARATOR . $file;
            if (is_dir($s)) {
                vs_rrmdir_copy($s, $d);
            } else {
                copy($s, $d);
            }
        }
    }
    closedir($dir);
}

function vs_extract_and_install($zipPath, $targetDir)
{
    if (!class_exists('ZipArchive')) {
        return ['ok' => false, 'msg' => 'ZipArchive missing'];
    }
    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        return ['ok' => false, 'msg' => 'Unable to open zip'];
    }
    $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'vulnscan_update_' . uniqid();
    @mkdir($tmp, 0755, true);
    // extract to tmp
    if (!$zip->extractTo($tmp)) {
        $zip->close();
        return ['ok' => false, 'msg' => 'Extraction failed'];
    }
    $zip->close();

    // GitHub zip format usually contains a top-level folder named owner-repo-<hash>
    $entries = scandir($tmp);
    foreach ($entries as $e) {
        if ($e === '.' || $e === '..') continue;
        $candidate = $tmp . DIRECTORY_SEPARATOR . $e;
        if (is_dir($candidate)) {
            // copy contents of candidate into target dir (overwrite)
            vs_rrmdir_copy($candidate, $targetDir);
            break;
        }
    }
    // cleanup
    // Note: keep it simple and do not attempt deep recursive delete here
    return ['ok' => true, 'msg' => 'Installed from zip'];
}

function vs_update_via_git($cwd)
{
    if (!vs_command_exists('git')) {
        return ['ok' => false, 'msg' => 'git not found'];
    }
    $cmd = 'git -C ' . escapeshellarg($cwd) . ' pull origin ' . escapeshellarg(VULNSCAN_BRANCH);
    $res = vs_run($cmd);
    if ($res['code'] !== 0) {
        return ['ok' => false, 'msg' => $res['output']];
    }
    return ['ok' => true, 'msg' => $res['output']];
}

function vs_update_from_zipball($cwd)
{
    // Try release API first
    $release = vs_get_latest_release();
    $zipUrl = $release['zip'] ?? null;
    if ($zipUrl === null) {
        // fallback to codeload link
        $zipUrl = VULNSCAN_CODELOAD;
    }
    $tmpZip = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'vulnscan_' . uniqid() . '.zip';
    if (!vs_download_file($zipUrl, $tmpZip)) {
        return ['ok' => false, 'msg' => 'Téléchargement échoué'];
    }
    $res = vs_extract_and_install($tmpZip, $cwd);
    @unlink($tmpZip);
    return $res;
}

function vs_perform_update($cwd = __DIR__ . DIRECTORY_SEPARATOR . '..')
{
    $cwd = realpath($cwd) ?: $cwd;
    $local = vs_get_local_version($cwd);
    $remote = vs_get_remote_version();

    if ($remote !== null && $local !== null && $remote === $local) {
        echo "Aucune mise à jour disponible. Version installée : {$local}\n";
        return ['ok' => true, 'uptodate' => true, 'msg' => "Version {$local} déjà installée"];
    }

    if ($remote !== null && $local !== null) {
        echo "Mise à jour disponible : {$local} -> {$remote}\n";
    } elseif ($remote !== null && $local === null) {
        echo "Version distante : {$remote}. Version locale introuvable. Tentative de mise à jour...\n";
    } else {
        echo "Impossible de vérifier la version distante. Tentative de mise à jour...\n";
    }

    // If repo is a Git checkout and git exists -> git pull
    if (vs_is_git_repo($cwd) && vs_command_exists('git')) {
        $res = vs_update_via_git($cwd);
        if ($res['ok']) {
            echo "Mise à jour via git terminée.\n";
            return $res;
        }
        echo "Echec git pull : {$res['msg']}\n";
    }

    // Otherwise download and install zipball
    $res = vs_update_from_zipball($cwd);
    if ($res['ok']) {
        echo "Mise à jour depuis archive terminée.\n";
    } else {
        echo "Echec mise à jour depuis archive : {$res['msg']}\n";
    }
    return $res;
}

// Expose a simple CLI entry when required
if (PHP_SAPI === 'cli' && basename($_SERVER['argv'][0]) === basename(__FILE__)) {
    $res = vs_perform_update(getcwd());
    if ($res['ok']) {
        echo "Update réussi: " . ($res['msg'] ?? "OK") . PHP_EOL;
        exit(0);
    }
    fwrite(STDERR, "Update échoué: " . ($res['msg'] ?? 'erreur') . PHP_EOL);
    exit(1);
}

// Wrapper attendu par modules/app.php
function vulnscanUpdate($cwd = null)
{
    if ($cwd === null) {
        $cwd = realpath(__DIR__ . DIRECTORY_SEPARATOR . '..');
    }
    // Capture output produced during the update process and only display
    // a concise success message on success. On failure, show the full log
    // to help debugging.
    ob_start();
    $res = vs_perform_update($cwd);
    $log = ob_get_clean();

    if (isset($res['ok']) && $res['ok']) {
        if (!empty($res['uptodate'])) {
            echo "Package déjà à jour.\n";
        } else {
            echo "Mise à jour terminée avec succès.\n";
        }
        return true;
    }

    // On échec, afficher le log complet puis un message d'erreur succinct
    if ($log !== '') {
        echo $log . "\n";
    }
    echo "La mise à jour a échoué.\n";
    return false;
}