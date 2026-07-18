<?php
/**
 * Exécution de nmap --script vuln et analyse structurée des résultats.
 */

/**
 * Lance nmap sur la cible et retourne la sortie complète (stdout+stderr).
 * Si $verbose est vrai, affiche la sortie en direct pendant l'exécution.
 */
function runNmapScan($target, $ports, $verbose) {
    $portOption = $ports !== null ? "-p " . escapeshellarg($ports) . " " : "";
    $cmd = "nmap --script vuln " . $portOption . escapeshellarg($target) . " 2>&1";

    $descriptors = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"],
    ];

    $process = proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($process)) {
        return null;
    }
    fclose($pipes[0]);

    $fullOutput = "";
    while (!feof($pipes[1])) {
        $line = fgets($pipes[1]);
        if ($line === false) {
            break;
        }
        $fullOutput .= $line;
        if ($verbose) {
            echo colorize($line, "gray");
        }
    }
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    return $fullOutput;
}

/**
 * Analyse la sortie de nmap et retourne la liste des vulnérabilités
 * trouvées, chacune avec : script, state, severity, cves, details.
 */
function parseFindings($output) {
    $findings = [];
    $lines = preg_split('/\r\n|\r|\n/', $output);
    $current = null;

    foreach ($lines as $line) {
        if (preg_match('/^\|[_ ]?([A-Za-z0-9\-_]+):\s*$/', trim($line), $m)) {
            if ($current !== null && $current["isVuln"]) {
                $findings[] = finalizeFinding($current);
            }
            $current = ["script" => $m[1], "lines" => [], "isVuln" => false, "state" => null, "cves" => []];
            continue;
        }

        if ($current === null) {
            continue;
        }

        if (trim($line) === "") {
            if ($current["isVuln"]) {
                $findings[] = finalizeFinding($current);
            }
            $current = null;
            continue;
        }

        $current["lines"][] = $line;

        if (preg_match('/State:\s*(.+)/i', $line, $sm)) {
            $state = trim($sm[1]);
            $current["state"] = $state;
            $current["isVuln"] = stripos($state, "NOT VULNERABLE") === false
                && (stripos($state, "VULNERABLE") !== false || stripos($state, "LIKELY") !== false);
        } elseif (stripos($line, "VULNERABLE") !== false && $current["state"] === null) {
            $current["state"] = trim(str_replace("|", "", $line));
            $current["isVuln"] = stripos($line, "NOT VULNERABLE") === false;
        }

        if (preg_match_all('/CVE-\d{4}-\d{4,7}/i', $line, $cm)) {
            foreach ($cm[0] as $cve) {
                $cveUpper = strtoupper($cve);
                if (!in_array($cveUpper, $current["cves"], true)) {
                    $current["cves"][] = $cveUpper;
                }
            }
        }
    }

    if ($current !== null && $current["isVuln"]) {
        $findings[] = finalizeFinding($current);
    }

    return $findings;
}

function finalizeFinding($finding) {
    $finding["severity"] = findingSeverity($finding);
    $finding["details"] = trim(implode("\n", array_filter($finding["lines"], function ($l) {
        return trim($l) !== "";
    })));
    unset($finding["lines"], $finding["isVuln"]);
    return $finding;
}

function findingSeverity($finding) {
    $state = strtoupper($finding["state"] ?? "");
    if (strpos($state, "EXPLOITABLE") !== false) {
        return "CRITICAL";
    }
    if (strpos($state, "LIKELY VULNERABLE") !== false) {
        return "MEDIUM";
    }
    if (strpos($state, "VULNERABLE") !== false) {
        return "HIGH";
    }
    return "LOW";
}

/**
 * Détermine la gravité globale du scan à partir des vulnérabilités trouvées.
 * Si aucun "State:" structuré n'a été trouvé, on retombe sur une recherche
 * par mots-clés dans la sortie brute (compatibilité avec les scripts NSE
 * qui ne suivent pas le format standard).
 */
function overallSeverity($findings, $rawOutput) {
    if (!empty($findings)) {
        $best = "LOW";
        foreach ($findings as $f) {
            if (severityLevel($f["severity"]) > severityLevel($best)) {
                $best = $f["severity"];
            }
        }
        return $best;
    }

    if (stripos($rawOutput, "critical") !== false) {
        return "CRITICAL";
    }
    if (stripos($rawOutput, "high") !== false) {
        return "HIGH";
    }
    if (stripos($rawOutput, "medium") !== false) {
        return "MEDIUM";
    }
    return "LOW";
}
