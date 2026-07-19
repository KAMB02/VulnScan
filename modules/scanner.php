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
    // If verbose, stream output live. Otherwise show a simple spinner while nmap runs.
    if ($verbose) {
        while (!feof($pipes[1])) {
            $line = fgets($pipes[1]);
            if ($line === false) break;
            $fullOutput .= $line;
            echo colorize($line, "gray");
        }
    } else {
        stream_set_blocking($pipes[1], false);
        $spinner = ['|', '/', '-', '\\'];
        $si = 0;
        while (true) {
            $status = proc_get_status($process);
            // read any available output
            $out = '';
            while (($chunk = fgets($pipes[1])) !== false) {
                $out .= $chunk;
            }
            if ($out !== '') {
                $fullOutput .= $out;
            }
            if (!$status['running']) {
                // drain remaining output
                while (!feof($pipes[1])) {
                    $line = fgets($pipes[1]);
                    if ($line === false) break;
                    $fullOutput .= $line;
                }
                break;
            }
            // print spinner
            $msg = sprintf("[ ] Scan en cours %s", $spinner[$si % count($spinner)]);
            echo "\r" . str_pad($msg, 40);
            usleep(120000);
            $si++;
        }
        echo "\r" . str_repeat(' ', 40) . "\r"; // clear line
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

/**
 * Vérifie si une commande externe est disponible dans le PATH.
 */
function toolAvailable($binary) {
    return trim((string) shell_exec("command -v " . escapeshellarg($binary) . " 2>/dev/null")) !== "";
}

/**
 * Exécution générique d'une commande externe avec le même comportement
 * que runNmapScan() : streaming en direct si --verbose, spinner sinon.
 */
function runToolCommand($cmd, $verbose) {
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
    if ($verbose) {
        while (!feof($pipes[1])) {
            $line = fgets($pipes[1]);
            if ($line === false) break;
            $fullOutput .= $line;
            echo colorize($line, "gray");
        }
    } else {
        stream_set_blocking($pipes[1], false);
        $spinner = ['|', '/', '-', '\\'];
        $si = 0;
        while (true) {
            $status = proc_get_status($process);
            $out = '';
            while (($chunk = fgets($pipes[1])) !== false) {
                $out .= $chunk;
            }
            if ($out !== '') {
                $fullOutput .= $out;
            }
            if (!$status['running']) {
                while (!feof($pipes[1])) {
                    $line = fgets($pipes[1]);
                    if ($line === false) break;
                    $fullOutput .= $line;
                }
                break;
            }
            $msg = sprintf("[ ] Analyse en cours %s", $spinner[$si % count($spinner)]);
            echo "\r" . str_pad($msg, 40);
            usleep(120000);
            $si++;
        }
        echo "\r" . str_repeat(' ', 40) . "\r";
    }
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    return $fullOutput;
}

/**
 * Repère les services web ouverts (80, 443, 8080, 8443...) dans la sortie
 * nmap, pour savoir si un scan web complémentaire (Nikto/Nuclei) est
 * pertinent, sans que l'utilisateur ait à le demander explicitement.
 */
function extractWebServices($rawOutput, $target) {
    $urls = [];
    $lines = preg_split('/\r\n|\r|\n/', $rawOutput);

    foreach ($lines as $line) {
        if (preg_match('/^(\d+)\/tcp\s+open\s+(\S+)/i', trim($line), $m)) {
            $port = $m[1];
            $service = strtolower($m[2]);

            $isHttps = strpos($service, "https") !== false || in_array($port, ["443", "8443"], true);
            $isHttp = !$isHttps && (strpos($service, "http") !== false || in_array($port, ["80", "8080", "8000"], true));

            if ($isHttps) {
                $urls[] = "https://{$target}:{$port}";
            } elseif ($isHttp) {
                $urls[] = "http://{$target}:{$port}";
            }
        }
    }

    return array_values(array_unique($urls));
}

/**
 * Lance Nikto sur une URL et retourne sa sortie brute.
 */
function runNiktoScan($url, $verbose) {
    $cmd = "nikto -h " . escapeshellarg($url) . " -Format txt 2>&1";
    return runToolCommand($cmd, $verbose);
}

/**
 * Analyse la sortie de Nikto et ne conserve que les lignes correspondant
 * à des constats de sécurité réels (pas les lignes d'information générale).
 */
function parseNiktoFindings($output) {
    $findings = [];
    $lines = preg_split('/\r\n|\r|\n/', (string) $output);

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === "" || $line[0] !== "+") {
            continue;
        }
        if (!preg_match('/OSVDB|CVE-|vulnerable|outdated|disclosure|injection|XSS|exposed|misconfigur/i', $line)) {
            continue;
        }

        $cves = [];
        if (preg_match_all('/CVE-\d{4}-\d{4,7}/i', $line, $cm)) {
            foreach ($cm[0] as $c) {
                $cves[] = strtoupper($c);
            }
        }

        $severity = "LOW";
        if (preg_match('/injection|remote code|RCE|CVE-/i', $line)) {
            $severity = "HIGH";
        } elseif (preg_match('/XSS|disclosure|outdated|misconfigur/i', $line)) {
            $severity = "MEDIUM";
        }

        $findings[] = [
            "script"   => "Analyse web (Nikto)",
            "state"    => ltrim($line, "+ "),
            "severity" => $severity,
            "cves"     => array_values(array_unique($cves)),
            "details"  => ltrim($line, "+ "),
        ];
    }

    return $findings;
}

/**
 * Lance Nuclei sur une URL et retourne sa sortie brute (JSON ligne par ligne).
 */
function runNucleiScan($url, $verbose) {
    $cmd = "nuclei -u " . escapeshellarg($url) . " -jsonl -silent 2>&1";
    return runToolCommand($cmd, $verbose);
}

/**
 * Analyse la sortie JSON de Nuclei.
 */
function parseNucleiFindings($output) {
    $findings = [];
    $lines = preg_split('/\r\n|\r|\n/', trim((string) $output));

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === "" || $line[0] !== "{") {
            continue;
        }
        $data = json_decode($line, true);
        if (!is_array($data)) {
            continue;
        }

        $info = $data["info"] ?? [];
        $sevMap = ["INFO" => "LOW", "LOW" => "LOW", "MEDIUM" => "MEDIUM", "HIGH" => "HIGH", "CRITICAL" => "CRITICAL"];
        $severity = $sevMap[strtoupper($info["severity"] ?? "info")] ?? "LOW";

        $cves = [];
        foreach (($info["classification"]["cve-id"] ?? []) as $c) {
            $cves[] = strtoupper($c);
        }

        $name = $info["name"] ?? ($data["template-id"] ?? "Résultat Nuclei");
        $matchedAt = $data["matched-at"] ?? "";

        $findings[] = [
            "script"   => $name,
            "state"    => $matchedAt !== "" ? "Correspondance : $matchedAt" : "Correspondance trouvée",
            "severity" => $severity,
            "cves"     => array_values(array_unique($cves)),
            "details"  => trim(($info["description"] ?? "") . ($matchedAt !== "" ? "\n$matchedAt" : "")),
        ];
    }

    return $findings;
}

/**
 * Croise une liste de CVE avec Exploit-DB via searchsploit et retourne,
 * pour chaque CVE ayant un résultat, la liste des exploits publics trouvés.
 */
function lookupExploitsForCves(array $cves) {
    $results = [];
    if (empty($cves) || !toolAvailable("searchsploit")) {
        return $results;
    }

    foreach (array_unique($cves) as $cve) {
        $cmd = "searchsploit --cve " . escapeshellarg($cve) . " -j 2>/dev/null";
        $json = shell_exec($cmd);
        $data = json_decode((string) $json, true);
        if (empty($data["RESULTS_EXPLOIT"])) {
            continue;
        }
        foreach ($data["RESULTS_EXPLOIT"] as $exploit) {
            $results[$cve][] = [
                "title"  => $exploit["Title"] ?? "",
                "edb_id" => $exploit["EDB-ID"] ?? "",
                "path"   => $exploit["Path"] ?? "",
            ];
        }
    }

    return $results;
}

/**
 * Orchestration complète et automatique du scan : nmap, puis, si des
 * services web sont détectés et que les outils sont installés, Nikto et
 * Nuclei, puis croisement des CVE trouvées avec Exploit-DB. Retourne
 * un tableau de résultats unifié, sans distinction visible d'origine.
 */
function runFullScan($target, $ports, $verbose, $quiet) {
    if (!$quiet) {
        $portInfo = $ports ? " (ports : $ports)" : "";
        echo colorize("[+] Scan de $target$portInfo en cours...\n", "cyan");
    }

    $rawOutput = runNmapScan($target, $ports, $verbose);
    if ($rawOutput === null || trim($rawOutput) === "") {
        return [null, null, null];
    }

    $findings = parseFindings($rawOutput);

    $webUrls = array_slice(extractWebServices($rawOutput, $target), 0, 2);
    foreach ($webUrls as $url) {
        if (toolAvailable("nikto")) {
            if (!$quiet) {
                echo colorize("[+] Service web détecté ($url), analyse complémentaire...\n", "cyan");
            }
            $niktoRaw = runNiktoScan($url, $verbose);
            if ($niktoRaw !== null) {
                $findings = array_merge($findings, parseNiktoFindings($niktoRaw));
            }
        }
        if (toolAvailable("nuclei")) {
            if (!$quiet) {
                echo colorize("[+] Analyse complémentaire ($url)...\n", "cyan");
            }
            $nucleiRaw = runNucleiScan($url, $verbose);
            if ($nucleiRaw !== null) {
                $findings = array_merge($findings, parseNucleiFindings($nucleiRaw));
            }
        }
    }

    $allCves = [];
    foreach ($findings as $f) {
        foreach ($f["cves"] as $c) {
            $allCves[] = $c;
        }
    }

    if (!empty($allCves) && toolAvailable("searchsploit")) {
        if (!$quiet) {
            echo colorize("[+] Vérification des exploits publics disponibles...\n", "cyan");
        }
        $exploitMap = lookupExploitsForCves($allCves);
        foreach ($findings as &$f) {
            $matched = [];
            foreach ($f["cves"] as $c) {
                if (!empty($exploitMap[$c])) {
                    $matched = array_merge($matched, $exploitMap[$c]);
                }
            }
            if (!empty($matched)) {
                $f["exploits"] = $matched;
                $f["severity"] = "CRITICAL";
            }
        }
        unset($f);
    }

    $severity = overallSeverity($findings, $rawOutput);

    return [$findings, $severity, $rawOutput];
}
