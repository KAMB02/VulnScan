<?php
/**
 * Génération des rapports : affichage terminal, HTML, JSON.
 */

function printGradeLegend() {
    echo colorize("Niveaux de gravité disponibles pour -g / --grade :\n", "cyan", true);
    echo "  " . colorize("LOW", severityColorName("LOW")) . "      Information mineure\n";
    echo "  " . colorize("MEDIUM", severityColorName("MEDIUM")) . "   Vulnérabilité probable, à vérifier\n";
    echo "  " . colorize("HIGH", severityColorName("HIGH")) . "     Vulnérabilité confirmée par le script NSE\n";
    echo "  " . colorize("CRITICAL", severityColorName("CRITICAL")) . " Vulnérabilité confirmée et exploitable\n";
    echo "\nExemple : vulnscan --target 192.168.1.1 -g HIGH\n";
    echo "          (n'affiche que les vulnérabilités HIGH et CRITICAL)\n";
}

/**
 * Filtre les résultats selon un niveau minimal de gravité.
 */
function filterByGrade($findings, $gradeFilter) {
    if ($gradeFilter === null) {
        return $findings;
    }
    $threshold = severityLevel($gradeFilter);
    return array_values(array_filter($findings, function ($f) use ($threshold) {
        return severityLevel($f["severity"]) >= $threshold;
    }));
}

/**
 * Affiche le rapport directement dans le terminal, avec couleurs.
 */
function printTerminalReport($target, $severity, $findings, $gradeFilter) {
    echo "\n" . colorize("========================================", "gray") . "\n";
    echo colorize(" Rapport VulnScan", "cyan", true) . "\n";
    echo colorize("========================================", "gray") . "\n";
    echo "Cible        : " . colorize($target, "white", true) . "\n";
    echo "Niveau global: " . colorize($severity, severityColorName($severity), true) . "\n";
    if ($gradeFilter !== null) {
        echo "Filtre       : >= " . colorize($gradeFilter, severityColorName($gradeFilter), true) . "\n";
    }
    echo colorize("----------------------------------------", "gray") . "\n";

    if (empty($findings)) {
        echo colorize("Aucune vulnérabilité à afficher pour ce filtre.\n", "green");
        return;
    }

    $counts = ["CRITICAL" => 0, "HIGH" => 0, "MEDIUM" => 0, "LOW" => 0];
    foreach ($findings as $f) {
        $counts[$f["severity"]]++;
    }
    echo "Résumé       : "
        . colorize($counts["CRITICAL"] . " CRITICAL", "red", true) . "  "
        . colorize($counts["HIGH"] . " HIGH", "red") . "  "
        . colorize($counts["MEDIUM"] . " MEDIUM", "yellow") . "  "
        . colorize($counts["LOW"] . " LOW", "cyan") . "\n";
    echo colorize("----------------------------------------", "gray") . "\n";

    foreach ($findings as $i => $f) {
        $badge = " " . $f["severity"] . " ";
        echo "\n" . colorize($badge, severityColorName($f["severity"]), true) . " "
            . colorize($f["script"], "white", true) . "\n";
        if (!empty($f["cves"])) {
            echo "  CVE   : " . colorize(implode(", ", $f["cves"]), "magenta") . "\n";
        }
        if (!empty($f["state"])) {
            echo "  État  : " . $f["state"] . "\n";
        }
        if (!empty($f["exploits"])) {
            echo "  " . colorize("⚠ Exploit public disponible", "red", true) . "\n";
            foreach (array_slice($f["exploits"], 0, 2) as $exploit) {
                $title = !empty($exploit["title"]) ? $exploit["title"] : "Exploit-DB";
                $id = !empty($exploit["edb_id"]) ? " (EDB-ID " . $exploit["edb_id"] . ")" : "";
                echo "    - " . colorize($title . $id, "red") . "\n";
            }
        }
    }
    echo "\n" . colorize("========================================", "gray") . "\n";
}

/**
 * Génère le rapport HTML.
 */
function buildHtmlReport($target, $severity, $findings) {
    $safeTarget = htmlspecialchars($target, ENT_QUOTES);
    $safeSeverity = htmlspecialchars($severity, ENT_QUOTES);
    $generatedAt = date("d/m/Y H:i:s");

    $rows = "";
    if (empty($findings)) {
        $rows = "<p>Aucune vulnérabilité détectée par les scripts NSE utilisés.</p>";
    } else {
        foreach ($findings as $f) {
            $script = htmlspecialchars($f["script"], ENT_QUOTES);
            $state = htmlspecialchars($f["state"] ?? "", ENT_QUOTES);
            $cves = htmlspecialchars(implode(", ", $f["cves"]), ENT_QUOTES);
            $details = htmlspecialchars($f["details"], ENT_QUOTES);
            $sevClass = strtolower($f["severity"]);
            $rows .= <<<ROW
<div class="finding sev-{$sevClass}">
  <div class="finding-header">
    <span class="badge badge-{$sevClass}">{$f['severity']}</span>
    <span class="script-name">{$script}</span>
  </div>
  <p><strong>État :</strong> {$state}</p>
ROW;
            if (!empty($f["cves"])) {
                $rows .= "  <p><strong>CVE :</strong> {$cves}</p>\n";
            }
            if (!empty($f["exploits"])) {
                $exploitLines = [];
                foreach (array_slice($f["exploits"], 0, 3) as $exploit) {
                    $title = htmlspecialchars(!empty($exploit["title"]) ? $exploit["title"] : "Exploit-DB", ENT_QUOTES);
                    $id = !empty($exploit["edb_id"]) ? " (EDB-ID " . htmlspecialchars((string) $exploit["edb_id"], ENT_QUOTES) . ")" : "";
                    $exploitLines[] = $title . $id;
                }
                $rows .= '  <p class="exploit-badge">⚠ Exploit public disponible : ' . implode(" ; ", $exploitLines) . "</p>\n";
            }
            $rows .= "  <pre>{$details}</pre>\n</div>\n";
        }
    }

    $html = <<<HTML
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Rapport VulnScan - {$safeTarget}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f9f9f9; color: #222; }
    h1 { margin-bottom: 4px; }
    .meta { color: #555; margin-bottom: 20px; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: bold; color: #fff; margin-right: 8px; }
    .badge-critical, .badge-high { background: #b00020; }
    .badge-medium { background: #b58900; }
    .badge-low { background: #007b8a; }
    .severity-global { font-weight: bold; }
    .finding { background: #fff; border: 1px solid #ddd; border-left: 6px solid #999; border-radius: 6px; padding: 12px 16px; margin-bottom: 14px; }
    .sev-critical, .sev-high { border-left-color: #b00020; }
    .sev-medium { border-left-color: #b58900; }
    .sev-low { border-left-color: #007b8a; }
    .finding-header { margin-bottom: 6px; }
    .script-name { font-weight: bold; }
    .exploit-badge { color: #b00020; font-weight: bold; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 6px; white-space: pre-wrap; font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>Rapport VulnScan</h1>
  <p class="meta">
    <strong>Cible :</strong> {$safeTarget}<br>
    <strong>Niveau global :</strong> <span class="severity-global">{$safeSeverity}</span><br>
    <strong>Généré le :</strong> {$generatedAt}
  </p>
  <h2>Résultats détectés</h2>
  {$rows}
</body>
</html>
HTML;

    return $html;
}

/**
 * Génère le rapport JSON.
 */
function buildJsonReport($target, $severity, $findings) {
    return json_encode([
        "target"    => $target,
        "severity"  => $severity,
        "generated" => date("c"),
        "findings"  => $findings,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}

/**
 * Génère le rapport CSV.
 */
function buildCsvReport($target, $severity, $findings) {
    $fp = fopen("php://temp", "r+");

    fputcsv($fp, ["Cible", $target]);
    fputcsv($fp, ["Niveau global", $severity]);
    fputcsv($fp, ["Généré le", date("d/m/Y H:i:s")]);
    fputcsv($fp, []);
    fputcsv($fp, ["Vulnérabilité", "Gravité", "CVE", "Exploit public disponible", "Détails"]);

    foreach ($findings as $f) {
        $exploitSummary = "";
        if (!empty($f["exploits"])) {
            $parts = [];
            foreach ($f["exploits"] as $exploit) {
                $title = !empty($exploit["title"]) ? $exploit["title"] : "Exploit-DB";
                $id = !empty($exploit["edb_id"]) ? " (EDB-ID " . $exploit["edb_id"] . ")" : "";
                $parts[] = $title . $id;
            }
            $exploitSummary = implode(" ; ", $parts);
        }

        fputcsv($fp, [
            $f["script"],
            $f["severity"],
            implode(", ", $f["cves"]),
            $exploitSummary,
            $f["state"] ?? "",
        ]);
    }

    rewind($fp);
    $csv = stream_get_contents($fp);
    fclose($fp);

    return $csv;
}
