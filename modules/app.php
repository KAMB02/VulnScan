<?php

define("VULNSCAN_VERSION_FILE", __DIR__ . "/../VERSION");
$vulnscanVersion = is_file(VULNSCAN_VERSION_FILE) ? trim(file_get_contents(VULNSCAN_VERSION_FILE)) : "dev";

require_once __DIR__ . "/colors.php";
require_once __DIR__ . "/scanner.php";
require_once __DIR__ . "/report.php";
require_once __DIR__ . "/update.php";

function printHelp($version) {
    echo colorize("VulnScan", "cyan", true) . " v{$version} - Scanner de vulnérabilités basé sur Nmap\n\n";
    echo colorize("Usage :\n", "white", true);
    echo "  vulnscan -t <cible> [options]\n\n";
    echo colorize("Options principales :\n", "white", true);
    echo "  -t, --target <cible>       Cible à scanner (IP, plage CIDR ou nom d'hôte)\n";
    echo "  -o, --output <fichier>     Chemin du rapport HTML (défaut : ./reports/rapport-<date>.html)\n";
    echo "  -j, --json <fichier>       Exporte également un rapport JSON\n";
    echo "  -c, --console              N'écrit aucun fichier, affiche seulement le rapport dans le terminal\n";
    echo "  -g, --grade [NIVEAU]       N'affiche que les résultats >= NIVEAU (LOW|MEDIUM|HIGH|CRITICAL)\n";
    echo "                             Sans argument : affiche la légende des niveaux\n";
    echo "  -p, --ports <ports>        Limite le scan à des ports précis (ex : 22,80,443 ou 1-1000)\n\n";
    echo colorize("Options d'affichage :\n", "white", true);
    echo "  -v, --verbose              Affiche la sortie brute de nmap en direct pendant le scan\n";
    echo "  -q, --quiet                Réduit les messages d'exécution\n";
    echo "      --no-color             Désactive les couleurs dans le terminal\n\n";
    echo colorize("Autres commandes :\n", "white", true);
    echo "  -u, --update               Met à jour VulnScan vers la dernière version\n";
    echo "  -V, --version              Affiche la version installée\n";
    echo "  -m, --man                  Affiche la page de manuel de VulnScan\n";
    echo "  -h, --help                 Affiche cette aide\n\n";
    echo colorize("Exemples :\n", "white", true);
    echo "  vulnscan --target 192.168.1.1\n";
    echo "  vulnscan -t example.com -p 80,443 -g HIGH\n";
    echo "  vulnscan -t 10.0.0.5 -c -v\n";
    echo "  vulnscan -t 10.0.0.0/24 -o /tmp/rapport.html -j /tmp/rapport.json\n";
    echo "  vulnscan --update\n";
}

// --- Analyse des arguments ---------------------------------------------

$target = null;
$output = null;
$json = null;
$ports = null;
$gradeFilter = null;
$consoleOnly = false;
$verbose = false;
$quiet = false;
$noColor = false;
$doUpdate = false;
$showVersion = false;
$showHelp = false;
$showMan = false;

function nextArgIsValue($argv, $i) {
    return isset($argv[$i + 1]) && (strlen($argv[$i + 1]) === 0 || $argv[$i + 1][0] !== "-");
}

for ($i = 1; $i < $argc; $i++) {
    $arg = $argv[$i];
    switch ($arg) {
        case "--target":
        case "-t":
            if (!isset($argv[$i + 1])) {
                echo "L'option $arg nécessite une valeur.\n";
                exit(1);
            }
            $target = $argv[++$i];
            break;

        case "--output":
        case "-o":
            if (!isset($argv[$i + 1])) {
                echo "L'option $arg nécessite une valeur.\n";
                exit(1);
            }
            $output = $argv[++$i];
            break;

        case "--json":
        case "-j":
            if (!isset($argv[$i + 1])) {
                echo "L'option $arg nécessite une valeur.\n";
                exit(1);
            }
            $json = $argv[++$i];
            break;

        case "--ports":
        case "-p":
            if (!isset($argv[$i + 1])) {
                echo "L'option $arg nécessite une valeur.\n";
                exit(1);
            }
            $ports = $argv[++$i];
            break;

        case "--grade":
        case "-g":
            if (nextArgIsValue($argv, $i)) {
                $gradeFilter = strtoupper($argv[++$i]);
                if (severityLevel($gradeFilter) === 0) {
                    echo "Niveau de gravité inconnu : $gradeFilter\n\n";
                    printGradeLegend();
                    exit(1);
                }
            } else {
                printGradeLegend();
                exit(0);
            }
            break;

        case "--console":
        case "-c":
            $consoleOnly = true;
            break;

        case "--verbose":
        case "-v":
            $verbose = true;
            break;

        case "--quiet":
        case "-q":
            $quiet = true;
            break;

        case "--no-color":
            $noColor = true;
            break;

        case "--update":
        case "-u":
            $doUpdate = true;
            break;

        case "--version":
        case "-V":
            $showVersion = true;
            break;

        case "--help":
        case "-h":
            $showHelp = true;
            break;

        case "--man":
        case "-m":
            $showMan = true;
            break;

        default:
            echo "Option inconnue : $arg\n";
            echo "Utilise --help pour voir les options disponibles.\n";
            exit(1);
    }
}

vulnscanSetNoColor($noColor);

if ($showHelp) {
    printHelp($vulnscanVersion);
    exit(0);
}

if ($showVersion) {
    echo "VulnScan v{$vulnscanVersion}\n";
    exit(0);
}

if ($showMan) {
    $manStatus = 0;
    system("man vulnscan", $manStatus);
    if ($manStatus !== 0) {
        echo "La page de manuel n'a pas pu être affichée. Vérifie que la commande 'man' est installée et que la page 'vulnscan' est disponible.\n";
    }
    exit($manStatus === 0 ? 0 : 1);
}

if ($doUpdate) {
    $rootDir = realpath(__DIR__ . "/..");
    $ok = vulnscanUpdate($rootDir);
    exit($ok ? 0 : 1);
}

if (!$target) {
    echo "Veuillez fournir une cible avec --target (ou -t).\n";
    echo "Utilise --help pour voir toutes les options.\n";
    exit(1);
}

// --- Validation de la cible ---------------------------------------------

if ($target[0] === "-") {
    echo "Cible invalide : elle ne peut pas commencer par '-'.\n";
    exit(1);
}

if (!preg_match('/^[A-Za-z0-9.\-\/:]+$/', $target)) {
    echo "Cible invalide : caractères non autorisés.\n";
    exit(1);
}

if ($ports !== null && !preg_match('/^[0-9,\-]+$/', $ports)) {
    echo "Liste de ports invalide : $ports\n";
    exit(1);
}

// --- Exécution du scan ---------------------------------------------------

if (!$quiet) {
    $portInfo = $ports ? " (ports : $ports)" : "";
    echo colorize("[+] Scan de $target$portInfo en cours...\n", "cyan");
}

$rawOutput = runNmapScan($target, $ports, $verbose);

if ($rawOutput === null || trim($rawOutput) === "") {
    echo colorize("Erreur lors de l'exécution de nmap. Vérifie que nmap est installé et que la cible est joignable.\n", "red");
    exit(1);
}

$findings = parseFindings($rawOutput);
$severity = overallSeverity($findings, $rawOutput);
$displayFindings = filterByGrade($findings, $gradeFilter);

// --- Affichage terminal ---------------------------------------------------

printTerminalReport($target, $severity, $displayFindings, $gradeFilter);

// --- Rapport HTML (sauf en mode --console) --------------------------------

if (!$consoleOnly) {
    $reportPath = $output ?: "./reports/rapport-" . date("Y-m-d-H-i-s") . ".html";
    $reportDir = dirname($reportPath);
    if (!is_dir($reportDir) && !@mkdir($reportDir, 0777, true) && !is_dir($reportDir)) {
        echo colorize("Impossible de créer le dossier de rapport : $reportDir\n", "red");
        exit(1);
    }

    $html = buildHtmlReport($target, $severity, $displayFindings);
    if (file_put_contents($reportPath, $html) === false) {
        echo colorize("Impossible d'écrire le rapport dans : $reportPath\n", "red");
        exit(1);
    }
    echo colorize("[OK] Rapport HTML enregistré : $reportPath\n", "green");
}

// --- Rapport JSON (optionnel) ----------------------------------------------

if ($json !== null) {
    $jsonDir = dirname($json);
    if (!is_dir($jsonDir) && !@mkdir($jsonDir, 0777, true) && !is_dir($jsonDir)) {
        echo colorize("Impossible de créer le dossier de rapport JSON : $jsonDir\n", "red");
        exit(1);
    }
    $jsonReport = buildJsonReport($target, $severity, $displayFindings);
    if (file_put_contents($json, $jsonReport) === false) {
        echo colorize("Impossible d'écrire le rapport JSON dans : $json\n", "red");
        exit(1);
    }
    echo colorize("[OK] Rapport JSON enregistré : $json\n", "green");
}

echo colorize("[OK] Niveau estimé : $severity\n", severityColorName($severity), true);
