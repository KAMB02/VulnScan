<?php
/**
 * Gestion des couleurs ANSI pour l'affichage terminal.
 * Désactivable avec --no-color ou la variable d'environnement NO_COLOR.
 */

$GLOBALS["vulnscan_no_color"] = false;

function vulnscanSetNoColor($value) {
    $GLOBALS["vulnscan_no_color"] = (bool) $value;
}

function supportsColor() {
    if ($GLOBALS["vulnscan_no_color"]) {
        return false;
    }
    if (getenv("NO_COLOR") !== false) {
        return false;
    }
    if (function_exists("posix_isatty")) {
        return posix_isatty(STDOUT);
    }
    return true;
}

function colorize($text, $color, $bold = false) {
    static $colors = [
        "red"     => "31",
        "green"   => "32",
        "yellow"  => "33",
        "blue"    => "34",
        "magenta" => "35",
        "cyan"    => "36",
        "white"   => "37",
        "gray"    => "90",
    ];

    if (!supportsColor() || !isset($colors[$color])) {
        return $text;
    }

    $code = $colors[$color];
    $prefix = $bold ? "\033[1;{$code}m" : "\033[{$code}m";
    return $prefix . $text . "\033[0m";
}

function severityColorName($severity) {
    switch (strtoupper($severity)) {
        case "CRITICAL": return "red";
        case "HIGH":     return "red";
        case "MEDIUM":   return "yellow";
        case "LOW":      return "cyan";
        default:         return "white";
    }
}

function severityLevel($severity) {
    switch (strtoupper($severity)) {
        case "CRITICAL": return 4;
        case "HIGH":     return 3;
        case "MEDIUM":   return 2;
        case "LOW":      return 1;
        default:         return 0;
    }
}
