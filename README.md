# VulnScan

VulnScan est un scanner de vulnérabilités basé sur Nmap, avec analyse
structurée des résultats, rapport coloré dans le terminal, export
HTML/JSON/CSV, croisement automatique avec Exploit-DB, et un système de
mise à jour intégré.

## Fonctionnement
- si des services web sont détectés parmi les ports ouverts (80, 443,
  8080, 8443...), et que les outils correspondants sont installés,
  **Nikto** et **Nuclei** sont lancés en complément sur ces services ;
- toutes les CVE identifiées (quelle que soit leur origine) sont
  automatiquement croisées avec **Exploit-DB** via `searchsploit` ; si un
  exploit public existe, la vulnérabilité est remontée en `CRITICAL` et un
  badge « ⚠ Exploit public disponible » apparaît dans le rapport ;
- un niveau de gravité est calculé par vulnérabilité et un niveau global
  pour l'ensemble du scan : `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.

Le rapport final ne distingue pas l'outil à l'origine de chaque résultat :
tout est fusionné en une seule liste de vulnérabilités, pour rester lisible
et directement exploitable.

Aucun de ces outils complémentaires n'est obligatoire : si Nikto, Nuclei ou
`searchsploit` ne sont pas installés, VulnScan continue de fonctionner
normalement avec les seuls résultats de nmap, sans erreur ni interruption.

Le rapport est affiché directement dans le terminal, et peut être exporté
en HTML, JSON et/ou CSV.

## Installation

```bash
chmod +x install
./install
```

### Installation depuis Git (option recommandée pour mettre à jour facilement)

Si vous préférez installer depuis le dépôt Git (permet d'utiliser `git pull` pour les mises à jour) :

```bash
git clone https://github.com/KAMB02/VulnScan.git
cd VulnScan
chmod +x install
./install
```

## Utilisation

```bash
vulnscan --target 192.168.1.1
vulnscan --target example.com --output /tmp/rapport.html
```

### Options principales

| Option                  | Description |
|--------------------------|--------------|
| `-t`, `--target <cible>` | Cible à scanner (IP, plage CIDR ou nom d'hôte) |
| `-o`, `--output <fichier>` | Chemin du rapport HTML (défaut : `./reports/rapport-<date>.html`) |
| `-j`, `--json <fichier>` | Exporte également un rapport JSON |
| `-s`, `--csv <fichier>` | Exporte également un rapport CSV |
| `-c`, `--console` | N'écrit aucun fichier, affiche seulement le rapport dans le terminal |
| `-g`, `--grade [NIVEAU]` | N'affiche que les résultats >= NIVEAU (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Sans argument : affiche la légende des niveaux |
| `-p`, `--ports <ports>` | Limite le scan à des ports précis (ex : `22,80,443` ou `1-1000`) |

### Options d'affichage

| Option        | Description |
|----------------|--------------|
| `-v`, `--verbose` | Affiche la sortie brute de nmap en direct pendant le scan |
| `-q`, `--quiet` | Réduit les messages d'exécution |
| `--no-color` | Désactive les couleurs dans le terminal |

### Autres commandes

| Option        | Description |
|----------------|--------------|
| `-u`, `--update` | Met à jour VulnScan vers la dernière version |
| `-V`, `--version` | Affiche la version installée |
| `-h`, `--help` | Affiche l'aide |

### Exemples

```bash
vulnscan --target 192.168.1.1
vulnscan -t example.com -p 80,443 -g HIGH
vulnscan -t 10.0.0.5 -c -v
vulnscan -t 10.0.0.0/24 -o /tmp/rapport.html -j /tmp/rapport.json
vulnscan -t 10.0.0.5 -s /tmp/rapport.csv
vulnscan --update
```

## Outils complémentaires (facultatifs)

Ces outils ne sont pas requis pour utiliser VulnScan, mais s'ils sont
installés, VulnScan les utilise automatiquement quand c'est pertinent :

| Outil | Rôle dans VulnScan | Installation (Kali/Debian) |
|---|---|---|
| `nikto` | Scan de vulnérabilités web complémentaire | `apt install nikto` |
| `nuclei` | Scan par templates (CVE récentes, mauvaises configs) | voir [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| `searchsploit` | Croisement des CVE trouvées avec les exploits publics d'Exploit-DB | `apt install exploitdb` |

## Outils non intégrés

Nessus, OpenVAS/Greenbone, Burp Suite et Metasploit ne sont pas intégrés
directement : ce sont des solutions nécessitant un serveur, une API ou une
licence, incompatibles avec un simple wrapper en ligne de commande. Ils
restent complémentaires à VulnScan et peuvent être utilisés en parallèle,
notamment pour l'exploitation manuelle des vulnérabilités identifiées.

## Sécurité

- La cible est validée (caractères autorisés, refus des valeurs commençant
  par `-`) et échappée avant d'être passée à `nmap`, pour empêcher toute
  injection de commande ou de flag.
- Les valeurs affichées dans le rapport HTML sont échappées (`htmlspecialchars`).

## Mise à jour

Procédure de mise à jour (exemples) :

1. Mise à jour simple (depuis le dossier d'installation) :

```bash
# si vous avez installé via le script et que 'vulnscan' est disponible
vulnscan --update
# ou, depuis le répertoire du projet
php modules/app.php --update
```

2. Si vous avez installé depuis Git :

```bash
cd VulnScan
git pull origin main
```

3. Si l'installation n'est pas un dépôt Git, VulnScan comparera le fichier
   local `VERSION` avec la version distante et téléchargera une archive ZIP
   depuis GitHub pour mettre à jour automatiquement (fallback `codeload`).

Notes et prérequis :
- Pour les mises à jour via Git : `git` doit être installé et disponible dans le PATH.
- Pour les mises à jour via archive ZIP : PHP doit disposer de `ZipArchive` (extension `zip`) pour l'extraction, et `allow_url_fopen` ou `curl` doit être disponible pour le téléchargement.
- Le mécanisme d'update vérifie la version distante (fichier `VERSION` sur la branche principale) et n'applique l'update que si une version plus récente est disponible.

Le dépôt de mise à jour utilisé est : https://github.com/KAMB02/VulnScan.git

## Contributions et idées d'amélioration

## Cadre légal

- **Usage autorisé :** Cet outil est fourni à des fins éducatives et d'audit de sécurité. N'utilisez `VulnScan` que sur des systèmes que vous possédez ou pour lesquels vous avez obtenu une autorisation explicite écrite du propriétaire. Toute utilisation non autorisée est illégale et strictement interdite.

- **Aucune garantie :** Le logiciel est fourni "tel quel" sans garantie d'aucune sorte, explicite ou implicite. L'auteur et les contributeurs ne garantissent pas la détection de toutes les vulnérabilités et ne peuvent être tenus responsables des dommages directs ou indirects résultant de l'utilisation du logiciel.

- **Responsabilité :** Vous êtes seul responsable de l'utilisation que vous faites de cet outil. Respectez les lois et régulations locales concernant les tests d'intrusion et la divulgation de vulnérabilités.

- **Licence et propriété :** Voir le fichier `LICENSE` pour les conditions de licence. Le dépôt et ses contributeurs restent propriétaires de leurs contributions selon les termes de la licence.


Toute personne peut contribuer à ce projet ou proposer des idées
d'amélioration. N'hésitez pas à ouvrir une issue ou une pull request sur le
référentiel GitHub : https://github.com/KAMB02/VulnScan.git
