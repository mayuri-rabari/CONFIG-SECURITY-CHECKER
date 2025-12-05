<h1 align="center">🔐 Config Security Checker</h1>
<p align="center">A professional-grade static configuration analyzer that detects secrets, weak ciphers, private keys & high-risk misconfigurations with near-zero false positives.</p> <p align="center"> <img src="https://img.shields.io/badge/Language-Python%203.8%2B-blue"> <img src="https://img.shields.io/badge/SAST-Static%20Analysis-yellow"> <img src="https://img.shields.io/badge/Detection-Secrets%20%7C%20Crypto%20%7C%20Keys-red"> <img src="https://img.shields.io/badge/License-MIT-green"> <img src="https://img.shields.io/badge/Maintainer-Mayuri-purple"> </p>
🚀 Overview

Config Security Checker is a next-generation static analysis engine designed to identify:

Hardcoded secrets & credentials

API keys, JWT tokens, OAuth secrets

Weak or deprecated SSL/TLS ciphers

RSA/EC/SSH private keys & insecure PEM blocks

High-entropy secret tokens

Insecure application and infrastructure configurations

Vulnerable nginx / Apache / HAProxy SSL settings

Sensitive .env, JSON, YAML, TOML and config leaks

The engine uses contextual detection, entropy scoring, heuristics, and an advanced false-positive suppression layer to ensure highly accurate results.

## 🧠 Architecture

```
                         +-----------------------------------------+
                         |             CLI Interface               |
                         +-------------------------+---------------+
                                                   |
                                                   v
        +------------------------------------------------------------------+
        |                          Scanner Core                             |
        |------------------------------------------------------------------|
        |  • Tokenizer Engine                                              |
        |  • Entropy Analyzer                                              |
        |  • Context-Based Secret Detector                                 |
        |  • Weak Cipher Detector                                          |
        |  • PEM / Private Key Classification                              |
        +-------------------------------+----------------------------------+
                                        |
                                        v
        +------------------------------------------------------------------+
        |                 False Positive Suppression Layer                 |
        |------------------------------------------------------------------|
        |  • Ignores VersionTables / Hash DBs                              |
        |  • Ignores CMS metadata & signature datasets                     |
        |  • Ignores minified / bundled JS                                 |
        |  • Ignores known safe non-sensitive patterns                     |
        +-------------------------------+----------------------------------+
                                        |
                                        v
        +------------------------------------------------------------------+
        |                      Output & Reporting                           |
        |------------------------------------------------------------------|
        |  • Pretty Console Tables                                         |
        |  • JSON Output for CI/CD                                         |
        |  • Severity Scoring                                              |
        |  • File-level Reporting                                          |
        +------------------------------------------------------------------+
```


✨ Key Features
✔ Secret Detection

Context-aware detection + entropy scoring to minimize false positives.

✔ Weak Cipher Identification

Detects DES, 3DES, RC4, NULL, EXPORT ciphers & old TLS versions.

✔ Private Key Detection

Identifies RSA, EC, PKCS8, OpenSSH keys with severity ranking.

✔ Noise-Free Results

Automatic suppression for:

VersionTables / checksums / hashed files

CMS signature DBs

Minified/packed JS

Vendor frameworks

Auto-generated files

✔ Developer & CI Friendly

JSON output

Pipe-friendly commands

Filtering & exclusion options

Aggressive deep-scan mode

📘 Usage

Below is the complete usage reference for all CLI features.

🔹 Basic Scan
config-checker .


Scans the current directory recursively.

🔹 Scan a Specific Path
config-checker <path>


Examples:

config-checker C:\Users\...
config-checker /etc/nginx
config-checker ./backend

🔹 JSON Output (for CI/CD)
config-checker . --json


Save JSON:

config-checker . --json > report.json

🔹 Filter by Minimum Severity Score
config-checker . --min-score 7


Range:

1–4 → Low

5–6 → Medium

7–8 → High

9–10 → Critical

🔹 Exclude Folders
config-checker . -x node_modules -x VersionTables -x ScanData

🔹 Exclude File Extensions
config-checker . --exclude-ext .log .min.js .cache

🔹 Only Show Specific Finding Types
Only secrets:
config-checker . --only secrets

Only crypto findings:
config-checker . --only crypto

Only private key leaks:
config-checker . --only keys

🔹 Aggressive Deep Scan
config-checker . --aggressive


Deep mode:

Expands heuristics

Scans borderline text/binary files

Disables some suppression rules

🔹 Quiet Mode (Less Noise)
config-checker . --quiet

🔹 Limit Maximum File Size (MB)
config-checker . --max-size 10


(default: 5 MB)

🔹 Save Output to File
config-checker . --output findings.txt

🔹 Full Help Menu
config-checker --help

📄 Summary of All Commands
Command	Description
config-checker .	Scan current directory
--json	Output in JSON
--min-score <int>	Filter by severity
--aggressive	Enable deep scan
--quiet	Show only findings
-x <dir>	Exclude directories
--exclude-ext <ext>	Exclude file types
--only <type>	secrets, crypto, keys
--max-size <MB>	Skip large files
--output <file>	Save results
--help	Show help
📁 Supported File Types

.env

.json

.yaml / .yml

.ini

.cfg

.conf

.pem / .key

Python / JS / TS / Go / PHP / Java config files

Any text-based configuration file

🚫 Noise Suppression (Auto-Ignored)

VersionTables

CMSPattern databases

Checksums / signature lists

Minified JavaScript

Vendor bundles & framework assets

Binary-like files

Generated cache files

📊 Example Output
File                    Type          Severity   Detail                       Score
─────────────────────────────────────────────────────────────────────────────────────
config/app.conf         weak-cipher   HIGH       TLS1.0 detected               8
.env                    secret        CRITICAL   AWS_SECRET_ACCESS_KEY        10
keys/id_rsa             private-key   CRITICAL   RSA Private Key (2048-bit)   10
