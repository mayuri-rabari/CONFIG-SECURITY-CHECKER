# Config Security Checker

Small CLI tool to scan repositories and servers for:
- Hard-coded credentials (passwords, tokens, AWS keys)
- Weak cipher/protocol tokens (SSLv3, TLS1.0, RC4, DES)
- PEM private keys with small RSA sizes (if cryptography is available)

## Quickstart

1. Create env:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt


2. Run:
python -m config_security_checker.cli /path/to/scan


3. JSON output:
python -m config_security_checker.cli /path --json