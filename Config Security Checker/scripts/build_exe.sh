#!/usr/bin/env bash
set -e
# Build a single-file executable using pyinstaller (optional)
# Usage: install pyinstaller then run this script
pyinstaller --onefile --name=config-checker -n config_security_checker/cli.py || true
echo "If pyinstaller ran successfully, check dist/config-checker"
