#!/usr/bin/env python3
"""Single-file Config Security Checker - combined version of package files for convenience."""
import re, sys, argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
except Exception:
    console = None

REGEX_RULES = [
    ("Generic password assignment", re.compile(r"(?i)(?:password|passwd)\s*[:=]\s*['\"]?([^\s'\"#]{6,200})['\"]?"), 5),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), 6),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{8,128})"), 7),
    ("Private RSA key header", re.compile(r"-----BEGIN (RSA )?PRIVATE KEY-----"), 10),
    ("SSH private key header", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), 10),
]

WEAK_CIPHERS = {
    "SSLv2": ["sslv2"],
    "SSLv3": ["sslv3"],
    "TLS1.0": ["tls1", "tlsv1", "tls1.0"],
    "RC4": ["rc4"],
    "DES": ["des", "3des", "des-cbc"],
    "NULL-CIPHER": ["null"],
    "EXPORT": ["export"],
}

def is_text_file(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
            if b"\0" in chunk:
                return False
            return True
    except Exception:
        return False

def read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except Exception:
        return ""

def detect_secrets(text: str):
    findings = []
    for name, pattern, score in REGEX_RULES:
        for m in pattern.finditer(text):
            preview = m.group(1) if m.groups() else m.group(0)
            if isinstance(preview, str) and len(preview) > 120:
                preview = preview[:120] + "..."
            findings.append({"type":"secret","rule":name,"match":preview,"line":text[:m.start()].count("\n") + 1,"score":score})
    return findings

def detect_weak_ciphers(text: str):
    findings = []
    lower = text.lower()
    for name, tokens in WEAK_CIPHERS.items():
        for t in tokens:
            if t.lower() in lower:
                findings.append({"type":"weak-cipher","cipher":name,"token":t,"score":5})
                break
    return findings

def detect_pem_keys(text: str):
    findings = []
    if "-----BEGIN" not in text:
        return findings
    pem_blocks = re.findall(r"(-----BEGIN [^-]+-----(?:.|\n)+?-----END [^-]+-----)", text, re.MULTILINE)
    for block in pem_blocks:
        header = block.splitlines()[0] if block.splitlines() else "-----BEGIN ???-----"
        item = {"type":"pem","header":header}
        if CRYPTO_AVAILABLE:
            try:
                key = serialization.load_pem_private_key(block.encode(), password=None, backend=default_backend())
                if isinstance(key, rsa.RSAPrivateKey):
                    size = key.key_size
                    item["rsa_bits"] = size
                    item["score"] = 9 if size < 2048 else 2
                    item["weak"] = size < 2048
                elif isinstance(key, ec.EllipticCurvePrivateKey):
                    item["curve"] = key.curve.name
            except Exception:
                pass
        findings.append(item)
    return findings

def scan_path(target: Path, max_size: int = 200000):
    results = {}
    for p in target.rglob("*"):
        try:
            if not p.is_file():
                continue
            if not is_text_file(p):
                continue
            if p.stat().st_size > max_size:
                continue
            text = read_text(p)
            file_findings = []
            file_findings += detect_secrets(text)
            file_findings += detect_weak_ciphers(text)
            file_findings += detect_pem_keys(text)
            if file_findings:
                results[str(p)] = file_findings
        except Exception:
            continue
    return results

def print_results(results):
    if not results:
        print("No issues found.")
        return
    if console:
        table = Table(title="Config Security Checker Results")
        table.add_column("File", overflow="fold")
        table.add_column("Type")
        table.add_column("Detail", overflow="fold")
        table.add_column("Score", justify="right")
        for file, issues in results.items():
            for issue in issues:
                t = issue.get("type","")
                detail = ""
                if t == "secret":
                    detail = f"{issue.get('rule')} @ line {issue.get('line')}: {issue.get('match')}"
                elif t == "weak-cipher":
                    detail = f"{issue.get('cipher')} (token {issue.get('token')})"
                elif t == "pem":
                    detail = issue.get('header',"")
                    if 'rsa_bits' in issue:
                        detail += f" - rsa {issue['rsa_bits']} bits"
                table.add_row(file, t, detail, str(issue.get('score',"")))
        console.print(table)
    else:
        for file, issues in results.items():
            print(f"== {file} ==")
            for issue in issues:
                print(issue)

def main(argv=None):
    parser = argparse.ArgumentParser(description="Config Security Checker - single-file")
    parser.add_argument("target", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--max-size", type=int, default=200000, help="Max file size to scan") 
    args = parser.parse_args(argv)
    target = Path(args.target)
    if not target.exists():
        print("Target not found", file=sys.stderr); sys.exit(2)
    results = scan_path(target, max_size=args.max_size)
    print_results(results)

if __name__ == '__main__':
    main()
