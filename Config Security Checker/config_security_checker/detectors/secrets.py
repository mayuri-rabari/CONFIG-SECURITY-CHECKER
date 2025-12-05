import re
from pathlib import Path
from .utils import read_text, shannon_entropy, is_likely_hash, is_base64_like
from typing import List, Dict, Tuple

# Strong whitelist prefixes (common API key prefixes)
KNOWN_SECRET_PREFIXES = [
    "AKIA", "ASIA", "AIza", "ghp_", "sk_live_", "sk_test_", "pk_live_", "pk_test_", "RGAPI-", "sq0atp-", "BT-", "xoxp-", "xoxb-"
]

# contexts that indicate assignment/JSON keys
ASSIGNMENT_CTX = re.compile(r'(?i)(?:["\']?(?:apikey|api_key|api-key|aws_access_key_id|aws_secret_access_key|secret|token|access_token|auth_token|password|pwd|client_secret|private_key|secret_key|key)["\']?\s*[:=])')

# patterns with score
REGEX_RULES: List[Tuple[str, re.Pattern, int]] = [
    ("Password assignment", re.compile(r'(?i)(?:password|passwd|pwd)[\s\"\'`]*[:=]\s*["\'`]?([^"\'>\s]{6,200})'), 9),
    ("Key-like assignment (API/TOKEN/SECRET/KEY)", re.compile(r'(?i)(?:\b(?:api[_-]?key|token|secret|access[_-]?token|auth|client[_-]?secret|private[_-]?key|aws_secret_access_key)\b)[\s\"\'`]*[:=]\s*["\'`]?(?P<t>[A-Za-z0-9_\-+/=]{16,512})'), 9),
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}'), 10),
    ("Private key header", re.compile(r'-----BEGIN (RSA )?PRIVATE KEY-----'), 10),
    ("OpenSSH private key header", re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), 10),
]

# fallback aggressive token (only used when aggressive=True)
GENERIC_FALLBACK = re.compile(r'([A-Za-z0-9_\-+/=]{40,512})')

class SecretDetector:
    def __init__(self, rules=None, aggressive=False):
        self.rules = rules or REGEX_RULES
        self.aggressive = aggressive

    def _validate_token(self, token: str) -> bool:
        t = token.strip()
        if not t:
            return False
        # known prefixes are high-confidence
        for p in KNOWN_SECRET_PREFIXES:
            if t.startswith(p):
                return True
        # ignore likely hashes
        if is_likely_hash(t):
            return False
        # base64-like: require high entropy and reasonable length
        if is_base64_like(t):
            if len(t) < 20:
                return False
            e = shannon_entropy(t)
            if e < 3.8:
                return False
            return True
        # alnum tokens: length + entropy
        if len(t) < 8:
            return False
        if shannon_entropy(t) < 3.0:
            return False
        # avoid placeholders
        lower = t.lower()
        placeholders = ["changeme", "your_key_here", "example", "dummy", "replace", "your_token", "your_api_key", "xxx"]
        for ph in placeholders:
            if ph in lower:
                return False
        return True

    def scan(self, path: Path, text: str = None) -> List[Dict]:
        findings = []
        if text is None:
            text = read_text(path)
        if not text:
            return findings

        # Primary rules
        for name, pattern, score in self.rules:
            for m in pattern.finditer(text):
                if "t" in m.groupdict():
                    token = m.group("t")
                else:
                    # grab first capturing group if exists else full match
                    token = m.group(1) if m.groups() else m.group(0)
                if not token:
                    token = m.group(0)
                if not self._validate_token(token):
                    continue
                findings.append({
                    "type": "secret",
                    "rule": name,
                    "match": token if len(token) <= 200 else token[:200] + "...",
                    "line": text[:m.start()].count("\n") + 1,
                    "score": score,
                    "note": "Contextual assignment + entropy/whitelist validation"
                })

        # Aggressive fallback
        if self.aggressive:
            for m in GENERIC_FALLBACK.finditer(text):
                token = m.group(1)
                if not self._validate_token(token):
                    continue
                findings.append({
                    "type": "secret",
                    "rule": "Generic fallback token",
                    "match": token[:200] + ("..." if len(token) > 200 else ""),
                    "line": text[:m.start()].count("\n") + 1,
                    "score": 5,
                    "note": "Aggressive fallback - enable only when hunting"
                })
        return findings
