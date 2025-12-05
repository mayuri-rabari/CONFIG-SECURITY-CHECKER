from pathlib import Path
from .utils import read_text
from typing import List, Dict
import re

# List of weak cipher tokens (human-friendly names)
WEAK_CIPHER_TOKENS = {
    "SSLv2": ["sslv2"],
    "SSLv3": ["sslv3"],
    "TLS1.0": ["tls1", "tlsv1", "tls1.0"],
    "RC4": ["rc4"],
    "DES/3DES": ["des", "3des", "des-cbc", "des-ede3"],
    "NULL": ["null"],
    "EXPORT": ["export"],
    "MD5": ["md5"],
}

# configuration context indicators where ciphers are legitimately set
CIPHER_CONTEXT_PATTERNS = [
    re.compile(r'(?i)\bssl_cipher(s)?\b'),      # nginx ssl_ciphers
    re.compile(r'(?i)\bSSLCipherSuite\b'),      # apache
    re.compile(r'(?i)\bciphers?\b'),            # haproxy, libs
    re.compile(r'(?i)\bcipher_suite\b'),        # json config
    re.compile(r'(?i)\bssl_protocols\b'),
    re.compile(r'(?i)\bopenssl_cipher\b'),
    re.compile(r'(?i)\bsslengine\b'),
]

# regex to find likely cipher lists in a line
CIPHER_LIST_RX = re.compile(r'(?i)[A-Za-z0-9\-\:\s,\/\+]+')

class CipherDetector:
    def __init__(self, weak_map=None):
        self.weak_map = weak_map or WEAK_CIPHER_TOKENS

    def _line_in_context(self, text: str, pos: int) -> bool:
        """
        Return True if the match position is in a line that contains a context indicator,
        or if a nearby line (within +/-3 lines) contains one.
        """
        lines = text.splitlines()
        # compute line number
        line_no = text[:pos].count("\n")
        start = max(0, line_no - 3)
        end = min(len(lines), line_no + 4)
        for ln in lines[start:end]:
            for pat in CIPHER_CONTEXT_PATTERNS:
                if pat.search(ln):
                    return True
        return False

    def scan(self, path: Path, text: str = None) -> List[Dict]:
        findings = []
        if text is None:
            text = read_text(path)
        if not text:
            return findings
        lower = text.lower()
        # fast path: look for cipher context first
        has_context = any(p.search(text) for p in CIPHER_CONTEXT_PATTERNS)
        # If no explicit context, we'll still check for explicit config file names (nginx/apache/sshd)
        filename = path.name.lower()
        config_like_names = ("nginx", "httpd", "sshd", "haproxy", "openssl", "apache", "ssl", "tls")
        potential_config_file = any(k in filename for k in config_like_names)

        for name, tokens in self.weak_map.items():
            for t in tokens:
                # only trigger if context exists or filename looks config-like
                if (has_context or potential_config_file):
                    # confirm token appears within a cipher-like chunk (avoid words inside normal strings)
                    idx = lower.find(t.lower())
                    if idx == -1:
                        continue
                    # ensure the line appears inside a cipher setting context
                    if not self._line_in_context(text, idx):
                        # if the filename strongly suggests config, allow but with lower confidence
                        score = 5 if potential_config_file else 0
                        if score == 0:
                            continue
                    else:
                        score = 6
                    findings.append({
                        "type": "weak-cipher",
                        "cipher": name,
                        "token": t,
                        "score": score,
                        "line": text[:idx].count("\n") + 1
                    })
                    break
        return findings
