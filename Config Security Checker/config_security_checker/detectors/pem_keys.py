from pathlib import Path
from .utils import read_text
from typing import List, Dict
import re

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

class PemKeyDetector:
    def __init__(self):
        self.crypto = CRYPTO_AVAILABLE

    def scan(self, path: Path, text: str = None) -> List[Dict]:
        findings = []
        if text is None:
            text = read_text(path)
        if not text or "-----BEGIN" not in text:
            return findings

        pem_blocks = re.findall(r"(-----BEGIN [^-]+-----(?:.|\n)+?-----END [^-]+-----)", text, re.MULTILINE)
        for block in pem_blocks:
            header = block.splitlines()[0] if block.splitlines() else "-----BEGIN ???-----"
            item = {"type": "pem", "header": header}
            # attempt to parse key if cryptography available
            if self.crypto:
                try:
                    key = serialization.load_pem_private_key(block.encode(), password=None, backend=default_backend())
                    if isinstance(key, rsa.RSAPrivateKey):
                        size = key.key_size
                        item["rsa_bits"] = size
                        item["score"] = 10 if size < 2048 else 6
                        item["weak"] = size < 2048
                    elif isinstance(key, ec.EllipticCurvePrivateKey):
                        item["curve"] = key.curve.name
                        item["score"] = 6
                except Exception:
                    # possibly encrypted key or unsupported format - treat as high risk because private key found
                    item["score"] = 10
                    item["note"] = "Could be encrypted or unsupported private key format"
            else:
                # cannot parse, but presence of private key header is critical
                item["score"] = 10
            findings.append(item)
        return findings
