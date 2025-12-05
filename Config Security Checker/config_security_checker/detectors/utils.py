from pathlib import Path
import math
import re

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

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for v in freq.values():
        p = v / length
        entropy -= p * math.log2(p)
    return entropy

_hex_re = re.compile(r'^[a-fA-F0-9]{32,128}$')
_base64_re = re.compile(r'^[A-Za-z0-9+/=]{20,}$')

def is_likely_hash(s: str) -> bool:
    s = s.strip()
    if _hex_re.match(s):
        ln = len(s)
        if ln in (32, 40, 64, 128) or ln >= 32:
            return True
    return False

def is_base64_like(s: str) -> bool:
    return bool(_base64_re.match(s.strip()))

def is_likely_hash_file(path: Path, text: str) -> bool:
    """
    Heuristic: if file contains many lines that look like hex hashes or base64-ish short chunks,
    or filename contains manifest/versiontable keywords, treat it as an asset manifest/hash table.
    """
    name = path.name.lower()
    manifest_keywords = ["sha", "checksum", "versiontables", "manifest", "hashes", "checksums", "assets", "digest", "versiontables", "version table"]
    if any(k in name for k in manifest_keywords):
        return True

    lines = text.splitlines()
    sample = lines[:200]
    if not sample:
        return False
    hash_like = 0
    for ln in sample:
        token = ln.strip().split()[-1] if ln.strip().split() else ""
        if is_likely_hash(token) or is_base64_like(token):
            hash_like += 1
    if len(sample) >= 10 and (hash_like / len(sample)) > 0.25:
        return True
    return False
