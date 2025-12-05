from pathlib import Path
from .detectors.secrets import SecretDetector
from .detectors.weak_ciphers import CipherDetector
from .detectors.pem_keys import PemKeyDetector
from .detectors.utils import is_text_file, read_text, is_likely_hash_file
import fnmatch

# conservative set of globs we consider config-like
CONFIG_GLOBS = [
    "*.conf", "*.cnf", "*.cfg", "*.env", "*.yml", "*.yaml", "*.json", "*.ini",
    "Dockerfile", "*.pem", "*.key", "docker-compose.yml", "compose.yaml",
    "*.php", "*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "nginx.conf", "httpd.conf", "sshd_config"
]

class Scanner:
    def __init__(self, base_path: Path, verbose=False, follow_symlinks=False, max_size=300000, excludes=None, allowlist_path=None, aggressive=False):
        self.base_path = Path(base_path)
        self.verbose = verbose
        self.follow_symlinks = follow_symlinks
        self.max_size = max_size
        self.secret_detector = SecretDetector(aggressive=aggressive)
        self.cipher_detector = CipherDetector()
        self.pem_detector = PemKeyDetector()
        self.excludes = [str(e) for e in (excludes or [])]
        self.allowlist = self._load_allowlist(allowlist_path)

    def _load_allowlist(self, path):
        patterns = []
        if not path:
            return patterns
        try:
            with open(path, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    patterns.append(ln)
        except Exception:
            pass
        return patterns

    def _is_excluded(self, path: Path):
        s = str(path)
        # allowlist overrides exclusion: if path matches allowlist, do not exclude
        for pat in self.allowlist:
            if fnmatch.fnmatch(s, pat) or fnmatch.fnmatch(path.name, pat):
                return False
        for ex in self.excludes:
            if ex and (ex in s or fnmatch.fnmatch(s, ex) or fnmatch.fnmatch(path.name, ex)):
                return True
        return False

    def _iter_files(self):
        for p in self.base_path.rglob("*"):
            try:
                if p.is_file():
                    if self._is_excluded(p):
                        if self.verbose:
                            print(f"[-] Skipping excluded {p}")
                        continue
                    yield p
            except Exception:
                continue

    def scan(self):
        results = {}
        for p in self._iter_files():
            try:
                if not is_text_file(p):
                    continue
                # skip large non-config files unless they match config globs
                if p.stat().st_size > self.max_size and not any(fnmatch.fnmatch(p.name, g) for g in CONFIG_GLOBS):
                    if self.verbose:
                        print(f"[-] Skipping large file {p}")
                    continue
            except Exception:
                continue

            text = read_text(p)
            if not text:
                continue

            # If file looks like a hash manifest / signature dataset -> conservative path:
            if is_likely_hash_file(p, text):
                if self.verbose:
                    print(f"[-] Detected manifest/hash dataset -> skipping secret detection: {p}")
                issues = []
                issues += self.cipher_detector.scan(p, text=text)
                issues += self.pem_detector.scan(p, text=text)
            else:
                # normal scanning
                issues = []
                issues += self.secret_detector.scan(p, text=text)
                issues += self.cipher_detector.scan(p, text=text)
                issues += self.pem_detector.scan(p, text=text)

            # dedupe
            uniq = []
            seen = set()
            for f in issues:
                key = (f.get("type"), f.get("rule", f.get("cipher", f.get("header"))), f.get("line"))
                if key in seen:
                    continue
                seen.add(key)
                uniq.append(f)

            if uniq:
                results[str(p)] = uniq
                if self.verbose:
                    print(f"[+] {p}: {len(uniq)} findings")
        return results
