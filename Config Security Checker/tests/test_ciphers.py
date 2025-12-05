from pathlib import Path
from config_security_checker.detectors.weak_ciphers import CipherDetector
import tempfile

def test_detect_tls1_token(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text("ssl_protocols TLSv1 TLSv1.1 TLSv1.2;")
    d = CipherDetector()
    findings = d.scan(Path(f))
    assert any(fx['type'] == 'weak-cipher' for fx in findings)
