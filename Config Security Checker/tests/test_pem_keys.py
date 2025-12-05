from pathlib import Path
from config_security_checker.detectors.pem_keys import PemKeyDetector
import pytest

def test_detect_pem_header(tmp_path):
    f = tmp_path / "key.pem"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----")
    d = PemKeyDetector()
    findings = d.scan(Path(f))
    assert any(fx['type'] == 'pem' for fx in findings)
