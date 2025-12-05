import pytest
from pathlib import Path
from config_security_checker.detectors.secrets import SecretDetector
import tempfile

def test_detect_password_assignment(tmp_path):
    f = tmp_path / "a.env"
    f.write_text("DB_PASSWORD='hunter2'\nother=1\n")
    d = SecretDetector()
    findings = d.scan(Path(f))
    assert any(fx['rule'].startswith("Generic password") for fx in findings)
