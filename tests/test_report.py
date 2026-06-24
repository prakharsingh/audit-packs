from audit_packs.models import Finding, ControlFinding
from audit_packs.report import build_comments, gate_failed

def _cf(sev, control="SC-13"):
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 11, sev, "no encryption", "encrypted=false")
    return ControlFinding(f, "nist-800-53", control, "Cryptographic Protection")

def test_build_comments_one_per_finding_with_control_tag():
    comments = build_comments([_cf("high")], commit_sha="abc")
    assert len(comments) == 1
    c = comments[0]
    assert c["path"] == "main.tf"
    assert c["line"] == 11
    assert c["side"] == "RIGHT"
    assert "nist-800-53" in c["body"]
    assert "SC-13" in c["body"]
    assert "encrypted=false" in c["body"]

def test_gate_failed_respects_threshold():
    assert gate_failed([_cf("high")], fail_on="high") is True
    assert gate_failed([_cf("medium")], fail_on="high") is False
    assert gate_failed([], fail_on="low") is False
