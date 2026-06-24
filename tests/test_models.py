import pytest
from audit_packs.models import Finding, ControlFinding, severity_rank, SEVERITIES

def test_finding_is_frozen():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "no encryption", "encrypted=false")
    with pytest.raises(Exception):
        f.line = 6  # type: ignore[misc]

def test_severity_rank_orders_ascending():
    ranks = [severity_rank(s) for s in SEVERITIES]
    assert ranks == sorted(ranks)
    assert severity_rank("critical") > severity_rank("low")

def test_control_finding_wraps_finding():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "msg", "ev")
    cf = ControlFinding(f, "nist-800-53", "SC-13", "Cryptographic Protection")
    assert cf.finding.check_id == "CKV_AWS_19"
    assert cf.control_id == "SC-13"
