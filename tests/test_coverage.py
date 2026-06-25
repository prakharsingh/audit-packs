"""Tests for coverage.py — compute_coverage() pure logic."""

import pathlib
from audit_packs.models import Finding, ControlFinding, AssessmentStatus
from audit_packs.coverage import compute_coverage

PACKS = str(pathlib.Path(__file__).parent.parent / "packs")


def _cf(check_id, control_id, framework="nist-800-53", engine="checkov"):
    f = Finding(check_id, engine, "main.tf", 5, "high", "msg", "ev")
    return ControlFinding(f, framework, control_id, "Title for " + control_id)


class TestComputeCoverage:
    def test_fail_status_when_finding_exists(self):
        cf = _cf("CKV_AWS_19", "SC-13")
        statuses = compute_coverage([cf], PACKS, ["nist-800-53"])
        sc13 = next(s for s in statuses if s.control_id == "SC-13")
        assert sc13.status == AssessmentStatus.FAIL
        assert len(sc13.findings) == 1

    def test_pass_status_when_no_finding_for_observable_control(self):
        # Provide a finding that does NOT hit SC-28; SC-28 should be PASS
        cf = _cf("CKV_AWS_19", "SC-13")
        statuses = compute_coverage([cf], PACKS, ["nist-800-53"])
        sc28 = next(s for s in statuses if s.control_id == "SC-28")
        assert sc28.status == AssessmentStatus.PASS
        assert sc28.findings == ()

    def test_manual_status_for_governance_controls(self):
        statuses = compute_coverage([], PACKS, ["soc2"])
        cc11 = next(s for s in statuses if s.control_id == "CC1.1")
        assert cc11.status == AssessmentStatus.MANUAL
        assert cc11.check_ids == ()

    def test_all_soc2_criteria_appear_in_coverage(self):
        statuses = compute_coverage([], PACKS, ["soc2"])
        ids = {s.control_id for s in statuses}
        # Spot-check across CC1–CC9, A1, C1
        for expected in ("CC1.1", "CC6.1", "CC7.2", "CC8.1", "CC9.1", "A1.1", "C1.1"):
            assert expected in ids, f"{expected} missing from soc2 coverage"

    def test_no_findings_all_observable_controls_are_pass(self):
        statuses = compute_coverage([], PACKS, ["nist-800-53"])
        for s in statuses:
            assert s.status == AssessmentStatus.PASS

    def test_coverage_includes_check_ids(self):
        statuses = compute_coverage([], PACKS, ["nist-800-53"])
        sc13 = next(s for s in statuses if s.control_id == "SC-13")
        assert ("checkov", "CKV_AWS_19") in sc13.check_ids

    def test_multiple_findings_all_captured_in_status(self):
        cfs = [
            _cf("CKV_AWS_19", "SC-13"),
            _cf("CKV_AWS_5", "SC-13"),
        ]
        statuses = compute_coverage(cfs, PACKS, ["nist-800-53"])
        sc13 = next(s for s in statuses if s.control_id == "SC-13")
        assert sc13.status == AssessmentStatus.FAIL
        assert len(sc13.findings) == 2

    def test_soc2_technical_control_fail_when_finding_present(self):
        cf = _cf("CKV_AWS_19", "CC6.1", framework="soc2")
        statuses = compute_coverage([cf], PACKS, ["soc2"])
        cc61 = next(s for s in statuses if s.control_id == "CC6.1")
        assert cc61.status == AssessmentStatus.FAIL

    def test_multi_framework_returns_statuses_for_all(self):
        statuses = compute_coverage([], PACKS, ["nist-800-53", "soc2"])
        frameworks = {s.framework for s in statuses}
        assert "nist-800-53" in frameworks
        assert "soc2" in frameworks

    def test_evidence_extracted_from_findings(self):
        f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "msg", "my-evidence")
        cf = ControlFinding(f, "nist-800-53", "SC-13", "Cryptographic Protection")
        statuses = compute_coverage([cf], PACKS, ["nist-800-53"])
        sc13 = next(s for s in statuses if s.control_id == "SC-13")
        assert "my-evidence" in sc13.evidence
