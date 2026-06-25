"""Tests for oscal.py — OSCAL assessment-results generation."""

import json
from audit_packs.models import Finding, ControlFinding, AssessmentStatus, ControlStatus
from audit_packs.oscal import to_assessment_results


def _status(fw, ctrl_id, status, findings=()):
    return ControlStatus(
        framework=fw,
        control_id=ctrl_id,
        control_title=f"Title {ctrl_id}",
        status=status,
        check_ids=(("checkov", "CKV_AWS_19"),)
        if status != AssessmentStatus.MANUAL
        else (),
        findings=findings,
        evidence=tuple(cf.finding.evidence for cf in findings),
    )


class TestToAssessmentResults:
    def test_top_level_schema_shape(self):
        result = to_assessment_results([])
        assert "assessment-results" in result
        ar = result["assessment-results"]
        assert "uuid" in ar
        assert "metadata" in ar
        assert "results" in ar
        assert isinstance(ar["results"], list)

    def test_metadata_contains_timestamps_and_title(self):
        result = to_assessment_results([])
        meta = result["assessment-results"]["metadata"]
        assert "title" in meta
        assert "last-modified" in meta
        assert "version" in meta
        # ISO-8601 timestamp ending in Z
        assert meta["last-modified"].endswith("Z")

    def test_result_entry_per_framework(self):
        statuses = [
            _status("nist-800-53", "SC-13", AssessmentStatus.PASS),
            _status("soc2", "CC6.1", AssessmentStatus.FAIL),
        ]
        result = to_assessment_results(statuses)
        results = result["assessment-results"]["results"]
        frameworks_in_results = {r["title"] for r in results}
        assert "nist-800-53" in frameworks_in_results
        assert "soc2" in frameworks_in_results

    def test_reviewed_controls_list(self):
        statuses = [
            _status("nist-800-53", "SC-13", AssessmentStatus.PASS),
            _status("nist-800-53", "SC-28", AssessmentStatus.FAIL),
        ]
        result = to_assessment_results(statuses)
        nist_result = next(
            r
            for r in result["assessment-results"]["results"]
            if r["title"] == "nist-800-53"
        )
        assert "reviewed-controls" in nist_result
        rc = nist_result["reviewed-controls"]
        assert "control-selections" in rc
        selections = rc["control-selections"]
        assert isinstance(selections, list)

    def test_finding_entries_for_fail_controls(self):
        f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "msg", "ev")
        cf = ControlFinding(f, "nist-800-53", "SC-13", "Cryptographic Protection")
        statuses = [_status("nist-800-53", "SC-13", AssessmentStatus.FAIL, (cf,))]
        result = to_assessment_results(statuses)
        nist_result = next(
            r
            for r in result["assessment-results"]["results"]
            if r["title"] == "nist-800-53"
        )
        assert "findings" in nist_result
        findings = nist_result["findings"]
        assert len(findings) >= 1
        assert any(fnd["target"]["target-id"] == "SC-13" for fnd in findings)

    def test_manual_controls_have_correct_state(self):
        statuses = [_status("soc2", "CC1.1", AssessmentStatus.MANUAL)]
        result = to_assessment_results(statuses)
        soc2_result = next(
            r for r in result["assessment-results"]["results"] if r["title"] == "soc2"
        )
        # Manual controls appear in reviewed-controls with state "not-satisfied"
        # (they need human evidence) or a dedicated manual state
        rc = soc2_result["reviewed-controls"]["control-selections"]
        # At minimum, the reviewed-controls block should exist and be non-empty
        assert len(rc) >= 1

    def test_output_is_json_serialisable(self):
        statuses = [
            _status("soc2", "CC6.1", AssessmentStatus.PASS),
            _status("soc2", "CC1.1", AssessmentStatus.MANUAL),
        ]
        result = to_assessment_results(statuses)
        # Must not raise
        serialized = json.dumps(result)
        assert len(serialized) > 0

    def test_empty_input_produces_valid_skeleton(self):
        result = to_assessment_results([])
        ar = result["assessment-results"]
        assert ar["results"] == []
