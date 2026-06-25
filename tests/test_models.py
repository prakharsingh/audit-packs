import pytest
from audit_packs.models import (
    Finding,
    ControlFinding,
    severity_rank,
    SEVERITIES,
    AssessmentStatus,
    ControlStatus,
    PathNode,
    AdjudicationResult,
    AdjudicationMode,
)


def test_finding_is_frozen():
    f = Finding(
        "CKV_AWS_19",
        "checkov",
        "main.tf",
        5,
        "high",
        "no encryption",
        "encrypted=false",
    )
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


# --- Phase 1: AssessmentStatus + ControlStatus ---


def test_assessment_status_values():
    assert {s.value for s in AssessmentStatus} == {
        "pass",
        "fail",
        "not_applicable",
        "manual",
    }


def test_assessment_status_is_string_enum():
    assert AssessmentStatus.PASS == "pass"
    assert AssessmentStatus.FAIL == "fail"
    assert AssessmentStatus.MANUAL == "manual"
    assert AssessmentStatus.NOT_APPLICABLE == "not_applicable"


def test_control_status_is_frozen():
    cs = ControlStatus(
        "soc2",
        "CC6.1",
        "Encryption at Rest",
        AssessmentStatus.PASS,
        check_ids=(("checkov", "CKV_AWS_19"),),
        findings=(),
        evidence=(),
    )
    with pytest.raises(Exception):
        cs.status = AssessmentStatus.FAIL  # type: ignore[misc]


def test_control_status_fields():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "msg", "ev")
    cf = ControlFinding(f, "soc2", "CC6.1", "Encryption at Rest")
    cs = ControlStatus(
        framework="soc2",
        control_id="CC6.1",
        control_title="Encryption at Rest",
        status=AssessmentStatus.FAIL,
        check_ids=(("checkov", "CKV_AWS_19"),),
        findings=(cf,),
        evidence=("ev",),
    )
    assert cs.framework == "soc2"
    assert cs.control_id == "CC6.1"
    assert cs.status == AssessmentStatus.FAIL
    assert len(cs.findings) == 1
    assert cs.findings[0].control_id == "CC6.1"


def test_control_status_manual_has_empty_findings():
    cs = ControlStatus(
        "soc2",
        "CC1.1",
        "Control Environment",
        AssessmentStatus.MANUAL,
        check_ids=(),
        findings=(),
        evidence=(),
    )
    assert cs.status == AssessmentStatus.MANUAL
    assert cs.findings == ()
    assert cs.check_ids == ()


# --- Compliance Framework Extension Models Tests ---


def test_finding_doc_context_defaults_to_empty():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 11, "high", "msg", "snippet")
    assert f.doc_context == ""


def test_finding_evidence_path_defaults_to_empty_tuple():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 11, "high", "msg", "snippet")
    assert f.evidence_path == ()


def test_pathnode_fields():
    pn = PathNode(
        file="models.py",
        line=14,
        snippet="user_id = request.args.get('id')",
        description="source",
    )
    assert pn.file == "models.py"
    assert pn.line == 14


def test_adjudication_mode_values():
    assert AdjudicationMode.OFF.value == "off"
    assert AdjudicationMode.ADVISORY.value == "advisory"
    assert AdjudicationMode.ENFORCE.value == "enforce"


def test_adjudication_result_fields():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 11, "high", "msg", "snippet")
    cf = ControlFinding(
        finding=f,
        framework="gdpr",
        control_id="SC-28",
        control_title="Protection of Information at Rest",
    )
    result = AdjudicationResult(
        control_finding=cf,
        detector_score=0.8,
        verifier_argument="data is stored unencrypted",
        adversarial_argument="this is test infra",
        judge_score=0.75,
        model_consensus=0.75,
        rationale="Evidence supports a real violation.",
    )
    assert result.model_consensus == result.judge_score
    assert result.rationale == "Evidence supports a real violation."
