import pytest
from audit_packs.models import (
    Finding,
    ControlFinding,
    AdjudicationResult,
    AdjudicationMode,
)
from audit_packs.confidence import (
    ScoreComponents,
    score_finding,
    apply_confidence_gate,
    get_historical_precision,
    update_precision,
    DEFAULT_WEIGHTS,
)


def _result(judge_score=0.8):
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "msg", "snippet")
    cf = ControlFinding(f, "gdpr", "SC-28", "Protection at Rest")
    return AdjudicationResult(
        control_finding=cf,
        detector_score=judge_score,
        verifier_argument="real violation",
        adversarial_argument="test infra",
        judge_score=judge_score,
        model_consensus=judge_score,
        rationale="Evidence is clear.",
    )


def _components(**overrides):
    defaults = dict(
        rule_confidence=0.9,
        evidence_confidence=0.7,
        model_consensus=0.8,
        historical_precision=0.8,
        control_severity=0.8,
        flow_confidence=0.5,
    )
    defaults.update(overrides)
    return ScoreComponents(**defaults)


def test_default_weights_sum_to_1():
    assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.001


def test_score_finding_weighted_sum():
    result = _result(judge_score=0.8)
    comps = _components(
        rule_confidence=1.0,
        evidence_confidence=1.0,
        model_consensus=1.0,
        historical_precision=1.0,
        control_severity=1.0,
        flow_confidence=1.0,
    )
    score = score_finding(result, comps, DEFAULT_WEIGHTS)
    assert score == pytest.approx(1.0)


def test_score_finding_zero_when_all_zeros():
    result = _result(judge_score=0.0)
    comps = _components(
        rule_confidence=0.0,
        evidence_confidence=0.0,
        model_consensus=0.0,
        historical_precision=0.0,
        control_severity=0.0,
        flow_confidence=0.0,
    )
    score = score_finding(result, comps, DEFAULT_WEIGHTS)
    assert score == pytest.approx(0.0)


def test_apply_gate_enforce_suppresses_below_threshold():
    result = _result(judge_score=0.4)
    comps = _components(
        model_consensus=0.4,
        rule_confidence=0.3,
        evidence_confidence=0.4,
        historical_precision=0.4,
        control_severity=0.4,
        flow_confidence=0.4,
    )
    pairs = [(result, comps)]
    scored = apply_confidence_gate(
        pairs, threshold=0.70, mode=AdjudicationMode.ENFORCE, weights=DEFAULT_WEIGHTS
    )
    assert len(scored) == 1
    assert scored[0].surfaced is False
    assert "0.70" in scored[0].suppression_reason


def test_apply_gate_enforce_surfaces_above_threshold():
    result = _result(judge_score=0.9)
    comps = _components()
    pairs = [(result, comps)]
    scored = apply_confidence_gate(
        pairs, threshold=0.70, mode=AdjudicationMode.ENFORCE, weights=DEFAULT_WEIGHTS
    )
    assert scored[0].surfaced is True
    assert scored[0].suppression_reason == ""


def test_apply_gate_advisory_surfaces_all():
    result = _result(judge_score=0.1)
    comps = _components(
        model_consensus=0.1,
        rule_confidence=0.1,
        evidence_confidence=0.1,
        historical_precision=0.1,
        control_severity=0.1,
        flow_confidence=0.1,
    )
    pairs = [(result, comps)]
    scored = apply_confidence_gate(
        pairs, threshold=0.70, mode=AdjudicationMode.ADVISORY, weights=DEFAULT_WEIGHTS
    )
    assert scored[0].surfaced is True


def test_apply_gate_off_surfaces_all_regardless_of_score():
    result = _result(judge_score=0.0)
    comps = _components(
        model_consensus=0.0,
        rule_confidence=0.0,
        evidence_confidence=0.0,
        historical_precision=0.0,
        control_severity=0.0,
        flow_confidence=0.0,
    )
    pairs = [(result, comps)]
    scored = apply_confidence_gate(
        pairs, threshold=0.70, mode=AdjudicationMode.OFF, weights=DEFAULT_WEIGHTS
    )
    assert scored[0].surfaced is True


def test_get_historical_precision_default_prior():
    score = get_historical_precision("UNKNOWN_CHECK", "gdpr", {})
    assert score == pytest.approx(4 / 5)


def test_get_historical_precision_from_data():
    data = {"CKV_AWS_19:gdpr": {"alpha": 7, "beta": 3}}
    score = get_historical_precision("CKV_AWS_19", "gdpr", data)
    assert score == pytest.approx(0.7)


def test_update_precision_creates_entry_if_missing():
    data = {}
    updated = update_precision("CKV_AWS_19", "gdpr", data)
    assert updated["CKV_AWS_19:gdpr"]["alpha"] == 5
    assert updated["CKV_AWS_19:gdpr"]["beta"] == 1


def test_update_precision_increments_alpha():
    data = {"CKV_AWS_19:gdpr": {"alpha": 5, "beta": 1}}
    updated = update_precision("CKV_AWS_19", "gdpr", data)
    assert updated["CKV_AWS_19:gdpr"]["alpha"] == 6
