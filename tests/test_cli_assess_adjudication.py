"""Tests for assess() adjudication branch and ev_conf_map keying."""

import pathlib
from unittest.mock import patch
from audit_packs.cli import assess
from audit_packs.models import (
    Finding,
    ControlFinding,
    AdjudicationResult,
    AdjudicationMode,
)

ROOT = pathlib.Path(__file__).parent.parent
PACKS = str(ROOT / "packs")
RULES = str(ROOT / "rules/weak-cipher.yaml")

_FINDING = Finding(
    check_id="CKV_AWS_19",
    engine="checkov",
    file="main.tf",
    line=5,
    severity="high",
    message="S3 bucket not encrypted",
    evidence="aws_s3_bucket",
)
_CF = ControlFinding(
    finding=_FINDING,
    framework="nist-800-53",
    control_id="SC-28",
    control_title="Protection of Information at Rest",
)
_ADJ_RESULT = AdjudicationResult(
    control_finding=_CF,
    detector_score=0.9,
    verifier_argument="",
    challenger_argument="",
    consensus_score=0.9,
    model_consensus=0.9,
    rationale="",
)

_MOCK_SARIF = {
    "runs": [
        {
            "tool": {"driver": {"name": "checkov", "rules": []}},
            "results": [
                {
                    "ruleId": "CKV_AWS_19",
                    "level": "error",
                    "message": {"text": "S3 bucket not encrypted"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.tf"},
                                "region": {"startLine": 5},
                            }
                        }
                    ],
                    "properties": {"severity": "high", "evidence": "aws_s3_bucket"},
                }
            ],
        }
    ]
}


def _patch_engines(codeql_sarif=None):
    """Return a context manager that patches all engine calls."""
    from contextlib import ExitStack
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with ExitStack() as stack:
            stack.enter_context(
                patch("asyncio.run", side_effect=RuntimeError("force sync"))
            )
            stack.enter_context(
                patch("audit_packs.cli.run_checkov", return_value=_MOCK_SARIF)
            )
            stack.enter_context(
                patch("audit_packs.cli.run_semgrep", return_value={"runs": []})
            )
            if codeql_sarif is not None:
                stack.enter_context(
                    patch(
                        "audit_packs.cli.read_codeql_sarif", return_value=codeql_sarif
                    )
                )
            stack.enter_context(
                patch("audit_packs.adjudicate.adjudicate", return_value=_ADJ_RESULT)
            )
            stack.enter_context(
                patch("audit_packs.evidence.evidence_confidence", return_value=0.88)
            )
            yield

    return _ctx()


def test_assess_adjudication_off_returns_control_statuses():
    """assess() with adj_mode=OFF must return ControlStatus objects without calling adjudicate."""
    repo = str(ROOT / "tests/fixtures/terraform")
    with _patch_engines():
        statuses = assess(
            repo, PACKS, RULES, ["nist-800-53"], adj_mode=AdjudicationMode.OFF
        )
    assert isinstance(statuses, list)


def test_assess_adjudication_advisory_runs_scoring_branch():
    """assess() with adj_mode=ADVISORY must enter the adjudication loop and return ControlStatus."""
    repo = str(ROOT / "tests/fixtures/terraform")
    with _patch_engines():
        with patch(
            "audit_packs.adjudicate.adjudicate", return_value=_ADJ_RESULT
        ) as mock_adj:
            statuses = assess(
                repo, PACKS, RULES, ["nist-800-53"], adj_mode=AdjudicationMode.ADVISORY
            )
    # adjudicate must have been called (not bypassed by the early-return path)
    assert mock_adj.called, "adjudicate() was never called in ADVISORY mode"
    assert isinstance(statuses, list)


def test_assess_evidence_confidence_not_defaulted():
    """evidence_confidence=0.88 must be reflected in scored findings, not silently defaulted to 0.4."""
    repo = str(ROOT / "tests/fixtures/terraform")
    captured_pairs = []

    original_gate = __import__(
        "audit_packs.confidence", fromlist=["apply_confidence_gate"]
    ).apply_confidence_gate

    def capturing_gate(pairs, **kwargs):
        captured_pairs.extend(pairs)
        return original_gate(pairs, **kwargs)

    with _patch_engines():
        with patch(
            "audit_packs.confidence.apply_confidence_gate", side_effect=capturing_gate
        ):
            assess(
                repo, PACKS, RULES, ["nist-800-53"], adj_mode=AdjudicationMode.ADVISORY
            )

    assert captured_pairs, "no (result, components) pairs reached the gate"
    for _result, components in captured_pairs:
        assert components.evidence_confidence == 0.88, (
            f"Expected 0.88 but got {components.evidence_confidence}; "
            "ev_conf_map id()-keying bug may still be present in assess()"
        )


def test_assess_includes_codeql_findings():
    """When codeql_sarif_dir is provided, assess() must include CodeQL findings."""
    repo = str(ROOT / "tests/fixtures/terraform")
    codeql_sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "codeql",
                        "rules": [
                            {"id": "CKV_AWS_19", "shortDescription": {"text": "test"}}
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CKV_AWS_19",
                        "level": "error",
                        "message": {"text": "CodeQL finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "main.tf"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                        "properties": {"severity": "high"},
                    }
                ],
            }
        ]
    }
    findings_seen = []

    original_map = __import__(
        "audit_packs.packs", fromlist=["map_findings"]
    ).map_findings

    def capturing_map(findings, *args, **kwargs):
        findings_seen.extend(findings)
        return original_map(findings, *args, **kwargs)

    with _patch_engines(codeql_sarif=codeql_sarif):
        with patch("audit_packs.cli.map_findings", side_effect=capturing_map):
            assess(
                repo,
                PACKS,
                RULES,
                ["nist-800-53"],
                adj_mode=AdjudicationMode.OFF,
                codeql_sarif_dir="/fake/codeql",
            )

    engines_seen = {f.engine for f in findings_seen}
    assert (
        "codeql" in engines_seen
    ), f"No CodeQL findings reached map_findings; engines seen: {engines_seen}"
