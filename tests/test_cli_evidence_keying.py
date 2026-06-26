"""Regression test: evidence_confidence must be passed through, not silently defaulted."""

import pathlib
from unittest.mock import patch
from audit_packs.cli import analyze
from audit_packs.models import Finding, ControlFinding, AdjudicationResult

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


def test_evidence_confidence_is_not_always_default():
    """When enrich() returns non-default evidence, score must differ from a 0.4-evidence baseline."""
    changed = {"main.tf": {5}}

    # Mock engines to return a single finding
    mock_sarif = {
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

    with (
        patch("asyncio.run", side_effect=RuntimeError("force sync")),
        patch("audit_packs.cli.run_checkov", return_value=mock_sarif),
        patch("audit_packs.cli.run_semgrep", return_value={"runs": []}),
        patch("audit_packs.cli.run_git_diff", return_value=""),
        patch("audit_packs.agents.build_agents", return_value=[]),
        patch("audit_packs.evidence.enrich", side_effect=lambda f, txt, ctx: f),
        patch(
            "audit_packs.evidence.evidence_confidence", return_value=0.99
        ) as mock_ev_conf,
        patch("audit_packs.adjudicate.adjudicate", return_value=_ADJ_RESULT),
    ):
        scored = analyze(
            str(ROOT / "tests/fixtures/terraform"),
            changed,
            PACKS,
            RULES,
            ["nist-800-53"],
        )

    # evidence_confidence must have been called (not bypassed)
    assert mock_ev_conf.called, "evidence_confidence was never called"
    # At least one scored finding must exist
    assert scored, "no findings scored"
    # The evidence component must reflect 0.99, not the fallback 0.4
    for sf in scored:
        assert sf.components.evidence_confidence == 0.99, (
            f"Expected evidence_confidence=0.99 but got {sf.components.evidence_confidence}; "
            "id()-keying bug may still be present"
        )
