import os
from unittest.mock import patch
from audit_packs_action.cli import validate_policies, init_wizard, main


def test_validate_policies_non_existent(tmp_path):
    """Validate policies when packs/rules dirs don't exist returns failure."""
    non_existent = str(tmp_path / "does-not-exist")
    code = validate_policies(non_existent, non_existent)
    assert code != 0


def test_validate_policies_valid_packs_rules(tmp_path):
    """Validate policies with valid minimal pack and semgrep rule."""
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()
    pack_conf = packs_dir / "controls.yaml"
    pack_conf.write_text("""
title: "NIST 800-53 Minimal"
controls:
  - id: SC-13
    title: Cryptographic Protection
""")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_conf = rules_dir / "weak-cipher.yaml"
    rule_conf.write_text("""
rules:
  - id: weak-cipher
    message: Use of weak cipher
    severity: ERROR
    languages:
      - python
""")

    code = validate_policies(str(packs_dir), str(rules_dir))
    assert code == 0


def test_validate_policies_invalid_pack(tmp_path):
    """Validate policies with invalid pack file (missing required fields) returns error code."""
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()
    pack_conf = packs_dir / "controls.yaml"
    pack_conf.write_text("""
title: "NIST 800-53 Minimal"
# Missing controls
""")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_conf = rules_dir / "weak-cipher.yaml"
    rule_conf.write_text("""
rules:
  - id: weak-cipher
    message: Use of weak cipher
    severity: ERROR
    languages:
      - python
""")

    code = validate_policies(str(packs_dir), str(rules_dir))
    assert code != 0


def test_init_wizard(tmp_path):
    """Verify init wizard creates audit-models.yaml, audit.yml workflow, and org-policy template."""
    with patch("builtins.input", side_effect=["nist-800-53,soc2", "y", "y", "y"]):
        code = init_wizard(str(tmp_path))
        assert code == 0

        # Check that audit-models.yaml is created
        assert (tmp_path / "audit-models.yaml").exists()

        # Check GHA workflow
        workflow_path = tmp_path / ".github" / "workflows" / "audit.yml"
        assert workflow_path.exists()
        assert "nist-800-53,soc2" in workflow_path.read_text()

        # Check custom policy template
        org_policy_path = tmp_path / "packs" / "org-policy" / "controls.yaml"
        assert org_policy_path.exists()
        assert "Internal Acme Corp Security Policy" in org_policy_path.read_text()


def test_slack_notification_integration():
    """Verify Slack webhook POST is invoked when slack_webhook arg is passed."""
    from audit_packs_core.models import ControlFinding, Finding
    from audit_packs_ai.adjudicate import AdjudicationResult
    from audit_packs_ai.confidence import ScoreComponents, ScoredFinding

    # Build mock scored findings
    f = Finding(
        check_id="CKV_AWS_19",
        file="s3.tf",
        line=10,
        severity="high",
        message="S3 bucket not encrypted",
        evidence="encryption=false",
        engine="checkov",
    )
    cf = ControlFinding(
        finding=f,
        framework="soc2",
        control_id="CC6.1",
        control_title="Encryption at rest",
        evidence_requirements=[],
    )
    adj = AdjudicationResult(
        control_finding=cf,
        detector_score=0.9,
        verifier_argument="pro",
        challenger_argument="con",
        consensus_score=0.9,
        model_consensus=0.9,
        rationale="Clear violation",
    )
    comps = ScoreComponents(
        rule_confidence=0.9,
        evidence_confidence=0.8,
        model_consensus=0.9,
        historical_precision=1.0,
        control_severity=0.8,
        flow_confidence=1.0,
    )
    sf = ScoredFinding(
        result=adj,
        components=comps,
        finding_score=0.9,
        surfaced=True,
        suppression_reason="",
    )

    with (
        patch("requests.post") as mock_post,
        patch("audit_packs_action.cli.run_git_diff", return_value=""),
        patch("audit_packs_action.cli.parse_unified_diff", return_value={}),
        patch("audit_packs_action.cli.analyze", return_value=[sf]),
        patch("audit_packs_action.cli.assess", return_value=[]),
    ):
        test_args = [
            "audit-packs",
            "--slack-webhook",
            "https://hooks.slack.com/services/T00/B00/X00",
            "--scan-mode",
            "diff",
            "--fail-on",
            "high",
        ]
        with patch("sys.argv", test_args):
            # GITHUB_REPOSITORY is empty/not set so it runs in local report mode
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": ""}, clear=True):
                main()
                mock_post.assert_called_once()
                args, kwargs = mock_post.call_args
                payload = kwargs["json"]
                assert "attachments" in payload
                assert "blocks" in payload["attachments"][0]


def test_jira_notification_integration():
    """Verify Jira issue creation POST is invoked when jira args are passed."""
    from audit_packs_core.models import (
        ControlFinding,
        Finding,
        ControlStatus,
        AssessmentStatus,
    )
    from audit_packs_ai.adjudicate import AdjudicationResult
    from audit_packs_ai.confidence import ScoreComponents, ScoredFinding

    # Build mock findings
    f = Finding(
        check_id="CKV_AWS_19",
        file="s3.tf",
        line=10,
        severity="high",
        message="S3 bucket not encrypted",
        evidence="encryption=false",
        engine="checkov",
    )
    cf = ControlFinding(
        finding=f,
        framework="soc2",
        control_id="CC6.1",
        control_title="Encryption at rest",
        evidence_requirements=[],
    )
    adj = AdjudicationResult(
        control_finding=cf,
        detector_score=0.9,
        verifier_argument="pro",
        challenger_argument="con",
        consensus_score=0.9,
        model_consensus=0.9,
        rationale="Clear violation",
    )
    comps = ScoreComponents(
        rule_confidence=0.9,
        evidence_confidence=0.8,
        model_consensus=0.9,
        historical_precision=1.0,
        control_severity=0.8,
        flow_confidence=1.0,
    )
    sf = ScoredFinding(
        result=adj,
        components=comps,
        finding_score=0.9,
        surfaced=True,
        suppression_reason="",
    )

    # 1. Test Jira issue creation for diff/both scans (with scored findings)
    with (
        patch("requests.post") as mock_response,
        patch("audit_packs_action.cli.run_git_diff", return_value=""),
        patch("audit_packs_action.cli.parse_unified_diff", return_value={}),
        patch("audit_packs_action.cli.analyze", return_value=[sf]),
        patch("audit_packs_action.cli.assess", return_value=[]),
    ):
        mock_response.return_value.status_code = 201
        mock_response.return_value.json.return_value = {"key": "ACME-123"}

        test_args = [
            "audit-packs",
            "--jira-url",
            "https://acme.atlassian.net",
            "--jira-email",
            "audit@acme.com",
            "--jira-token",
            "mock_token",
            "--jira-project",
            "ACME",
            "--scan-mode",
            "diff",
            "--fail-on",
            "high",
        ]
        with patch("sys.argv", test_args):
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": ""}, clear=True):
                main()
                mock_response.assert_called_once()
                args, kwargs = mock_response.call_args
                payload = kwargs["json"]
                assert payload["fields"]["project"]["key"] == "ACME"
                assert "ACME-123" in mock_response.return_value.json()["key"]
        patch.stopall()

    # 2. Test Jira issue creation for full scan (with control_statuses failures)
    cs = ControlStatus(
        framework="soc2",
        control_id="CC6.1",
        control_title="Encryption at rest",
        status=AssessmentStatus.FAIL,
        findings=[cf],
        check_ids=["CKV_AWS_19"],
        evidence=("encryption=false",),
    )
    with (
        patch("requests.post") as mock_response,
        patch("audit_packs_action.cli.analyze", return_value=[]),
        patch("audit_packs_action.cli.assess", return_value=[cs]),
    ):
        mock_response.return_value.status_code = 201
        mock_response.return_value.json.return_value = {"key": "ACME-456"}

        test_args = [
            "audit-packs",
            "--jira-url",
            "https://acme.atlassian.net",
            "--jira-email",
            "audit@acme.com",
            "--jira-token",
            "mock_token",
            "--jira-project",
            "ACME",
            "--scan-mode",
            "full",
            "--fail-on",
            "high",
        ]
        with patch("sys.argv", test_args):
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": ""}, clear=True):
                main()
                mock_response.assert_called_once()
                args, kwargs = mock_response.call_args
                payload = kwargs["json"]
                assert payload["fields"]["project"]["key"] == "ACME"
                assert (
                    "Compliance Audit Failure: 1 controls failed"
                    in payload["fields"]["summary"]
                )
        patch.stopall()
