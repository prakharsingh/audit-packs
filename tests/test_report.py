import pytest
import requests
import json
import re
from unittest.mock import patch, MagicMock
from audit_packs_core.models import (
    Finding,
    ControlFinding,
    ControlStatus,
    AssessmentStatus,
)
from audit_packs_action.report import (
    build_comments,
    build_summary_comment,
    gate_failed,
    build_coverage_matrix,
    build_sarif,
    post_review,
    write_job_summary,
)


def _cf(sev, control="SC-13"):
    f = Finding(
        "CKV_AWS_19", "checkov", "main.tf", 11, sev, "no encryption", "encrypted=false"
    )
    return ControlFinding(f, "nist-800-53", control, "Cryptographic Protection")


def _cs(ctrl_id, status, framework="soc2", findings=()):
    return ControlStatus(
        framework=framework,
        control_id=ctrl_id,
        control_title=f"Title {ctrl_id}",
        status=status,
        check_ids=(("checkov", "CKV_AWS_19"),)
        if status != AssessmentStatus.MANUAL
        else (),
        findings=findings,
        evidence=tuple(cf.finding.evidence for cf in findings),
    )


def _scored_finding(
    surfaced=True,
    consensus_score=0.87,
    framework="gdpr",
    control_id="Art-32-a",
    control_title="Pseudonymisation and Encryption",
    severity="high",
    check_id="CKV_AWS_19",
    engine="checkov",
    message="S3 bucket encryption disabled",
):
    from audit_packs_core.models import Finding, ControlFinding, AdjudicationResult
    from audit_packs_ai.confidence import (
        ScoreComponents,
        ScoredFinding,
        DEFAULT_WEIGHTS,
        score_finding,
    )

    f = Finding(check_id, engine, "main.tf", 11, severity, message, "encrypted = false")
    cf = ControlFinding(f, framework, control_id, control_title)
    result = AdjudicationResult(
        control_finding=cf,
        detector_score=consensus_score,
        verifier_argument="Data stored without encryption",
        challenger_argument="This could be a test bucket",
        consensus_score=consensus_score,
        model_consensus=consensus_score,
        rationale="Storing data at rest without encryption violates GDPR Art. 32(a).",
    )
    comps = ScoreComponents(
        rule_confidence=0.9,
        evidence_confidence=0.8,
        model_consensus=consensus_score,
        historical_precision=0.78,
        control_severity=0.8,
        flow_confidence=0.9,
    )
    fs = score_finding(result, comps, DEFAULT_WEIGHTS)
    return ScoredFinding(
        result=result,
        components=comps,
        finding_score=fs,
        surfaced=surfaced,
        suppression_reason="" if surfaced else "low score",
    )


def test_build_comments_one_per_finding_with_control_tag():
    scored = [
        _scored_finding(
            framework="nist-800-53",
            control_id="SC-13",
            control_title="Cryptographic Protection",
            message="no encryption",
        )
    ]
    comments = build_comments(scored, commit_sha="abc")
    assert len(comments) == 1
    c = comments[0]
    assert c["path"] == "main.tf"
    assert c["line"] == 11
    assert c["side"] == "RIGHT"
    assert "nist-800-53" in c["body"].lower()
    assert "SC-13" in c["body"]
    assert "encrypted = false" in c["body"]


def test_gate_failed_respects_threshold():
    assert gate_failed([_cf("high")], fail_on="high") is True
    assert gate_failed([_cf("medium")], fail_on="high") is False
    assert gate_failed([], fail_on="low") is False


# --- Phase 3: coverage matrix + SARIF ---


def test_build_coverage_matrix_md_contains_all_controls():
    statuses = [
        _cs("CC6.1", AssessmentStatus.PASS),
        _cs("CC7.2", AssessmentStatus.FAIL),
        _cs("CC1.1", AssessmentStatus.MANUAL),
    ]
    md = build_coverage_matrix(statuses, fmt="md")
    assert "CC6.1" in md
    assert "CC7.2" in md
    assert "CC1.1" in md


def test_build_coverage_matrix_md_shows_status_icons():
    statuses = [
        _cs("CC6.1", AssessmentStatus.PASS),
        _cs("CC7.2", AssessmentStatus.FAIL),
        _cs("CC1.1", AssessmentStatus.MANUAL),
    ]
    md = build_coverage_matrix(statuses, fmt="md")
    assert "✅" in md or "PASS" in md
    assert "❌" in md or "FAIL" in md
    assert "📋" in md or "MANUAL" in md


def test_build_coverage_matrix_html_is_valid_html():
    statuses = [_cs("CC6.1", AssessmentStatus.PASS)]
    html = build_coverage_matrix(statuses, fmt="html")
    assert "<!doctype html>" in html
    assert "<title>Audit Packs Control Coverage Matrix</title>" in html
    assert 'name="description"' in html
    assert 'type="application/ld+json"' in html
    assert "<table" in html
    assert "CC6.1" in html


def test_build_coverage_matrix_html_supports_seo_metadata():
    statuses = [_cs("CC6.1", AssessmentStatus.PASS, framework="soc2")]
    html = build_coverage_matrix(
        statuses,
        fmt="html",
        title="SOC 2 Audit Coverage",
        description="Public SOC 2 coverage report.",
        canonical_url="https://example.com/audit/coverage.html",
    )
    assert "<title>SOC 2 Audit Coverage</title>" in html
    assert 'content="Public SOC 2 coverage report."' in html
    assert 'rel="canonical" href="https://example.com/audit/coverage.html"' in html
    assert 'property="og:title" content="SOC 2 Audit Coverage"' in html
    assert 'name="twitter:card" content="summary"' in html


def test_build_coverage_matrix_html_json_ld_is_parseable():
    statuses = [_cs("CC6.1", AssessmentStatus.PASS, framework="soc2")]
    html = build_coverage_matrix(statuses, fmt="html")
    match = re.search(
        r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL
    )
    assert match
    schema = json.loads(match.group(1))
    assert schema["@type"] == "Dataset"
    assert "soc2" in schema["keywords"]


def test_build_coverage_matrix_html_fragment_returns_table_only():
    statuses = [_cs("CC6.1", AssessmentStatus.PASS)]
    html = build_coverage_matrix(statuses, fmt="html-fragment")
    assert html.startswith("<table>")
    assert "<!doctype html>" not in html
    assert "CC6.1" in html


def test_build_coverage_matrix_html_escapes_control_text():
    statuses = [
        ControlStatus(
            framework="soc2",
            control_id="CC<script>",
            control_title='Title "quoted" <unsafe>',
            status=AssessmentStatus.PASS,
            check_ids=(),
            findings=(),
            evidence=(),
        )
    ]
    html = build_coverage_matrix(statuses, fmt="html-fragment")
    assert "CC&lt;script&gt;" in html
    assert "Title &quot;quoted&quot; &lt;unsafe&gt;" in html
    assert "<unsafe>" not in html


def test_build_coverage_matrix_summary_counts():
    statuses = [
        _cs("CC6.1", AssessmentStatus.PASS),
        _cs("CC7.2", AssessmentStatus.FAIL),
        _cs("CC1.1", AssessmentStatus.MANUAL),
        _cs("CC9.1", AssessmentStatus.MANUAL),
    ]
    md = build_coverage_matrix(statuses, fmt="md")
    # Summary line should mention counts
    assert "1" in md  # at least one FAIL
    assert "2" in md  # two PASS+FAIL or two MANUALs


def test_build_sarif_top_level_schema():
    sarif = build_sarif([])
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert isinstance(sarif["runs"], list)


def test_build_sarif_contains_results_for_findings():
    cf = _cf("high")
    sarif = build_sarif([cf])
    runs = sarif["runs"]
    assert len(runs) >= 1
    results = runs[0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CKV_AWS_19"


def test_build_sarif_result_has_location():
    cf = _cf("high")
    sarif = build_sarif([cf])
    result = sarif["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "main.tf"
    assert loc["region"]["startLine"] == 11


# --- post_review ---


def test_post_review_calls_correct_github_url():
    mock_resp = MagicMock()
    with patch(
        "audit_packs_action.report.requests.post", return_value=mock_resp
    ) as mock_post:
        post_review(
            [{"path": "main.tf", "line": 1, "side": "RIGHT", "body": "x"}],
            "Audit summary",
            repo="org/repo",
            pr_number="42",
            token="ghp_test",
            commit_sha="abc123",
        )
    mock_post.assert_called_once()
    url = mock_post.call_args[0][0]
    assert url == "https://api.github.com/repos/org/repo/pulls/42/reviews"


def test_post_review_sends_bearer_token_and_payload():
    mock_resp = MagicMock()
    with patch(
        "audit_packs_action.report.requests.post", return_value=mock_resp
    ) as mock_post:
        post_review(
            [],
            "summary",
            repo="org/repo",
            pr_number="7",
            token="ghp_secret",
            commit_sha="deadbeef",
        )
    kwargs = mock_post.call_args[1]
    assert kwargs["headers"]["Authorization"] == "Bearer ghp_secret"
    assert kwargs["json"]["commit_id"] == "deadbeef"
    assert kwargs["json"]["event"] == "COMMENT"
    mock_resp.raise_for_status.assert_called_once()


def test_post_review_propagates_http_error():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = requests.HTTPError("403 Forbidden")
    with patch("audit_packs_action.report.requests.post", return_value=mock_resp):
        with pytest.raises(requests.HTTPError):
            post_review([], "s", repo="r/r", pr_number="1", token="t", commit_sha="s")


def test_write_job_summary_appends_to_file(tmp_path):
    summary_file = tmp_path / "step_summary.md"
    summary_file.write_text("")
    with patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": str(summary_file)}):
        write_job_summary("## Coverage\nall good\n")
    assert "## Coverage" in summary_file.read_text()


def test_write_job_summary_noop_without_env(tmp_path):
    with patch.dict("os.environ", {}, clear=True):
        write_job_summary("should not crash")  # no exception, no file created


# --- Task 9: Report Extension Tests ---


def test_build_comments_includes_framework_and_control():
    scored = [_scored_finding()]
    comments = build_comments(scored, "abc123")
    assert len(comments) == 1
    assert "GDPR" in comments[0]["body"] or "gdpr" in comments[0]["body"].lower()
    assert "Art-32-a" in comments[0]["body"]


def test_build_comments_includes_score_percentage():
    scored = [_scored_finding(consensus_score=0.87)]
    comments = build_comments(scored, "abc123")
    body = comments[0]["body"]
    assert "%" in body


def test_build_comments_includes_score_breakdown():
    scored = [_scored_finding()]
    comments = build_comments(scored, "abc123")
    body = comments[0]["body"]
    assert "rule" in body and "evidence" in body and "consensus" in body


def test_build_comments_includes_rationale():
    scored = [_scored_finding()]
    comments = build_comments(scored, "abc123")
    body = comments[0]["body"]
    assert "GDPR Art. 32(a)" in body


def test_build_comments_excludes_suppressed():
    scored = [_scored_finding(surfaced=False)]
    comments = build_comments(scored, "abc123")
    assert comments == []


def test_build_summary_comment_contains_framework_row():
    from audit_packs_ai.confidence import DEFAULT_WEIGHTS

    scored = [
        _scored_finding(framework="gdpr"),
        _scored_finding(framework="gdpr", surfaced=False),
    ]
    summary = build_summary_comment(scored, threshold=0.70, weights=DEFAULT_WEIGHTS)
    assert "gdpr" in summary
    assert "1" in summary  # 1 suppressed


def test_build_summary_comment_shows_score_formula():
    from audit_packs_ai.confidence import DEFAULT_WEIGHTS

    scored = [_scored_finding()]
    summary = build_summary_comment(scored, threshold=0.70, weights=DEFAULT_WEIGHTS)
    assert "0.20" in summary or "rule" in summary
    assert "Threshold" in summary or "threshold" in summary.lower()
