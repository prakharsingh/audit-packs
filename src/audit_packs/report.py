import os
import requests
from audit_packs.models import (
    ControlFinding,
    ControlStatus,
    AssessmentStatus,
    severity_rank,
)

# Status display helpers
_STATUS_ICON = {
    AssessmentStatus.PASS: "✅",
    AssessmentStatus.FAIL: "❌",
    AssessmentStatus.MANUAL: "📋",
    AssessmentStatus.NOT_APPLICABLE: "➖",
}

_SARIF_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def build_comments(scored_findings: list, commit_sha: str) -> list[dict]:
    """Build PR review comments for surfaced ScoredFindings."""
    comments = []
    for sf in scored_findings:
        if not sf.surfaced:
            continue
        result = sf.result
        cf = result.control_finding
        f = cf.finding
        comps = sf.components
        score_pct = round(sf.finding_score * 100)

        breakdown = (
            f"rule {round(comps.rule_confidence * 100)}% · "
            f"evidence {round(comps.evidence_confidence * 100)}% · "
            f"consensus {round(comps.model_consensus * 100)}% · "
            f"history {round(comps.historical_precision * 100)}% · "
            f"severity {round(comps.control_severity * 100)}% · "
            f"flow {round(comps.flow_confidence * 100)}%"
        )

        body = (
            f"**[{cf.framework.upper()} / {cf.control_id} — {cf.control_title}]**  score: {score_pct}%\n"
            f"- Severity: `{f.severity}`  |  Engine: `{f.engine}` (`{f.check_id}`)\n"
            f"- Finding: {f.message}\n"
            f"- Score breakdown: {breakdown}\n"
            f"Evidence: `{f.evidence}`\n"
            f"Rationale: {result.rationale}"
        )
        comments.append({"path": f.file, "line": f.line, "side": "RIGHT", "body": body})
    return comments


def build_summary_comment(all_scored: list, threshold: float, weights: dict) -> str:
    """Build the summary comment posted once after inline comments."""
    from collections import defaultdict

    by_framework: dict[str, list] = defaultdict(list)
    for sf in all_scored:
        fw = sf.result.control_finding.framework
        by_framework[fw].append(sf)

    lines = [
        "## Audit Packs Summary",
        "| Framework | Findings | Suppressed | Avg Score |",
        "|---|---|---|---|",
    ]
    total_surfaced = 0
    total_suppressed = 0

    for fw, sfs in sorted(by_framework.items()):
        surfaced = [s for s in sfs if s.surfaced]
        suppressed = [s for s in sfs if not s.surfaced]
        avg = (
            round(sum(s.finding_score for s in surfaced) / len(surfaced) * 100)
            if surfaced
            else 0
        )
        lines.append(f"| {fw} | {len(surfaced)} | {len(suppressed)} | {avg}% |")
        total_surfaced += len(surfaced)
        total_suppressed += len(suppressed)

    lines.append("")
    lines.append(
        f"Total: {total_surfaced} surfaced, {total_suppressed} suppressed (FP). "
        f"Threshold: {round(threshold * 100)}%."
    )
    weight_formula = " + ".join(
        f"{w}·{k}"
        for k, w in [
            ("rule", weights.get("rule", 0.20)),
            ("evidence", weights.get("evidence", 0.15)),
            ("consensus", weights.get("consensus", 0.25)),
            ("history", weights.get("history", 0.10)),
            ("severity", weights.get("severity", 0.10)),
            ("flow", weights.get("flow", 0.20)),
        ]
    )
    lines.append(f"Score = {weight_formula}")
    return "\n".join(lines)


def gate_failed(control_findings: list[ControlFinding], fail_on: str) -> bool:
    threshold = severity_rank(fail_on)
    return any(
        severity_rank(cf.finding.severity) >= threshold for cf in control_findings
    )


def build_coverage_matrix(
    control_statuses: list[ControlStatus], fmt: str = "md"
) -> str:
    """Build a human-readable control coverage matrix.

    Args:
        control_statuses: Output of coverage.compute_coverage().
        fmt:              "md" for Markdown, "html" for HTML.

    Returns:
        A string containing the formatted matrix.
    """
    if fmt == "html":
        return _coverage_html(control_statuses)
    return _coverage_md(control_statuses)


def _coverage_md(statuses: list[ControlStatus]) -> str:
    lines = []
    # Group by framework
    frameworks: dict[str, list[ControlStatus]] = {}
    for s in statuses:
        frameworks.setdefault(s.framework, []).append(s)

    for fw, fw_statuses in frameworks.items():
        n_pass = sum(1 for s in fw_statuses if s.status == AssessmentStatus.PASS)
        n_fail = sum(1 for s in fw_statuses if s.status == AssessmentStatus.FAIL)
        n_manual = sum(1 for s in fw_statuses if s.status == AssessmentStatus.MANUAL)
        n_total = len(fw_statuses)

        lines.append(f"## {fw} — Control Coverage\n")
        lines.append(
            f"**Summary:** {n_pass} ✅ PASS · {n_fail} ❌ FAIL · "
            f"{n_manual} 📋 MANUAL · {n_total} total\n"
        )
        lines.append("| Control | Title | Status | Checks | Findings |")
        lines.append("|---------|-------|--------|--------|----------|")
        for s in fw_statuses:
            icon = _STATUS_ICON.get(s.status, "?")
            status_label = f"{icon} {s.status.value.upper()}"
            n_checks = len(s.check_ids)
            n_findings = len(s.findings)
            lines.append(
                f"| {s.control_id} | {s.control_title} | {status_label} "
                f"| {n_checks} | {n_findings} |"
            )
        lines.append("")

    return "\n".join(lines)


def _coverage_html(statuses: list[ControlStatus]) -> str:
    rows = []
    for s in statuses:
        icon = _STATUS_ICON.get(s.status, "?")
        rows.append(
            f"<tr><td>{s.control_id}</td><td>{s.control_title}</td>"
            f"<td>{icon} {s.status.value}</td>"
            f"<td>{len(s.check_ids)}</td><td>{len(s.findings)}</td></tr>"
        )
    body = "\n".join(rows)
    return (
        "<table>\n"
        "<thead><tr><th>Control</th><th>Title</th><th>Status</th>"
        "<th>Checks</th><th>Findings</th></tr></thead>\n"
        f"<tbody>\n{body}\n</tbody>\n</table>"
    )


def build_sarif(control_findings: list[ControlFinding]) -> dict:
    """Build an aggregate SARIF document from ControlFindings.

    Suitable for upload via actions/upload-sarif to GitHub code-scanning.
    """
    results = []
    rules: dict[str, dict] = {}

    for cf in control_findings:
        f = cf.finding
        rule_id = f.check_id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.message},
                "properties": {
                    "compliance-control": f"{cf.framework}/{cf.control_id}",
                },
            }
        level = _SARIF_LEVEL.get(f.severity, "warning")
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{f.message} [{cf.framework}/{cf.control_id}]"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": f.line},
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "audit-packs",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/prakharsingh/audit-packs",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_job_summary(content: str) -> None:
    """Append *content* to the GitHub Actions job summary file."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a") as fh:
        fh.write(content)
        fh.write("\n")


def post_review(comments, summary, *, repo, pr_number, token, commit_sha) -> None:
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    payload = {
        "commit_id": commit_sha,
        "body": summary,
        "event": "COMMENT",
        "comments": comments,
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
