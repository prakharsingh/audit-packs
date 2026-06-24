import requests
from audit_packs.models import ControlFinding, severity_rank

def build_comments(control_findings: list[ControlFinding], commit_sha: str) -> list[dict]:
    comments = []
    for cf in control_findings:
        f = cf.finding
        body = (
            f"**Compliance control touched: `{cf.framework}` / {cf.control_id} — {cf.control_title}**\n\n"
            f"- Severity: `{f.severity}`\n"
            f"- Engine: `{f.engine}` (`{f.check_id}`)\n"
            f"- Finding: {f.message}\n\n"
            f"Evidence:\n```\n{f.evidence}\n```"
        )
        comments.append({"path": f.file, "line": f.line, "side": "RIGHT", "body": body})
    return comments

def gate_failed(control_findings: list[ControlFinding], fail_on: str) -> bool:
    threshold = severity_rank(fail_on)
    return any(severity_rank(cf.finding.severity) >= threshold for cf in control_findings)

def post_review(comments, summary, *, repo, pr_number, token, commit_sha) -> None:
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    payload = {
        "commit_id": commit_sha,
        "body": summary,
        "event": "COMMENT",
        "comments": comments,
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
