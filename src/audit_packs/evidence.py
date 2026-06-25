from __future__ import annotations
import re
from dataclasses import dataclass, replace

import requests

from audit_packs.models import Finding


@dataclass(frozen=True)
class PRContext:
    pr_body: str
    commit_messages: tuple[str, ...]


def fetch_pr_context(repo: str, pr_number: str, token: str) -> PRContext:
    """Fetch PR body and last 5 commit subjects from GitHub API. IO boundary."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    base = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

    pr_resp = requests.get(base, headers=headers, timeout=15)
    pr_resp.raise_for_status()
    pr_body = (pr_resp.json().get("body") or "")[:500]

    commits_resp = requests.get(f"{base}/commits", headers=headers, timeout=15)
    commits_resp.raise_for_status()
    commits = commits_resp.json()[-5:]
    subjects = tuple(c["commit"]["message"].splitlines()[0] for c in commits)

    return PRContext(pr_body=pr_body, commit_messages=subjects)


def extract_doc_context(file_text: str, line: int) -> str:
    """Return the nearest docstring or block comment within ±10 lines of *line*."""
    lines = file_text.splitlines()
    window_start = max(0, line - 11)
    window_end = min(len(lines), line + 10)
    window = lines[window_start:window_end]

    # Python triple-quoted strings
    triple_pattern = re.compile(r'"""(.*?)"""|\'\'\'(.*?)\'\'\'', re.DOTALL)
    window_text = "\n".join(window)
    for m in triple_pattern.finditer(window_text):
        content = (m.group(1) or m.group(2) or "").strip()
        if content:
            return content[:300]

    # HCL / shell / YAML block comments (# or // prefix)
    comment_pattern = re.compile(r"^\s*(?:#|//)\s*(.+)$")
    for ln in window:
        m = comment_pattern.match(ln)
        if m:
            return m.group(1).strip()

    return ""


def enrich(finding: Finding, changed_file_text: str, pr_context: PRContext) -> Finding:
    """Return a new Finding with doc_context populated. Never mutates the original."""
    doc_ctx = extract_doc_context(changed_file_text, finding.line)
    return replace(finding, doc_context=doc_ctx)


def evidence_confidence(finding: Finding, pr_context: PRContext | None) -> float:
    """
    Compute evidence_confidence [0.0, 1.0].

    +0.4  SARIF code snippet always present
    +0.3  doc_context non-empty
    +0.3  PR body or any commit message references finding.file
    """
    score = 0.4
    if finding.doc_context:
        score += 0.3
    if pr_context:
        file_ref = finding.file in pr_context.pr_body or any(
            finding.file in msg for msg in pr_context.commit_messages
        )
        if file_ref:
            score += 0.3
    return min(score, 1.0)
