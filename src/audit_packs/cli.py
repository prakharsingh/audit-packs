"""cli.py — Orchestration entry point for audit-packs.

Reads configuration from environment variables (set by the GitHub Action runner
or the user) and drives the full pipeline:

  diff scan  → analyze()  → ControlFindings → PR comments + severity gate
  full scan  → assess()   → ControlStatus[] → OSCAL + coverage matrix + SARIF
  both       → both paths (default)

IO boundary: this module calls engines.py (subprocess), report.py (HTTP/file IO),
and writes output files to GITHUB_WORKSPACE. All other logic is pure.
"""
import json
import os
import sys
from dataclasses import replace

from audit_packs.models import SEVERITIES
from audit_packs.engines import run_checkov, run_semgrep, run_git_diff
from audit_packs.normalize import sarif_to_findings
from audit_packs.diff import parse_unified_diff
from audit_packs.packs import map_findings
from audit_packs.coverage import compute_coverage
from audit_packs.oscal import to_assessment_results
from audit_packs.report import (
    build_comments,
    build_coverage_matrix,
    build_sarif,
    gate_failed,
    post_review,
    write_job_summary,
)

_VALID_SCAN_MODES = ("diff", "full", "both")


def _rel(path: str, repo_dir: str) -> str:
    """Strip absolute repo_dir prefix from a SARIF URI to produce a repo-relative path."""
    abs_path = os.path.abspath(path)
    abs_repo = os.path.abspath(repo_dir)
    if abs_path.startswith(abs_repo + os.sep):
        return abs_path[len(abs_repo) + 1:]
    return path


def analyze(repo_dir, changed, packs_dir, rules_path, frameworks):
    """Run engines on the diff-changed lines and return ControlFindings.

    Only findings on lines present in *changed* are included. This is the
    path that feeds PR inline comments and the severity gate.
    """
    findings = []
    findings += sarif_to_findings(run_checkov(repo_dir), "checkov")
    findings += sarif_to_findings(run_semgrep(repo_dir, rules_path), "semgrep")
    in_diff = []
    for f in findings:
        rel_path = _rel(f.file, repo_dir)
        if f.line in changed.get(rel_path, set()):
            in_diff.append(replace(f, file=rel_path) if rel_path != f.file else f)
    return map_findings(in_diff, packs_dir, frameworks)


def assess(repo_dir, packs_dir, rules_path, frameworks):
    """Run engines over the full workspace and return ControlStatus objects.

    This is the path that feeds the coverage matrix, OSCAL output, and
    aggregate SARIF — it gives posture across all IaC, not just the PR diff.
    """
    findings = []
    findings += sarif_to_findings(run_checkov(repo_dir), "checkov")
    findings += sarif_to_findings(run_semgrep(repo_dir, rules_path), "semgrep")
    all_rel = [replace(f, file=_rel(f.file, repo_dir)) for f in findings]
    cfs = map_findings(all_rel, packs_dir, frameworks)
    return compute_coverage(cfs, packs_dir, frameworks)


def main() -> int:
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    pr_number = os.environ["PR_NUMBER"]
    base_ref = os.environ.get("BASE_REF", "origin/main")
    commit_sha = os.environ["GITHUB_SHA"]
    frameworks = [s.strip() for s in os.environ.get("FRAMEWORKS", "nist-800-53").split(",") if s.strip()]
    fail_on = os.environ.get("FAIL_ON", "high")
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    packs_dir = os.environ.get("PACKS_DIR", "/app/packs")
    rules_path = os.environ.get("RULES_PATH", "/app/rules")

    # New in Phase 3
    scan_mode = os.environ.get("SCAN_MODE", "both").lower()
    emit_oscal = os.environ.get("EMIT_OSCAL", "true").lower() == "true"
    emit_coverage = os.environ.get("EMIT_COVERAGE", "true").lower() == "true"
    emit_sarif = os.environ.get("EMIT_SARIF", "true").lower() == "true"

    if fail_on not in SEVERITIES:
        print(f"Error: FAIL_ON='{fail_on}' is not valid. Choose from: {', '.join(SEVERITIES)}", file=sys.stderr)
        return 2

    if scan_mode not in _VALID_SCAN_MODES:
        print(f"Error: SCAN_MODE='{scan_mode}' is not valid. Choose from: {', '.join(_VALID_SCAN_MODES)}", file=sys.stderr)
        return 2

    gate_tripped = False

    # ── Diff scan: PR comments + severity gate ────────────────────────────────
    if scan_mode in ("diff", "both"):
        diff_text = run_git_diff(workspace, base_ref)
        changed = parse_unified_diff(diff_text)
        cfs = analyze(workspace, changed, packs_dir, rules_path, frameworks)
        comments = build_comments(cfs, commit_sha)
        summary = f"Audit Packs: {len(cfs)} control-tagged finding(s) across {', '.join(frameworks)}."
        if comments:
            post_review(comments, summary, repo=repo, pr_number=pr_number, token=token, commit_sha=commit_sha)
        if gate_failed(cfs, fail_on):
            gate_tripped = True

    # ── Full scan: coverage matrix, OSCAL, aggregate SARIF ───────────────────
    if scan_mode in ("full", "both"):
        control_statuses = assess(workspace, packs_dir, rules_path, frameworks)

        if emit_oscal:
            oscal_path = os.path.join(workspace, "oscal.json")
            oscal_data = to_assessment_results(control_statuses)
            with open(oscal_path, "w") as fh:
                json.dump(oscal_data, fh, indent=2)
            print(f"::notice::OSCAL assessment-results written to {oscal_path}")

        if emit_coverage:
            for fmt in ("md", "html"):
                cov_path = os.path.join(workspace, f"coverage.{fmt}")
                content = build_coverage_matrix(control_statuses, fmt=fmt)
                with open(cov_path, "w") as fh:
                    fh.write(content)
            print(f"::notice::Coverage matrix written to {os.path.join(workspace, 'coverage.md')}")
            write_job_summary(build_coverage_matrix(control_statuses, fmt="md"))

        if emit_sarif:
            # Build a flat list of ControlFindings from the full-scan statuses for SARIF
            all_cfs = [cf for cs in control_statuses for cf in cs.findings]
            sarif_path = os.path.join(workspace, "audit-packs.sarif")
            with open(sarif_path, "w") as fh:
                json.dump(build_sarif(all_cfs), fh, indent=2)
            print(f"::notice::Aggregate SARIF written to {sarif_path}")

    return 1 if gate_tripped else 0


if __name__ == "__main__":
    sys.exit(main())
