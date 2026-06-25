"""cli.py — Orchestration entry point for audit-packs.

Reads configuration from environment variables (set by the GitHub Action runner
or the user) and drives the full pipeline:

  diff scan  → analyze()  → ScoredFinding[] → PR comments + severity gate
  full scan  → assess()   → ControlStatus[] → OSCAL + coverage matrix + SARIF
  both       → both paths (default)

IO boundary: this module calls engines.py (subprocess), report.py (HTTP/file IO),
and writes output files to GITHUB_WORKSPACE. All other logic is pure.
"""

from __future__ import annotations

import os
import sys
from dataclasses import replace

from audit_packs.adjudicate import AdjudicationMode
from audit_packs.models import SEVERITIES
from audit_packs.engines import (
    run_checkov,
    run_semgrep,
    run_git_diff,
    read_codeql_sarif,
)
from audit_packs.normalize import sarif_to_findings
from audit_packs.diff import parse_unified_diff
from audit_packs.packs import map_findings
from audit_packs.coverage import compute_coverage
from audit_packs.oscal import to_assessment_results
from audit_packs.report import (
    build_coverage_matrix,
    build_sarif,
    gate_failed,
    post_review,
    write_job_summary,
)

_VALID_SCAN_MODES = ("diff", "full", "both")

_FRAMEWORK_ALIASES: dict[str, str] = {
    "gdpr": "gdpr",
    "hipaa": "hipaa",
    "soc2": "soc2",
    "soc-2": "soc2",
    "iso27001": "iso27001",
    "iso-27001": "iso27001",
    "pci-dss": "pci-dss",
    "pcidss": "pci-dss",
    "pci_dss": "pci-dss",
    "nist-800-53": "nist-800-53",
    "nist800-53": "nist-800-53",
    "nist": "nist-800-53",
    "fedramp": "fedramp",
    "org-policy": "org-policy",
    "org_policy": "org-policy",
    "internal": "org-policy",
}


def normalize_frameworks(raw: str) -> list[str]:
    """Parse FRAMEWORKS env (comma or newline separated) and resolve aliases."""
    tokens = [t.strip().lower() for t in raw.replace("\n", ",").split(",") if t.strip()]
    result = []
    for tok in tokens:
        if tok not in _FRAMEWORK_ALIASES:
            raise ValueError(
                f"Unknown framework: {tok!r}. Supported: {sorted(set(_FRAMEWORK_ALIASES.values()))}"
            )
        result.append(_FRAMEWORK_ALIASES[tok])
    return result


def _rel(path: str, repo_dir: str) -> str:
    """Strip absolute repo_dir prefix from a SARIF URI to produce a repo-relative path."""
    abs_path = os.path.abspath(path)
    abs_repo = os.path.abspath(repo_dir)
    if abs_path.startswith(abs_repo + os.sep):
        return abs_path[len(abs_repo) + 1 :]
    return path


def analyze(
    repo_dir,
    changed,
    packs_dir,
    rules_path,
    frameworks,
    adj_mode=AdjudicationMode.OFF,
    model_config=None,
    pr_context=None,
    codeql_sarif_dir="",
    precision_data=None,
    weights=None,
    threshold=0.70,
):
    """Run engines, enrich, adjudicate, score, and return ScoredFindings for diff-changed lines."""
    from audit_packs.evidence import enrich, evidence_confidence
    from audit_packs.dataflow import extract_data_flows, flow_confidence
    from audit_packs.confidence import (
        ScoreComponents,
        apply_confidence_gate,
        get_historical_precision,
        control_severity_score,
    )
    from audit_packs.adjudicate import adjudicate as adj_finding
    from audit_packs.normalize import extract_rule_confidences

    if model_config is None:
        from audit_packs.adjudicate import load_model_config

        model_config = load_model_config()
    if precision_data is None:
        precision_data = {}
    if weights is None:
        from audit_packs.confidence import DEFAULT_WEIGHTS

        weights = DEFAULT_WEIGHTS

    # Run detection engines in parallel using async engines
    async def _run_scans_parallel():
        import asyncio
        from audit_packs.engines import CheckovEngine, SemgrepEngine, CodeQLEngine

        checkov_task = asyncio.create_task(CheckovEngine().run_scan_async(repo_dir, {}))
        semgrep_task = asyncio.create_task(
            SemgrepEngine().run_scan_async(repo_dir, {"rules_path": rules_path})
        )
        if codeql_sarif_dir:
            codeql_task = asyncio.create_task(
                CodeQLEngine().run_scan_async(codeql_sarif_dir, {})
            )
        else:
            codeql_task = None

        c_sarif, s_sarif = await asyncio.gather(checkov_task, semgrep_task)
        q_sarif = await codeql_task if codeql_task else {"runs": []}
        return c_sarif, s_sarif, q_sarif

    try:
        import asyncio

        checkov_sarif, semgrep_sarif, codeql_sarif = asyncio.run(_run_scans_parallel())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        codeql_sarif = (
            read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}
        )

    # Run all registered detection agents for Phase 2
    from audit_packs.agents import build_agents

    agents = build_agents(frameworks, packs_dir)
    changed_file_texts = {}
    for rel_path in changed:
        abs_path = os.path.join(repo_dir, rel_path)
        if os.path.isfile(abs_path):
            try:
                changed_file_texts[rel_path] = open(abs_path).read()
            except OSError:
                pass

    rule_confidences: dict[str, float] = {}
    rule_confidences.update(extract_rule_confidences(semgrep_sarif))
    rule_confidences.update(extract_rule_confidences(codeql_sarif))

    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")

    for agent in agents:
        agent_sarif = agent.detect(changed_file_texts)
        rule_confidences.update(extract_rule_confidences(agent_sarif))
        findings += sarif_to_findings(agent_sarif, f"{agent.framework}-agent")

    # Extract data flows per file (for flow_confidence)
    data_flows: dict[str, list] = {}
    for rel_path, file_text in changed_file_texts.items():
        lang = (
            "python"
            if rel_path.endswith(".py")
            else "hcl"
            if rel_path.endswith(".tf")
            else "yaml"
        )
        data_flows[rel_path] = extract_data_flows(file_text, lang)

    # Enrich findings and compute evidence_confidence per finding
    ev_conf_map: dict[tuple, float] = {}
    enriched_findings = []
    for f in findings:
        rel_path = _rel(f.file, repo_dir)
        file_text = changed_file_texts.get(rel_path, "")
        enriched = enrich(f, file_text, pr_context) if file_text else f
        ev_conf_map[(enriched.check_id, rel_path, enriched.line)] = evidence_confidence(
            enriched, pr_context
        )
        enriched_findings.append(enriched)

    # Filter to diff-changed lines
    in_diff = []
    for f in enriched_findings:
        rel_path = _rel(f.file, repo_dir)
        if f.line in changed.get(rel_path, set()):
            in_diff.append(replace(f, file=rel_path) if rel_path != f.file else f)

    # Map to control findings
    control_findings = map_findings(in_diff, packs_dir, frameworks)

    # Adjudicate each control finding
    pairs = []
    for cf in control_findings:
        finding = cf.finding
        result = adj_finding(cf, pr_context, adj_mode, model_config)

        rel_path = finding.file
        flows = data_flows.get(rel_path, [])
        f_conf = flow_confidence(flows, finding.line)
        ev_conf = ev_conf_map.get((finding.check_id, finding.file, finding.line), 0.4)
        rule_conf = rule_confidences.get(finding.check_id, 0.6)
        hist_prec = get_historical_precision(
            finding.check_id, cf.framework, precision_data
        )
        ctrl_sev = control_severity_score(finding.severity)

        components = ScoreComponents(
            rule_confidence=rule_conf,
            evidence_confidence=ev_conf,
            model_consensus=result.model_consensus,
            historical_precision=hist_prec,
            control_severity=ctrl_sev,
            flow_confidence=f_conf,
        )
        pairs.append((result, components))

    return apply_confidence_gate(
        pairs, threshold=threshold, mode=adj_mode, weights=weights
    )


def _read_all_files(repo_dir: str) -> dict[str, str]:
    file_texts = {}
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and d not in ("venv", ".venv", "node_modules", "build", "dist")
        ]
        for file in files:
            if file.endswith((".py", ".tf", ".yaml", ".yml", ".json")):
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, repo_dir)
                try:
                    with open(abs_path, encoding="utf-8", errors="ignore") as fh:
                        file_texts[rel_path] = fh.read()
                except Exception:
                    pass
    return file_texts


def assess(
    repo_dir,
    packs_dir,
    rules_path,
    frameworks,
    adj_mode=AdjudicationMode.OFF,
    model_config=None,
    precision_data=None,
    weights=None,
    threshold=0.70,
):
    """Run engines over the full workspace and return ControlStatus objects.

    This is the path that feeds the coverage matrix, OSCAL output, and
    aggregate SARIF — it gives posture across all IaC, not just the PR diff.
    """
    from audit_packs.confidence import (
        ScoreComponents,
        apply_confidence_gate,
        get_historical_precision,
        control_severity_score,
    )
    from audit_packs.adjudicate import adjudicate as adj_finding
    from audit_packs.normalize import extract_rule_confidences
    from audit_packs.dataflow import extract_data_flows, flow_confidence
    from audit_packs.evidence import extract_doc_context, evidence_confidence

    if model_config is None:
        from audit_packs.adjudicate import load_model_config

        model_config = load_model_config()
    if precision_data is None:
        precision_data = {}
    if weights is None:
        from audit_packs.confidence import DEFAULT_WEIGHTS

        weights = DEFAULT_WEIGHTS

    # Run detection engines in parallel using async engines
    async def _run_scans_parallel_assess():
        import asyncio
        from audit_packs.engines import CheckovEngine, SemgrepEngine

        checkov_task = asyncio.create_task(CheckovEngine().run_scan_async(repo_dir, {}))
        semgrep_task = asyncio.create_task(
            SemgrepEngine().run_scan_async(repo_dir, {"rules_path": rules_path})
        )

        c_sarif, s_sarif = await asyncio.gather(checkov_task, semgrep_task)
        return c_sarif, s_sarif

    try:
        import asyncio

        checkov_sarif, semgrep_sarif = asyncio.run(_run_scans_parallel_assess())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)

    # Load and run Phase 2 detection agents over the full workspace
    from audit_packs.agents import build_agents

    agents = build_agents(frameworks, packs_dir)
    all_file_texts = _read_all_files(repo_dir)

    rule_confidences: dict[str, float] = {}
    rule_confidences.update(extract_rule_confidences(semgrep_sarif))

    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")

    for agent in agents:
        agent_sarif = agent.detect(all_file_texts)
        rule_confidences.update(extract_rule_confidences(agent_sarif))
        findings += sarif_to_findings(agent_sarif, f"{agent.framework}-agent")

    # Group by file and read file text for doc_context and flow_confidence
    changed_file_texts = {}
    for f in findings:
        rel_path = _rel(f.file, repo_dir)
        if rel_path not in changed_file_texts:
            if rel_path in all_file_texts:
                changed_file_texts[rel_path] = all_file_texts[rel_path]
            else:
                abs_path = os.path.join(repo_dir, rel_path)
                if os.path.isfile(abs_path):
                    try:
                        changed_file_texts[rel_path] = open(abs_path).read()
                    except OSError:
                        pass

    data_flows: dict[str, list] = {}
    for rel_path, file_text in changed_file_texts.items():
        lang = (
            "python"
            if rel_path.endswith(".py")
            else "hcl"
            if rel_path.endswith(".tf")
            else "yaml"
        )
        data_flows[rel_path] = extract_data_flows(file_text, lang)

    # Enrich findings
    ev_conf_map: dict[int, float] = {}
    enriched_findings = []
    for f in findings:
        rel_path = _rel(f.file, repo_dir)
        file_text = changed_file_texts.get(rel_path, "")
        doc_ctx = extract_doc_context(file_text, f.line) if file_text else ""
        enriched = replace(f, doc_context=doc_ctx)
        ev_conf_map[id(enriched)] = evidence_confidence(enriched, None)
        enriched_findings.append(enriched)

    all_rel = [replace(f, file=_rel(f.file, repo_dir)) for f in enriched_findings]
    cfs = map_findings(all_rel, packs_dir, frameworks)

    if adj_mode is AdjudicationMode.OFF:
        return compute_coverage(cfs, packs_dir, frameworks)

    # Otherwise adjudicate and confidence-gate the control findings
    pairs = []
    for cf in cfs:
        finding = cf.finding
        result = adj_finding(cf, None, adj_mode, model_config)

        rel_path = finding.file
        flows = data_flows.get(rel_path, [])
        f_conf = flow_confidence(flows, finding.line)
        ev_conf = ev_conf_map.get(id(finding), 0.4)
        rule_conf = rule_confidences.get(finding.check_id, 0.6)
        hist_prec = get_historical_precision(
            finding.check_id, cf.framework, precision_data
        )
        ctrl_sev = control_severity_score(finding.severity)

        components = ScoreComponents(
            rule_confidence=rule_conf,
            evidence_confidence=ev_conf,
            model_consensus=result.model_consensus,
            historical_precision=hist_prec,
            control_severity=ctrl_sev,
            flow_confidence=f_conf,
        )
        pairs.append((result, components))

    scored = apply_confidence_gate(
        pairs, threshold=threshold, mode=adj_mode, weights=weights
    )
    surfaced_cfs = [sf.result.control_finding for sf in scored if sf.surfaced]
    return compute_coverage(surfaced_cfs, packs_dir, frameworks)


def main() -> int:
    import json as _json
    from audit_packs.adjudicate import load_model_config
    from audit_packs.confidence import DEFAULT_WEIGHTS
    from audit_packs.report import build_summary_comment

    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    pr_number = os.environ.get("PR_NUMBER", "")
    base_ref = os.environ.get("BASE_REF", "origin/main")
    commit_sha = os.environ["GITHUB_SHA"]
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    packs_dir = os.environ.get("PACKS_DIR", "/app/packs")
    rules_path = os.environ.get("RULES_PATH", "/app/rules")

    raw_frameworks = os.environ.get("FRAMEWORKS", "nist-800-53")
    try:
        frameworks = normalize_frameworks(raw_frameworks)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    fail_on = os.environ.get("FAIL_ON", "high")
    if fail_on not in SEVERITIES:
        print(
            f"Error: FAIL_ON='{fail_on}' is not valid. Choose from: {', '.join(SEVERITIES)}",
            file=sys.stderr,
        )
        return 2

    scan_mode = os.environ.get("SCAN_MODE", "both").lower()
    if scan_mode not in _VALID_SCAN_MODES:
        print(f"Error: SCAN_MODE='{scan_mode}' is not valid.", file=sys.stderr)
        return 2

    emit_oscal = os.environ.get("EMIT_OSCAL", "true").lower() == "true"
    emit_coverage = os.environ.get("EMIT_COVERAGE", "true").lower() == "true"
    emit_sarif = os.environ.get("EMIT_SARIF", "true").lower() == "true"
    seo_title = os.environ.get("SEO_TITLE", "Audit Packs Control Coverage Matrix")
    seo_description = os.environ.get(
        "SEO_DESCRIPTION",
        "Compliance control coverage report generated by audit-packs.",
    )
    seo_canonical_url = os.environ.get("SEO_CANONICAL_URL", "")

    adj_mode_str = os.environ.get("ADJUDICATION_MODE", "off").lower()
    adj_mode = (
        AdjudicationMode(adj_mode_str)
        if adj_mode_str in {m.value for m in AdjudicationMode}
        else AdjudicationMode.OFF
    )

    threshold_str = os.environ.get("CONFIDENCE_THRESHOLD", "0.70")
    try:
        threshold = float(threshold_str)
    except ValueError:
        print(
            f"Error: CONFIDENCE_THRESHOLD='{threshold_str}' is not a valid float.",
            file=sys.stderr,
        )
        return 2

    # Load score weights
    weights = DEFAULT_WEIGHTS
    score_weights_env = os.environ.get("SCORE_WEIGHTS", "")
    if score_weights_env:
        try:
            parsed = dict(pair.split(":") for pair in score_weights_env.split(","))
            weights = {k: float(v) for k, v in parsed.items()}
            if abs(sum(weights.values()) - 1.0) > 0.001:
                raise ValueError("weights must sum to 1.0")
        except Exception as exc:
            print(f"Error: SCORE_WEIGHTS invalid: {exc}", file=sys.stderr)
            return 2

    models_config_path = os.environ.get("AUDIT_MODELS_CONFIG", "audit-models.yaml")
    try:
        model_config = load_model_config(models_config_path)
    except ValueError as exc:
        print(f"Error loading model config: {exc}", file=sys.stderr)
        return 2

    codeql_sarif_dir = os.environ.get("CODEQL_SARIF_DIR", "")

    # Historical precision
    precision_path = os.path.join(".audit-cache", "precision.json")
    precision_data: dict = {}
    if os.path.exists(precision_path):
        try:
            with open(precision_path) as fh:
                precision_data = _json.load(fh)
        except Exception:
            pass

    audit_confirm = os.environ.get("AUDIT_CONFIRM", "")
    if audit_confirm:
        from audit_packs.confidence import update_precision
        import tempfile

        for pair in audit_confirm.split(","):
            pair = pair.strip()
            if ":" in pair:
                chk, fw = pair.split(":", 1)
                precision_data = update_precision(
                    chk.strip(), fw.strip(), precision_data
                )
        os.makedirs(".audit-cache", exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", dir=".audit-cache", delete=False, suffix=".tmp"
        ) as fh:
            _json.dump(precision_data, fh)
            tmp = fh.name
        os.replace(tmp, precision_path)

    # Fetch PR context (best-effort)
    pr_context = None
    if adj_mode is not AdjudicationMode.OFF and pr_number:
        try:
            from audit_packs.evidence import fetch_pr_context

            pr_context = fetch_pr_context(repo, pr_number, token)
        except Exception as exc:
            import logging

            logging.getLogger(__name__).warning("Could not fetch PR context: %s", exc)

    gate_tripped = False

    if scan_mode in ("diff", "both"):
        diff_text = run_git_diff(workspace, base_ref)
        changed = parse_unified_diff(diff_text)
        scored = analyze(
            workspace,
            changed,
            packs_dir,
            rules_path,
            frameworks,
            adj_mode=adj_mode,
            model_config=model_config,
            pr_context=pr_context,
            codeql_sarif_dir=codeql_sarif_dir,
            precision_data=precision_data,
            weights=weights,
            threshold=threshold,
        )
        from audit_packs.report import build_comments, build_summary_comment

        comments = build_comments(scored, commit_sha)
        summary = build_summary_comment(scored, threshold=threshold, weights=weights)
        if pr_number:
            post_review(
                comments,
                summary,
                repo=repo,
                pr_number=pr_number,
                token=token,
                commit_sha=commit_sha,
            )
        else:
            print(
                "PR_NUMBER not set; skipping posting PR review comment.",
                file=sys.stderr,
            )
        surfaced_cfs = [sf.result.control_finding for sf in scored if sf.surfaced]
        if gate_failed(surfaced_cfs, fail_on):
            gate_tripped = True

    if scan_mode in ("full", "both"):
        control_statuses = assess(
            workspace,
            packs_dir,
            rules_path,
            frameworks,
            adj_mode=adj_mode,
            model_config=model_config,
            precision_data=precision_data,
            weights=weights,
            threshold=threshold,
        )
        if emit_oscal:
            oscal_path = os.path.join(workspace, "oscal.json")
            oscal_data = to_assessment_results(control_statuses)
            with open(oscal_path, "w") as fh:
                _json.dump(oscal_data, fh, indent=2)
            print(f"::notice::OSCAL assessment-results written to {oscal_path}")
        if emit_coverage:
            for fmt in ("md", "html"):
                cov_path = os.path.join(workspace, f"coverage.{fmt}")
                content = build_coverage_matrix(
                    control_statuses,
                    fmt=fmt,
                    title=seo_title,
                    description=seo_description,
                    canonical_url=seo_canonical_url,
                )
                with open(cov_path, "w") as fh:
                    fh.write(content)
            print(
                f"::notice::Coverage matrix written to {os.path.join(workspace, 'coverage.md')}"
            )
            write_job_summary(build_coverage_matrix(control_statuses, fmt="md"))
        if emit_sarif:
            all_cfs = [cf for cs in control_statuses for cf in cs.findings]
            sarif_path = os.path.join(workspace, "audit-packs.sarif")
            with open(sarif_path, "w") as fh:
                _json.dump(build_sarif(all_cfs), fh, indent=2)
            print(f"::notice::Aggregate SARIF written to {sarif_path}")

    return 1 if gate_tripped else 0


if __name__ == "__main__":
    sys.exit(main())
