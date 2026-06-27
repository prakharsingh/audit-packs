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

from audit_packs_ai.adjudicate import AdjudicationMode
from audit_packs_core.models import SEVERITIES
from audit_packs_action.engines import (
    run_checkov,
    run_semgrep,
    run_git_diff,
    read_codeql_sarif,
    run_ast_rules,
    run_trivy_fs,
    run_trivy_image,
    run_tfsec,
    run_gitleaks,
)
from audit_packs_core.normalize import sarif_to_findings
from audit_packs_core.diff import parse_unified_diff
from audit_packs_mapping.packs import map_findings
from audit_packs_mapping.coverage import compute_coverage
from audit_packs_mapping.oscal import to_assessment_results
from audit_packs_action.report import (
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
    ast_rules_dir="ast-rules",
    trivy_enabled=False,
    trivy_image="",
    tfsec_enabled=False,
    gitleaks_enabled=False,
    scanners_dir=None,
):
    """Run engines, enrich, adjudicate, score, and return ScoredFindings for diff-changed lines."""
    if ast_rules_dir and not os.path.isabs(ast_rules_dir):
        ast_rules_dir = os.path.join(repo_dir, ast_rules_dir)
    from audit_packs_evidence.evidence import enrich, evidence_confidence
    from audit_packs_core.dataflow import extract_data_flows, flow_confidence
    from audit_packs_ai.confidence import (
        ScoreComponents,
        apply_confidence_gate,
        get_historical_precision,
        control_severity_score,
    )
    from audit_packs_ai.adjudicate import adjudicate as adj_finding
    from audit_packs_core.normalize import extract_rule_confidences

    if model_config is None:
        from audit_packs_ai.adjudicate import load_model_config

        model_config = load_model_config()
    if precision_data is None:
        precision_data = {}
    if weights is None:
        from audit_packs_ai.confidence import DEFAULT_WEIGHTS

        weights = DEFAULT_WEIGHTS

    # Run detection engines in parallel using async engines
    async def _run_scans_parallel():
        import asyncio
        from audit_packs_action.engines import (
            CheckovEngine,
            SemgrepEngine,
            CodeQLEngine,
            ASTEngine,
            TrivyEngine,
            TfsecEngine,
            GitleaksEngine,
            load_plugins,
        )

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
        ast_task = asyncio.create_task(
            ASTEngine().run_scan_async(repo_dir, {"rules_dir": ast_rules_dir})
        )
        trivy_fs_task = (
            asyncio.create_task(TrivyEngine().run_scan_async(repo_dir, {}))
            if trivy_enabled
            else None
        )
        trivy_img_task = (
            asyncio.create_task(
                TrivyEngine().run_scan_async("", {"image": trivy_image})
            )
            if (trivy_enabled and trivy_image)
            else None
        )
        tfsec_task = (
            asyncio.create_task(TfsecEngine().run_scan_async(repo_dir, {}))
            if tfsec_enabled
            else None
        )
        gitleaks_task = (
            asyncio.create_task(GitleaksEngine().run_scan_async(repo_dir, {}))
            if gitleaks_enabled
            else None
        )

        plugins = load_plugins(scanners_dir)
        plugin_tasks = []
        for p in plugins:
            plugin_tasks.append(
                (p.name, asyncio.create_task(p.run_scan_async(repo_dir, {})))
            )

        tasks = [checkov_task, semgrep_task, ast_task]
        if codeql_task:
            tasks.append(codeql_task)
        if trivy_fs_task:
            tasks.append(trivy_fs_task)
        if trivy_img_task:
            tasks.append(trivy_img_task)
        if tfsec_task:
            tasks.append(tfsec_task)
        if gitleaks_task:
            tasks.append(gitleaks_task)

        plugin_start_idx = len(tasks)
        for _, p_task in plugin_tasks:
            tasks.append(p_task)

        results = await asyncio.gather(*tasks)

        c_sarif = results[0]
        s_sarif = results[1]
        a_sarif = results[2]
        idx = 3
        q_sarif = results[idx] if codeql_task else {"runs": []}
        if codeql_task:
            idx += 1
        t_fs_sarif = results[idx] if trivy_fs_task else {"runs": []}
        if trivy_fs_task:
            idx += 1
        t_img_sarif = results[idx] if trivy_img_task else {"runs": []}
        if trivy_img_task:
            idx += 1
        tf_sarif = results[idx] if tfsec_task else {"runs": []}
        if tfsec_task:
            idx += 1
        gl_sarif = results[idx] if gitleaks_task else {"runs": []}
        if gitleaks_task:
            idx += 1

        plugin_results = {}
        for (p_name, _), res in zip(plugin_tasks, results[plugin_start_idx:]):
            plugin_results[p_name] = res

        return (
            c_sarif,
            s_sarif,
            q_sarif,
            a_sarif,
            t_fs_sarif,
            t_img_sarif,
            tf_sarif,
            gl_sarif,
            plugin_results,
        )

    try:
        import asyncio

        coro = _run_scans_parallel()
        (
            checkov_sarif,
            semgrep_sarif,
            codeql_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
            tfsec_sarif,
            gitleaks_sarif,
            plugin_sarifs,
        ) = asyncio.run(coro)
    except RuntimeError:
        try:
            coro.close()
        except AttributeError:
            pass
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        codeql_sarif = (
            read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}
        )
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
        tfsec_sarif = run_tfsec(repo_dir) if tfsec_enabled else {"runs": []}
        gitleaks_sarif = run_gitleaks(repo_dir) if gitleaks_enabled else {"runs": []}

        from audit_packs_action.engines import load_plugins

        plugins = load_plugins(scanners_dir)
        plugin_sarifs = {}
        for p in plugins:
            plugin_sarifs[p.name] = p.run_scan(repo_dir, {})
    except Exception:
        try:
            coro.close()
        except AttributeError:
            pass
        raise

    # Run all registered detection agents for Phase 2
    from audit_packs_evidence.agents import build_agents

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
    rule_confidences.update(extract_rule_confidences(checkov_sarif, "checkov"))
    rule_confidences.update(extract_rule_confidences(semgrep_sarif, "semgrep"))
    rule_confidences.update(extract_rule_confidences(codeql_sarif, "codeql"))
    rule_confidences.update(extract_rule_confidences(ast_sarif, "ast"))

    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")
    findings += sarif_to_findings(ast_sarif, "ast")
    trivy_runs = trivy_fs_sarif.get("runs", []) + trivy_img_sarif.get("runs", [])
    if trivy_runs:
        merged_trivy = {"runs": trivy_runs}
        rule_confidences.update(extract_rule_confidences(merged_trivy, "trivy"))
        findings += sarif_to_findings(merged_trivy, "trivy")
    if tfsec_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(tfsec_sarif, "tfsec"))
        findings += sarif_to_findings(tfsec_sarif, "tfsec")
    if gitleaks_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(gitleaks_sarif, "gitleaks"))
        findings += sarif_to_findings(gitleaks_sarif, "gitleaks")

    for p_name, p_sarif in plugin_sarifs.items():
        if p_sarif.get("runs"):
            rule_confidences.update(extract_rule_confidences(p_sarif, p_name))
            findings += sarif_to_findings(p_sarif, p_name)

    for agent in agents:
        agent_sarif = agent.detect(changed_file_texts)
        engine_name = f"{agent.framework}-agent"
        rule_confidences.update(extract_rule_confidences(agent_sarif, engine_name))
        findings += sarif_to_findings(agent_sarif, engine_name)

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
    codeql_sarif_dir="",
    ast_rules_dir="ast-rules",
    trivy_enabled=False,
    trivy_image="",
    tfsec_enabled=False,
    gitleaks_enabled=False,
    scanners_dir=None,
):
    """Run engines over the full workspace and return ControlStatus objects.

    This is the path that feeds the coverage matrix, OSCAL output, and
    aggregate SARIF — it gives posture across all IaC, not just the PR diff.
    """
    if ast_rules_dir and not os.path.isabs(ast_rules_dir):
        ast_rules_dir = os.path.join(repo_dir, ast_rules_dir)
    from audit_packs_ai.confidence import (
        ScoreComponents,
        apply_confidence_gate,
        get_historical_precision,
        control_severity_score,
    )
    from audit_packs_ai.adjudicate import adjudicate as adj_finding
    from audit_packs_core.normalize import extract_rule_confidences
    from audit_packs_core.dataflow import extract_data_flows, flow_confidence
    from audit_packs_evidence.evidence import extract_doc_context, evidence_confidence

    if model_config is None:
        from audit_packs_ai.adjudicate import load_model_config

        model_config = load_model_config()
    if precision_data is None:
        precision_data = {}
    if weights is None:
        from audit_packs_ai.confidence import DEFAULT_WEIGHTS

        weights = DEFAULT_WEIGHTS

    # Run detection engines in parallel using async engines
    async def _run_scans_parallel_assess():
        import asyncio
        from audit_packs_action.engines import (
            CheckovEngine,
            SemgrepEngine,
            ASTEngine,
            TrivyEngine,
            TfsecEngine,
            GitleaksEngine,
            load_plugins,
        )

        checkov_task = asyncio.create_task(CheckovEngine().run_scan_async(repo_dir, {}))
        semgrep_task = asyncio.create_task(
            SemgrepEngine().run_scan_async(repo_dir, {"rules_path": rules_path})
        )
        ast_task = asyncio.create_task(
            ASTEngine().run_scan_async(repo_dir, {"rules_dir": ast_rules_dir})
        )
        trivy_fs_task = (
            asyncio.create_task(TrivyEngine().run_scan_async(repo_dir, {}))
            if trivy_enabled
            else None
        )
        trivy_img_task = (
            asyncio.create_task(
                TrivyEngine().run_scan_async("", {"image": trivy_image})
            )
            if (trivy_enabled and trivy_image)
            else None
        )
        tfsec_task = (
            asyncio.create_task(TfsecEngine().run_scan_async(repo_dir, {}))
            if tfsec_enabled
            else None
        )
        gitleaks_task = (
            asyncio.create_task(GitleaksEngine().run_scan_async(repo_dir, {}))
            if gitleaks_enabled
            else None
        )

        plugins = load_plugins(scanners_dir)
        plugin_tasks = []
        for p in plugins:
            plugin_tasks.append(
                (p.name, asyncio.create_task(p.run_scan_async(repo_dir, {})))
            )

        tasks = [checkov_task, semgrep_task, ast_task]
        if trivy_fs_task:
            tasks.append(trivy_fs_task)
        if trivy_img_task:
            tasks.append(trivy_img_task)
        if tfsec_task:
            tasks.append(tfsec_task)
        if gitleaks_task:
            tasks.append(gitleaks_task)

        plugin_start_idx = len(tasks)
        for _, p_task in plugin_tasks:
            tasks.append(p_task)

        results = await asyncio.gather(*tasks)

        c_sarif, s_sarif, a_sarif = results[0], results[1], results[2]
        idx = 3
        t_fs = results[idx] if trivy_fs_task else {"runs": []}
        if trivy_fs_task:
            idx += 1
        t_img = results[idx] if trivy_img_task else {"runs": []}
        if trivy_img_task:
            idx += 1
        tf = results[idx] if tfsec_task else {"runs": []}
        if tfsec_task:
            idx += 1
        gl = results[idx] if gitleaks_task else {"runs": []}
        if gitleaks_task:
            idx += 1

        plugin_results = {}
        for (p_name, _), res in zip(plugin_tasks, results[plugin_start_idx:]):
            plugin_results[p_name] = res

        return c_sarif, s_sarif, a_sarif, t_fs, t_img, tf, gl, plugin_results

    try:
        import asyncio

        coro = _run_scans_parallel_assess()
        (
            checkov_sarif,
            semgrep_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
            tfsec_sarif,
            gitleaks_sarif,
            plugin_sarifs,
        ) = asyncio.run(coro)
    except RuntimeError:
        try:
            coro.close()
        except AttributeError:
            pass
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
        tfsec_sarif = run_tfsec(repo_dir) if tfsec_enabled else {"runs": []}
        gitleaks_sarif = run_gitleaks(repo_dir) if gitleaks_enabled else {"runs": []}

        from audit_packs_action.engines import load_plugins

        plugins = load_plugins(scanners_dir)
        plugin_sarifs = {}
        for p in plugins:
            plugin_sarifs[p.name] = p.run_scan(repo_dir, {})
    except Exception:
        try:
            coro.close()
        except AttributeError:
            pass
        raise

    codeql_sarif = (
        read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}
    )
    rule_confidences: dict[str, float] = {}
    rule_confidences.update(extract_rule_confidences(checkov_sarif, "checkov"))
    rule_confidences.update(extract_rule_confidences(semgrep_sarif, "semgrep"))
    rule_confidences.update(extract_rule_confidences(codeql_sarif, "codeql"))
    rule_confidences.update(extract_rule_confidences(ast_sarif, "ast"))

    # Load and run Phase 2 detection agents over the full workspace
    from audit_packs_evidence.agents import build_agents

    agents = build_agents(frameworks, packs_dir)
    all_file_texts = _read_all_files(repo_dir)

    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")
    findings += sarif_to_findings(ast_sarif, "ast")
    trivy_runs = trivy_fs_sarif.get("runs", []) + trivy_img_sarif.get("runs", [])
    if trivy_runs:
        merged_trivy = {"runs": trivy_runs}
        rule_confidences.update(extract_rule_confidences(merged_trivy, "trivy"))
        findings += sarif_to_findings(merged_trivy, "trivy")
    if tfsec_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(tfsec_sarif, "tfsec"))
        findings += sarif_to_findings(tfsec_sarif, "tfsec")
    if gitleaks_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(gitleaks_sarif, "gitleaks"))
        findings += sarif_to_findings(gitleaks_sarif, "gitleaks")

    for p_name, p_sarif in plugin_sarifs.items():
        if p_sarif.get("runs"):
            rule_confidences.update(extract_rule_confidences(p_sarif, p_name))
            findings += sarif_to_findings(p_sarif, p_name)

    for agent in agents:
        agent_sarif = agent.detect(all_file_texts)
        engine_name = f"{agent.framework}-agent"
        rule_confidences.update(extract_rule_confidences(agent_sarif, engine_name))
        findings += sarif_to_findings(agent_sarif, engine_name)

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
    ev_conf_map: dict[tuple, float] = {}
    enriched_findings = []
    for f in findings:
        rel_path = _rel(f.file, repo_dir)
        file_text = changed_file_texts.get(rel_path, "")
        doc_ctx = extract_doc_context(file_text, f.line) if file_text else ""
        enriched = replace(f, doc_context=doc_ctx)
        ev_conf_map[(f.check_id, rel_path, f.line)] = evidence_confidence(
            enriched, None
        )
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

    scored = apply_confidence_gate(
        pairs, threshold=threshold, mode=adj_mode, weights=weights
    )
    surfaced_cfs = [sf.result.control_finding for sf in scored if sf.surfaced]
    return compute_coverage(surfaced_cfs, packs_dir, frameworks)


def validate_policies(packs_dir: str, rules_path: str) -> int:
    """Validate compliance packs and semgrep rules schemas."""
    import yaml
    import glob

    print("=" * 60)
    print("Policy Validation Suite")
    print("=" * 60)

    errors = 0

    # 1. Validate Packs
    if os.path.exists(packs_dir):
        print(f"\nChecking compliance packs in {packs_dir}...")
        pack_files = glob.glob(
            os.path.join(packs_dir, "**/controls.yaml"), recursive=True
        )
        if not pack_files:
            print("  ℹ No controls.yaml pack files found.")
        for pf in pack_files:
            try:
                with open(pf) as fh:
                    data = yaml.safe_load(fh)

                # Check required pack keys
                missing = []
                for k in ("title", "controls"):
                    if k not in data:
                        missing.append(k)
                if missing:
                    print(f"  ❌ {pf}: Missing required keys: {', '.join(missing)}")
                    errors += 1
                    continue

                controls = data.get("controls", [])
                if not isinstance(controls, list):
                    print(f"  ❌ {pf}: 'controls' must be a list of mappings.")
                    errors += 1
                    continue

                ctrl_errors = 0
                for c in controls:
                    if not isinstance(c, dict):
                        ctrl_errors += 1
                        continue
                    if "id" not in c or "title" not in c:
                        ctrl_errors += 1

                if ctrl_errors:
                    print(
                        f"  ❌ {pf}: {ctrl_errors} controls are missing 'id' or 'title'."
                    )
                    errors += ctrl_errors
                else:
                    print(f"  ✅ {pf} is valid ({len(controls)} controls).")
            except Exception as e:
                print(f"  ❌ {pf}: Failed to parse YAML: {e}")
                errors += 1
    else:
        print(f"  ❌ Packs directory '{packs_dir}' does not exist.")
        errors += 1

    # 2. Validate Semgrep Rules
    if os.path.exists(rules_path):
        print(f"\nChecking custom Semgrep rules in {rules_path}...")
        rule_files = glob.glob(os.path.join(rules_path, "*.yaml")) + glob.glob(
            os.path.join(rules_path, "*.yml")
        )
        if not rule_files:
            print("  ℹ No Semgrep rule files found.")
        for rf in rule_files:
            try:
                with open(rf) as fh:
                    data = yaml.safe_load(fh)
                if not isinstance(data, dict) or "rules" not in data:
                    print(f"  ❌ {rf}: Missing 'rules' key or not a dictionary.")
                    errors += 1
                    continue
                rules = data.get("rules", [])
                if not isinstance(rules, list):
                    print(f"  ❌ {rf}: 'rules' must be a list of rules.")
                    errors += 1
                    continue

                rule_errors = 0
                for r in rules:
                    if not isinstance(r, dict):
                        rule_errors += 1
                        continue
                    missing_r = [
                        k
                        for k in ("id", "message", "severity", "languages")
                        if k not in r
                    ]
                    if missing_r:
                        rule_errors += 1
                if rule_errors:
                    print(
                        f"  ❌ {rf}: {rule_errors} rules are missing required fields (id, message, severity, languages)."
                    )
                    errors += rule_errors
                else:
                    print(f"  ✅ {rf} is valid ({len(rules)} rules).")
            except Exception as e:
                print(f"  ❌ {rf}: Failed to parse Semgrep rules: {e}")
                errors += 1
    else:
        print(f"  ❌ Rules path '{rules_path}' does not exist.")
        errors += 1

    print("\n" + "=" * 60)
    if errors == 0:
        print("  🎉 Policy and rules validation PASSED!")
        return 0
    else:
        print(f"  ❌ Policy and rules validation FAILED with {errors} errors.")
        return 1


def init_wizard(workspace: str) -> int:
    """Run an interactive wizard to configure audit-packs."""
    print("=" * 60)
    print("              Audit Packs Configuration Wizard")
    print("=" * 60)
    print("This wizard will help you set up compliance auditing for your repo.")

    print("\nWhich compliance frameworks would you like to target?")
    print(
        "Supported: nist-800-53, soc2, gdpr, hipaa, iso27001, pci-dss, fedramp, org-policy"
    )
    frameworks_input = input(
        "Target frameworks (comma-separated, default: nist-800-53,soc2): "
    ).strip()
    if not frameworks_input:
        frameworks_input = "nist-800-53,soc2"

    models_config = "audit-models.yaml"
    models_path = os.path.join(workspace, models_config)
    print(f"\nCreating AI Adjudication model router config: {models_config}...")
    models_content = """# audit-models.yaml
# Map roles to AI providers for confidence scoring consensus.
# Define API keys in your environment variables.
models:
  detector:
    provider: openai
    model: gpt-4o
    api_key_env: OPENAI_API_KEY

  verifier:
    provider: anthropic
    model: claude-3-5-sonnet
    api_key_env: ANTHROPIC_API_KEY

  adversarial:
    provider: google
    model: gemini-1.5-pro
    api_key_env: GOOGLE_API_KEY

  judge:
    provider: openai
    model: gpt-4o
    api_key_env: OPENAI_API_KEY
"""
    if os.path.exists(models_path):
        overwrite = (
            input(f"File {models_config} already exists. Overwrite? (y/N): ")
            .lower()
            .strip()
        )
        if overwrite == "y":
            with open(models_path, "w") as f:
                f.write(models_content)
            print("  Updated audit-models.yaml")
        else:
            print("  Skipped audit-models.yaml")
    else:
        with open(models_path, "w") as f:
            f.write(models_content)
        print("  Created audit-models.yaml")

    workflow_dir = os.path.join(workspace, ".github", "workflows")
    workflow_path = os.path.join(workflow_dir, "audit.yml")
    print("\nCreating GitHub Actions workflow: .github/workflows/audit.yml...")
    workflow_content = f"""name: Audit Packs Compliance Scan

on:
  pull_request:
    branches: [ main, master ]
  push:
    branches: [ main, master ]

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Required for posting PR review inline comments

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required for diff-based scan

      - name: Run Compliance Scan
        uses: prakharsingh/audit-packs@v1
        with:
          frameworks: {frameworks_input}
          fail-on: high
          scan-mode: both
          adjudication-mode: off # Change to 'enforce' or 'advisory' to enable AI
        env:
          GH_TOKEN: ${{{{ github.token }}}}
          # Un-comment if AI adjudication is enabled:
          # OPENAI_API_KEY: ${{{{ secrets.OPENAI_API_KEY }}}}
          # ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
"""
    os.makedirs(workflow_dir, exist_ok=True)
    if os.path.exists(workflow_path):
        overwrite = (
            input("File .github/workflows/audit.yml already exists. Overwrite? (y/N): ")
            .lower()
            .strip()
        )
        if overwrite == "y":
            with open(workflow_path, "w") as f:
                f.write(workflow_content)
            print("  Updated workflow configuration.")
        else:
            print("  Skipped workflow configuration.")
    else:
        with open(workflow_path, "w") as f:
            f.write(workflow_content)
        print("  Created workflow configuration.")

    org_policy_dir = os.path.join(workspace, "packs", "org-policy")
    org_policy_path = os.path.join(org_policy_dir, "controls.yaml")
    print(
        "\nCreating Custom Policy-as-Code Pack template: packs/org-policy/controls.yaml..."
    )
    org_policy_content = """title: Internal Acme Corp Security Policy
crosswalk: nist-800-53
schema_version: '2'
framework: org-policy
controls:
  - id: ACME-ENC-1
    title: All Datastores Must Use Encryption at Rest
    maps_to:
      - SC-13
      - SC-28
  - id: ACME-NET-1
    title: Restrict Inbound Network Access to Secured Boundaries
    maps_to:
      - SC-7
  - id: ACME-LOG-1
    title: Enable Centralized System and Audit Logging
    maps_to:
      - AU-2
"""
    os.makedirs(org_policy_dir, exist_ok=True)
    if os.path.exists(org_policy_path):
        overwrite = (
            input(
                "File packs/org-policy/controls.yaml already exists. Overwrite? (y/N): "
            )
            .lower()
            .strip()
        )
        if overwrite == "y":
            with open(org_policy_path, "w") as f:
                f.write(org_policy_content)
            print("  Updated custom policy template.")
        else:
            print("  Skipped custom policy template.")
    else:
        with open(org_policy_path, "w") as f:
            f.write(org_policy_content)
        print("  Created custom policy template.")

    print("\n" + "=" * 60)
    print("🎉 Onboarding and setup complete!")
    print("To run a local compliance scan, use:")
    print(f"  audit-packs --frameworks {frameworks_input}")
    print("=" * 60)
    return 0


def print_local_report(scored_findings, threshold, weights):
    """Print a beautiful console compliance report for local runs."""
    from collections import defaultdict

    by_framework = defaultdict(list)
    for sf in scored_findings:
        fw = sf.result.control_finding.framework
        by_framework[fw].append(sf)

    print("\n\033[1m" + "=" * 60)
    print("                  AUDIT PACKS SCAN SUMMARY")
    print("=" * 60 + "\033[0m")

    print("\033[1m| Framework   | Findings | Suppressed | Avg Score |\033[0m")
    print("|-------------|----------|------------|-----------|")

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
        print(f"| {fw:<11} | {len(surfaced):<8} | {len(suppressed):<10} | {avg:<8}% |")
        total_surfaced += len(surfaced)
        total_suppressed += len(suppressed)
    print(
        f"\nTotal: \033[91m{total_surfaced} surfaced\033[0m, \033[90m{total_suppressed} suppressed (FP)\033[0m. Threshold: {round(threshold * 100)}%."
    )

    surfaced_findings = [sf for sf in scored_findings if sf.surfaced]
    if surfaced_findings:
        print("\n\033[1m" + "-" * 60)
        print("Surfaced Compliance Violations:")
        print("-" * 60 + "\033[0m")
        for sf in surfaced_findings:
            cf = sf.result.control_finding
            f = cf.finding
            score_pct = round(sf.finding_score * 100)
            print(
                f"\033[91m● [{cf.framework.upper()} / {cf.control_id} — {cf.control_title}]\033[0m score: {score_pct}%"
            )
            print(
                f"  Severity: \033[1m{f.severity}\033[0m | Engine: {f.engine} ({f.check_id})"
            )
            print(f"  Location: \033[36m{f.file}:{f.line}\033[0m")
            print(f"  Finding:  {f.message}")
            print(f"  Evidence: \033[90m{f.evidence}\033[0m")
            if sf.result.rationale:
                print(f"  Rationale: {sf.result.rationale}")
            print()


def print_local_coverage_matrix(control_statuses):
    """Print the control coverage matrix directly to the console."""
    from collections import defaultdict
    from audit_packs_core.models import AssessmentStatus

    by_fw = defaultdict(list)
    for s in control_statuses:
        by_fw[s.framework].append(s)

    print("\n\033[1m" + "=" * 60)
    print("                COMPLIANCE CONTROL COVERAGE")
    print("=" * 60 + "\033[0m")

    status_colors = {
        AssessmentStatus.PASS: "\033[92m✅ PASS\033[0m",
        AssessmentStatus.FAIL: "\033[91m❌ FAIL\033[0m",
        AssessmentStatus.MANUAL: "\033[93m📋 MANUAL\033[0m",
        AssessmentStatus.NOT_APPLICABLE: "\033[90m➖ N/A\033[0m",
    }

    for fw, fw_statuses in sorted(by_fw.items()):
        n_pass = sum(1 for s in fw_statuses if s.status == AssessmentStatus.PASS)
        n_fail = sum(1 for s in fw_statuses if s.status == AssessmentStatus.FAIL)
        n_manual = sum(1 for s in fw_statuses if s.status == AssessmentStatus.MANUAL)
        n_total = len(fw_statuses)

        print(
            f"\n\033[1m{fw.upper()} Framework Summary:\033[0m {n_pass} Pass, {n_fail} Fail, {n_manual} Manual ({n_total} total)"
        )
        print("-" * 75)
        print(
            f"\033[1m| {'Control':<10} | {'Status':<12} | {'Findings':<8} | {'Title':<35} |\033[0m"
        )
        print("-" * 75)
        for s in fw_statuses:
            status_lbl = status_colors.get(s.status, s.status.value.upper())
            title_truncated = (
                s.control_title[:35] + "..."
                if len(s.control_title) > 35
                else s.control_title
            )
            print(
                f"| {s.control_id:<10} | {status_lbl:<21} | {len(s.findings):<8} | {title_truncated:<35} |"
            )
        print("-" * 75)


def pack_init(pack_id: str, output_dir: str) -> int:
    import json

    target_dir = os.path.join(output_dir, pack_id)
    if os.path.exists(target_dir):
        print(f"Error: Target directory {target_dir} already exists.")
        return 1

    os.makedirs(os.path.join(target_dir, "rules"), exist_ok=True)
    os.makedirs(os.path.join(target_dir, "agents"), exist_ok=True)

    controls_content = f"""schema_version: "2"
framework: "{pack_id}"
title: "Custom Compliance Framework {pack_id}"
crosswalk: nist-800-53
controls:
  - id: CP-1.1
    title: "Example Automated Control"
    maps_to:
      - SC-13
    evidence_requirements:
      - "S3 bucket encryption must be enabled"
  - id: CP-1.2
    title: "Example Governance Policy"
    assessment: manual
"""
    with open(os.path.join(target_dir, "controls.yaml"), "w") as fh:
        fh.write(controls_content)

    metadata = {
        "schema_version": "2",
        "id": pack_id,
        "version": "0.1.0",
        "title": f"Custom Compliance Framework {pack_id}",
        "publisher": "Developer",
        "dependencies": {"nist-800-53": ">=5.0.0"},
    }
    with open(os.path.join(target_dir, "metadata.json"), "w") as fh:
        json.dump(metadata, fh, indent=2)

    print(f"Successfully initialized framework pack '{pack_id}' at {target_dir}")
    print("Files created:")
    print(f"  - {os.path.join(target_dir, 'controls.yaml')} (Control mappings)")
    print(f"  - {os.path.join(target_dir, 'metadata.json')} (Pack metadata)")
    print(f"  - {os.path.join(target_dir, 'rules/')} (Custom Semgrep rules)")
    print(f"  - {os.path.join(target_dir, 'agents/')} (Custom detection agents)")
    return 0


def pack_validate(pack_path: str) -> int:
    import json
    import yaml

    controls_file = os.path.join(pack_path, "controls.yaml")
    if not os.path.exists(controls_file):
        print(f"Error: {controls_file} does not exist.")
        return 1

    try:
        with open(controls_file) as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        print(f"Error: Failed to parse {controls_file}: {exc}")
        return 1

    if not isinstance(data, dict):
        print("Error: controls.yaml must be a dictionary at the top level.")
        return 1

    errors = []

    # Required keys
    for req in ("schema_version", "framework", "title", "controls"):
        if req not in data:
            errors.append(f"Missing required top-level key: {req}")

    if errors:
        for err in errors:
            print(f"Validation Error: {err}")
        return 1

    controls = data.get("controls")
    if not isinstance(controls, list):
        print("Validation Error: 'controls' key must be a list.")
        return 1

    # Crosswalk check
    crosswalk = data.get("crosswalk")
    if crosswalk:
        if crosswalk != "nist-800-53":
            print(
                f"Validation Warning: non-standard crosswalk: '{crosswalk}' (expected 'nist-800-53')"
            )

        parent_dir = os.path.dirname(os.path.abspath(pack_path))
        nist_file = os.path.join(parent_dir, "nist-800-53", "controls.yaml")
        if not os.path.exists(nist_file):
            nist_file = os.path.join(
                os.getcwd(), "packs", "nist-800-53", "controls.yaml"
            )

        if os.path.exists(nist_file):
            try:
                with open(nist_file) as fh:
                    nist_data = yaml.safe_load(fh)
                nist_control_ids = {c["id"] for c in nist_data.get("controls", [])}

                for idx, c in enumerate(controls):
                    if not isinstance(c, dict):
                        print(
                            f"Validation Error: Control at index {idx} is not a dictionary."
                        )
                        return 1
                    cid = c.get("id", f"index {idx}")
                    maps_to = c.get("maps_to", [])
                    if isinstance(maps_to, str):
                        maps_to = [maps_to]
                    for target in maps_to:
                        if target not in nist_control_ids:
                            errors.append(
                                f"Control '{cid}' maps to non-existent NIST control: '{target}'"
                            )
            except Exception as exc:
                print(
                    f"Validation Warning: Could not load nist-800-53 pack for crosswalk validation: {exc}"
                )
        else:
            print(
                "Validation Warning: nist-800-53 pack controls.yaml not found; skipping crosswalk ID checks."
            )

    # Check metadata.json
    metadata_file = os.path.join(pack_path, "metadata.json")
    if os.path.exists(metadata_file):
        try:
            with open(metadata_file) as fh:
                meta = json.load(fh)
            if not isinstance(meta, dict):
                errors.append("metadata.json must be a JSON object.")
            else:
                for req in ("schema_version", "id", "version", "title"):
                    if req not in meta:
                        errors.append(f"metadata.json missing required field: '{req}'")
        except Exception as exc:
            errors.append(f"Failed to parse metadata.json: {exc}")

    if errors:
        print(f"\nFound {len(errors)} validation errors:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(f"Framework pack at {pack_path} is VALID!")
    return 0


def pack_test(pack_path: str, fixture_dir: str, scanners_dir: str = None) -> int:
    import yaml

    if not os.path.exists(pack_path):
        print(f"Error: Pack directory {pack_path} does not exist.")
        return 1
    if not os.path.exists(fixture_dir):
        print(f"Error: Fixture directory {fixture_dir} does not exist.")
        return 1

    controls_file = os.path.join(pack_path, "controls.yaml")
    try:
        with open(controls_file) as fh:
            pack_data = yaml.safe_load(fh)
    except Exception as exc:
        print(f"Error loading pack controls.yaml: {exc}")
        return 1

    framework = pack_data.get("framework")
    if not framework:
        print("Error: Pack does not define a framework key.")
        return 1

    print(
        f"Running dry-run mapping test for framework '{framework}' on fixture '{fixture_dir}'..."
    )

    parent_dir = os.path.dirname(os.path.abspath(pack_path))

    try:
        from audit_packs_action.engines import (
            run_checkov,
            run_semgrep,
            load_plugins,
        )
        from audit_packs_core.normalize import sarif_to_findings

        findings = []

        try:
            c_sarif = run_checkov(fixture_dir)
            findings += sarif_to_findings(c_sarif, "checkov")
        except Exception:
            pass

        rules_path = os.path.join(os.getcwd(), "rules")
        if not os.path.exists(rules_path):
            rules_path = "/app/rules"
        try:
            s_sarif = run_semgrep(fixture_dir, rules_path)
            findings += sarif_to_findings(s_sarif, "semgrep")
        except Exception:
            pass

        plugins = load_plugins(scanners_dir)
        for p in plugins:
            try:
                p_sarif = p.run_scan(fixture_dir, {})
                findings += sarif_to_findings(p_sarif, p.name)
            except Exception:
                pass

        from audit_packs_mapping.packs import map_findings

        mapped = map_findings(findings, parent_dir, [framework])

        print("\nTest Scan Results Mapping Table:")
        print("-" * 110)
        print(
            f"| {'Engine':<12} | {'Check ID':<25} | {'Control ID':<12} | {'Control Title':<45} |"
        )
        print("-" * 110)
        if not mapped:
            print(f"| {'(No findings mapped)':^106} |")
        for cf in mapped:
            title_trunc = cf.control_title[:45]
            print(
                f"| {cf.finding.engine:<12} | {cf.finding.check_id:<25} | {cf.control_id:<12} | {title_trunc:<45} |"
            )
        print("-" * 110)
        print(f"Total mapped findings: {len(mapped)}")

    except Exception as exc:
        print(f"Error executing test run: {exc}")
        return 1

    return 0


def pack_publish(pack_path: str, output_dir: str) -> int:
    import json
    import tarfile
    import yaml

    if not os.path.exists(pack_path):
        print(f"Error: Pack directory {pack_path} does not exist.")
        return 1

    controls_file = os.path.join(pack_path, "controls.yaml")
    if not os.path.exists(controls_file):
        print(f"Error: {controls_file} does not exist.")
        return 1

    try:
        with open(controls_file) as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        print(f"Error parsing controls.yaml: {exc}")
        return 1

    framework = data.get("framework")
    if not framework:
        print("Error: Pack controls.yaml is missing the 'framework' key.")
        return 1

    version = "0.1.0"
    metadata_file = os.path.join(pack_path, "metadata.json")
    if os.path.exists(metadata_file):
        try:
            with open(metadata_file) as fh:
                meta = json.load(fh)
                version = meta.get("version", version)
        except Exception:
            pass

    tarball_name = f"{framework}-{version}.tar.gz"
    tarball_path = os.path.join(output_dir, tarball_name)

    print(f"Packaging compliance pack '{framework}' version {version}...")
    try:
        with tarfile.open(tarball_path, "w:gz") as tar:
            for item in ("controls.yaml", "metadata.json", "rules", "agents"):
                item_path = os.path.join(pack_path, item)
                if os.path.exists(item_path):
                    tar.add(item_path, arcname=item)
        print(f"Successfully packaged framework pack to {tarball_path}")
    except Exception as exc:
        print(f"Error packaging framework pack: {exc}")
        return 1

    return 0


def pack_install(source: str, output_dir: str = None) -> int:
    import urllib.request
    import tarfile
    import tempfile
    import shutil
    import yaml

    if not output_dir:
        output_dir = os.path.join(os.path.expanduser("~"), ".audit-packs", "installed")

    os.makedirs(output_dir, exist_ok=True)

    url = source
    if not (source.startswith("http://") or source.startswith("https://")):
        if os.path.exists(source):
            tarball_path = source
            url = None
        elif "/" in source:
            parts = source.split("@")
            repo_part = parts[0]
            tag = parts[1] if len(parts) > 1 else "main"
            url = f"https://github.com/{repo_part}/archive/refs/tags/{tag}.tar.gz"
            print(f"Resolving GitHub reference '{source}' to {url}")
        else:
            print(f"Error: Local file '{source}' not found or is not a valid tarball.")
            return 1

    if url:
        print(f"Downloading pack from {url}...")
        try:
            temp_fd, tarball_path = tempfile.mkstemp(suffix=".tar.gz")
            os.close(temp_fd)
            req = urllib.request.Request(
                url, headers={"User-Agent": "audit-packs-cli/2.0"}
            )
            with urllib.request.urlopen(req) as response, open(
                tarball_path, "wb"
            ) as out_file:
                shutil.copyfileobj(response, out_file)
        except Exception as exc:
            if "/" in source and "@" in source and "refs/tags/" in url:
                fallback_url = url.replace("refs/tags/", "refs/heads/")
                print(
                    f"Tag download failed. Trying fallback branch URL: {fallback_url}"
                )
                try:
                    req = urllib.request.Request(
                        fallback_url, headers={"User-Agent": "audit-packs-cli/2.0"}
                    )
                    with urllib.request.urlopen(req) as response, open(
                        tarball_path, "wb"
                    ) as out_file:
                        shutil.copyfileobj(response, out_file)
                except Exception as exc_fallback:
                    print(f"Error downloading pack: {exc_fallback}")
                    return 1
            else:
                print(f"Error downloading pack: {exc}")
                return 1

    print("Extracting and validating pack package...")
    try:
        with tempfile.TemporaryDirectory() as extract_tmp:
            with tarfile.open(tarball_path, "r:gz") as tar:
                tar.extractall(path=extract_tmp)

            controls_src_path = None
            for root, dirs, files in os.walk(extract_tmp):
                if "controls.yaml" in files:
                    controls_src_path = os.path.join(root, "controls.yaml")
                    break

            if not controls_src_path:
                print(
                    "Error: Extract failed. controls.yaml was not found inside the package."
                )
                return 1

            pack_root = os.path.dirname(controls_src_path)
            with open(controls_src_path) as fh:
                data = yaml.safe_load(fh) or {}
            framework = data.get("framework")
            if not framework:
                print("Error: Pack controls.yaml is missing the 'framework' ID.")
                return 1

            target_install_dir = os.path.join(output_dir, framework)
            if os.path.exists(target_install_dir):
                print(
                    f"Warning: Overwriting existing installation at {target_install_dir}"
                )
                shutil.rmtree(target_install_dir)

            shutil.copytree(pack_root, target_install_dir)
            print(
                f"Successfully installed framework pack '{framework}' to {target_install_dir}"
            )
    except Exception as exc:
        print(f"Error extracting pack package: {exc}")
        return 1
    finally:
        if url and os.path.exists(tarball_path):
            try:
                os.remove(tarball_path)
            except OSError:
                pass

    return 0


def handle_pack_subcommand(args_list: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="audit-packs framework pack utilities."
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize a new framework pack")
    init_parser.add_argument(
        "pack_id", help="The unique ID of the framework pack (e.g. custom-hipaa)"
    )
    init_parser.add_argument(
        "--output-dir",
        default="packs",
        help="Output directory to create the pack folder in",
    )

    val_parser = subparsers.add_parser(
        "validate", help="Validate a framework pack directory"
    )
    val_parser.add_argument("pack_path", help="Path to the framework pack directory")

    test_parser = subparsers.add_parser(
        "test", help="Test pack mappings against a target fixture"
    )
    test_parser.add_argument("pack_path", help="Path to the framework pack directory")
    test_parser.add_argument(
        "--fixture", required=True, help="Path to target directory of scan fixtures"
    )
    test_parser.add_argument(
        "--scanners-dir", default=None, help="Optional custom scanners directory"
    )

    pub_parser = subparsers.add_parser(
        "publish", help="Package a framework pack for publishing"
    )
    pub_parser.add_argument("pack_path", help="Path to the framework pack directory")
    pub_parser.add_argument(
        "--output-dir", default=".", help="Directory to save the packaged tarball"
    )

    inst_parser = subparsers.add_parser(
        "install", help="Install a framework pack from a URL or GitHub"
    )
    inst_parser.add_argument(
        "source",
        help="The source URL, GitHub repo (owner/repo@version), or path to local tarball",
    )
    inst_parser.add_argument(
        "--output-dir", default=None, help="Custom installation target directory"
    )

    parsed = parser.parse_args(args_list)

    if parsed.cmd == "init":
        return pack_init(parsed.pack_id, parsed.output_dir)
    elif parsed.cmd == "validate":
        return pack_validate(parsed.pack_path)
    elif parsed.cmd == "test":
        return pack_test(parsed.pack_path, parsed.fixture, parsed.scanners_dir)
    elif parsed.cmd == "publish":
        return pack_publish(parsed.pack_path, parsed.output_dir)
    elif parsed.cmd == "install":
        return pack_install(parsed.source, parsed.output_dir)

    return 0


def main() -> int:
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "pack":
        return handle_pack_subcommand(sys.argv[2:])
    import json as _json
    import argparse
    from audit_packs_ai.adjudicate import load_model_config, AdjudicationMode
    from audit_packs_ai.confidence import DEFAULT_WEIGHTS
    from audit_packs_action.report import (
        build_summary_comment,
        post_slack_message,
        create_jira_issue,
        build_compact_coverage_summary,
    )

    parser = argparse.ArgumentParser(
        description="audit-packs compliance scan orchestration CLI."
    )
    parser.add_argument(
        "--frameworks",
        default=os.environ.get("FRAMEWORKS", "nist-800-53"),
        help="Frameworks to audit (comma/newline separated)",
    )
    parser.add_argument(
        "--fail-on",
        default=os.environ.get("FAIL_ON", "high"),
        choices=SEVERITIES,
        help="Severity failure threshold",
    )
    parser.add_argument(
        "--scan-mode",
        default=os.environ.get("SCAN_MODE", "both"),
        choices=list(_VALID_SCAN_MODES),
        help="Scan mode (diff, full, both)",
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("GITHUB_WORKSPACE", "."),
        help="Repo workspace directory",
    )
    parser.add_argument(
        "--base-ref",
        default=os.environ.get("BASE_REF", "origin/main"),
        help="Base git branch/ref to diff against",
    )
    parser.add_argument(
        "--packs-dir",
        default=os.environ.get("PACKS_DIR"),
        help="Directory containing compliance framework packs",
    )
    parser.add_argument(
        "--rules-path",
        default=os.environ.get("RULES_PATH"),
        help="Directory containing semgrep rules",
    )
    parser.add_argument(
        "--adjudication-mode",
        default=os.environ.get("ADJUDICATION_MODE", "off"),
        help="LLM consensus adjudication mode (off, advisory, enforce)",
    )
    parser.add_argument(
        "--confidence-threshold",
        default=os.environ.get("CONFIDENCE_THRESHOLD", "0.70"),
        help="Composite confidence threshold for filtering",
    )
    parser.add_argument(
        "--codeql-sarif",
        default=os.environ.get("CODEQL_SARIF_DIR", ""),
        help="Path to directory containing CodeQL SARIF outputs",
    )
    parser.add_argument(
        "--trivy",
        action="store_true",
        default=os.environ.get("TRIVY_ENABLED", "false").lower() == "true",
        help="Enable Trivy scanning",
    )
    parser.add_argument(
        "--trivy-image",
        default=os.environ.get("TRIVY_IMAGE", ""),
        help="Trivy image target",
    )
    parser.add_argument(
        "--tfsec",
        action="store_true",
        default=os.environ.get("TFSEC_ENABLED", "false").lower() == "true",
        help="Enable tfsec scanning",
    )
    parser.add_argument(
        "--gitleaks",
        action="store_true",
        default=os.environ.get("GITLEAKS_ENABLED", "false").lower() == "true",
        help="Enable gitleaks secret detection",
    )
    parser.add_argument(
        "--scanners-dir",
        default=os.environ.get("SCANNERS_DIR"),
        help="Directory containing declarative scanner plugins",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Interactive configuration wizard to bootstrap compliance",
    )
    parser.add_argument(
        "--validate-policy",
        action="store_true",
        help="Validate custom compliance packs and rules schema",
    )
    parser.add_argument(
        "--slack-webhook",
        default=os.environ.get("SLACK_WEBHOOK_URL"),
        help="Slack Webhook URL for scan alerts",
    )
    parser.add_argument(
        "--jira-url",
        default=os.environ.get("JIRA_URL"),
        help="Jira Server/Cloud URL",
    )
    parser.add_argument(
        "--jira-email",
        default=os.environ.get("JIRA_EMAIL"),
        help="Jira email/username for API auth",
    )
    parser.add_argument(
        "--jira-token",
        default=os.environ.get("JIRA_API_TOKEN"),
        help="Jira API Token",
    )
    parser.add_argument(
        "--jira-project",
        default=os.environ.get("JIRA_PROJECT"),
        help="Jira Project Key",
    )

    # Use parse_known_args to allow parsing when called by pytest/other scripts that inject extra args
    args, unknown = parser.parse_known_args()

    if args.init:
        return init_wizard(args.workspace)

    packs_dir = args.packs_dir
    if not packs_dir or not os.path.exists(packs_dir):
        candidate = os.path.join(args.workspace, "packs")
        if os.path.exists(candidate):
            packs_dir = candidate
        else:
            packs_dir = "/app/packs"

    rules_path = args.rules_path
    if not rules_path or not os.path.exists(rules_path):
        candidate = os.path.join(args.workspace, "rules")
        if os.path.exists(candidate):
            rules_path = candidate
        else:
            rules_path = "/app/rules"

    scanners_dir = args.scanners_dir
    if not scanners_dir or not os.path.exists(scanners_dir):
        candidate = os.path.join(args.workspace, ".audit-packs/scanners")
        if os.path.exists(candidate):
            scanners_dir = candidate
        else:
            candidate = os.path.join(args.workspace, "scanners")
            if os.path.exists(candidate):
                scanners_dir = candidate
            else:
                scanners_dir = None

    if args.validate_policy:
        return validate_policies(packs_dir, rules_path)

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    commit_sha = os.environ.get("GITHUB_SHA", "")
    workspace = args.workspace

    try:
        frameworks = normalize_frameworks(args.frameworks)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    fail_on = args.fail_on
    scan_mode = args.scan_mode
    emit_oscal = os.environ.get("EMIT_OSCAL", "true").lower() == "true"
    emit_coverage = os.environ.get("EMIT_COVERAGE", "true").lower() == "true"
    emit_sarif = os.environ.get("EMIT_SARIF", "true").lower() == "true"
    seo_title = os.environ.get("SEO_TITLE", "Audit Packs Control Coverage Matrix")
    seo_description = os.environ.get(
        "SEO_DESCRIPTION",
        "Compliance control coverage report generated by audit-packs.",
    )
    seo_canonical_url = os.environ.get("SEO_CANONICAL_URL", "")

    adj_mode_str = args.adjudication_mode.lower()
    adj_mode = (
        AdjudicationMode(adj_mode_str)
        if adj_mode_str in {m.value for m in AdjudicationMode}
        else AdjudicationMode.OFF
    )

    try:
        threshold = float(args.confidence_threshold)
    except ValueError:
        print(
            f"Error: CONFIDENCE_THRESHOLD='{args.confidence_threshold}' is not a valid float.",
            file=sys.stderr,
        )
        return 2

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

    codeql_sarif_dir = args.codeql_sarif
    ast_rules_dir = os.environ.get("AST_RULES_DIR", "ast-rules")
    if not os.path.isabs(ast_rules_dir):
        ast_rules_dir = os.path.join(workspace, ast_rules_dir)

    trivy_enabled = args.trivy
    trivy_image = args.trivy_image
    tfsec_enabled = args.tfsec
    gitleaks_enabled = args.gitleaks

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
        from audit_packs_ai.confidence import update_precision
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

    pr_context = None
    if adj_mode is not AdjudicationMode.OFF and pr_number:
        try:
            from audit_packs_evidence.evidence import fetch_pr_context

            pr_context = fetch_pr_context(repo, pr_number, token)
        except Exception as exc:
            import logging

            logging.getLogger(__name__).warning("Could not fetch PR context: %s", exc)

    gate_tripped = False
    scored = []
    control_statuses = []

    if scan_mode in ("diff", "both"):
        diff_text = run_git_diff(workspace, args.base_ref)
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
            ast_rules_dir=ast_rules_dir,
            trivy_enabled=trivy_enabled,
            trivy_image=trivy_image,
            tfsec_enabled=tfsec_enabled,
            gitleaks_enabled=gitleaks_enabled,
            scanners_dir=scanners_dir,
        )
        from audit_packs_action.report import build_comments, build_summary_comment

        comments = build_comments(scored, commit_sha)
        summary = build_summary_comment(scored, threshold=threshold, weights=weights)

        if not repo:
            print_local_report(scored, threshold, weights)

        if pr_number and repo:
            post_review(
                comments,
                summary,
                repo=repo,
                pr_number=pr_number,
                token=token,
                commit_sha=commit_sha,
            )
        elif not repo:
            pass
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
            codeql_sarif_dir=codeql_sarif_dir,
            ast_rules_dir=ast_rules_dir,
            trivy_enabled=trivy_enabled,
            trivy_image=trivy_image,
            tfsec_enabled=tfsec_enabled,
            gitleaks_enabled=gitleaks_enabled,
            scanners_dir=scanners_dir,
        )

        if not repo:
            print_local_coverage_matrix(control_statuses)

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

        if scan_mode == "full":
            all_cfs = [cf for cs in control_statuses for cf in cs.findings]
            if gate_failed(all_cfs, fail_on):
                gate_tripped = True

    # Slack and Jira Notifications
    if args.slack_webhook or (args.jira_url and args.jira_project):
        if scored:
            summary_text = build_summary_comment(
                scored, threshold=threshold, weights=weights
            )
        elif control_statuses:
            summary_text = build_compact_coverage_summary(control_statuses)
        else:
            summary_text = "Compliance scan completed. No findings detected."

        if args.slack_webhook:
            post_slack_message(args.slack_webhook, scored, summary_text, gate_tripped)

        if args.jira_url and gate_tripped:
            create_jira_issue(
                args.jira_url,
                args.jira_email,
                args.jira_token,
                args.jira_project,
                scored,
                summary_text,
                control_statuses=control_statuses,
            )

    return 1 if gate_tripped else 0


if __name__ == "__main__":
    sys.exit(main())
