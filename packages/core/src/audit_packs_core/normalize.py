from audit_packs_core.models import Finding, PathNode

_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}
_PROP_TO_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "low",
}
_CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}


def _extract_evidence_path(result: dict) -> tuple[PathNode, ...]:
    """Parse codeFlows[0].threadFlows[0].locations into PathNode tuples."""
    code_flows = result.get("codeFlows", [])
    if not code_flows:
        return ()
    thread_flows = code_flows[0].get("threadFlows", [])
    if not thread_flows:
        return ()
    locations = thread_flows[0].get("locations", [])
    nodes = []
    for loc_entry in locations:
        loc = loc_entry.get("location", {})
        phys = loc.get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
        line = phys.get("region", {}).get("startLine", 0)
        snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
        description = loc.get("message", {}).get("text", "")
        nodes.append(
            PathNode(file=uri, line=int(line), snippet=snippet, description=description)
        )
    return tuple(nodes)


def _normalize_rule_id(rule_id: str, engine: str) -> str:
    """Strip dotted namespace prefix from semgrep rule IDs (e.g. 'org.foo.bar' → 'bar').

    Only applied for semgrep because other engines (checkov, codeql, ast) use their
    own ID schemes and stripping would break pack lookups or collapse distinct rules.
    """
    if engine == "semgrep" and "." in rule_id:
        return rule_id.split(".")[-1]
    return rule_id


def sarif_to_findings(sarif: dict, engine: str) -> list[Finding]:
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            path = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 1)
            msg = res.get("message", {}).get("text", "")
            snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
            prop_sev = _PROP_TO_SEVERITY.get(
                res.get("properties", {}).get("severity", "").upper()
            )
            level_sev = _LEVEL_TO_SEVERITY.get(res.get("level", "warning"), "medium")
            evidence_path = _extract_evidence_path(res)

            raw_id = res.get("ruleId", "")
            check_id = _normalize_rule_id(raw_id, engine)

            findings.append(
                Finding(
                    check_id=check_id,
                    engine=engine,
                    file=path,
                    line=int(line),
                    severity=prop_sev or level_sev,
                    message=msg,
                    evidence=snippet or msg,
                    evidence_path=evidence_path,
                )
            )
    return findings


def extract_rule_confidences(sarif: dict, engine: str = "") -> dict[str, float]:
    """Return {rule_id → confidence_score} from SARIF tool rule metadata.

    The engine parameter must match the value passed to sarif_to_findings so that
    the keys in the returned dict align with Finding.check_id values.
    """
    confidences: dict[str, float] = {}
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for rule in rules:
            rule_id = rule.get("id", "")
            norm_id = _normalize_rule_id(rule_id, engine)
            conf_str = rule.get("properties", {}).get("confidence", "")
            if conf_str.upper() in _CONFIDENCE_MAP:
                confidences[norm_id] = _CONFIDENCE_MAP[conf_str.upper()]
    return confidences
