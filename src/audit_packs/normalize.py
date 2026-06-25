from audit_packs.models import Finding, PathNode

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
            findings.append(
                Finding(
                    check_id=res.get("ruleId", ""),
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


def extract_rule_confidences(sarif: dict) -> dict[str, float]:
    """Return {rule_id → confidence_score} from SARIF tool rule metadata."""
    confidences: dict[str, float] = {}
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for rule in rules:
            rule_id = rule.get("id", "")
            conf_str = rule.get("properties", {}).get("confidence", "")
            if conf_str.upper() in _CONFIDENCE_MAP:
                confidences[rule_id] = _CONFIDENCE_MAP[conf_str.upper()]
    return confidences
