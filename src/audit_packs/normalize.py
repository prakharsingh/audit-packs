from audit_packs.models import Finding

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "low"}

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
            severity = _LEVEL_TO_SEVERITY.get(res.get("level", "warning"), "medium")
            findings.append(Finding(
                check_id=res.get("ruleId", ""),
                engine=engine,
                file=path,
                line=int(line),
                severity=severity,
                message=msg,
                evidence=msg,
            ))
    return findings
