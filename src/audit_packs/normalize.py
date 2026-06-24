from audit_packs.models import Finding

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
# Checkov encodes richer severity in result.properties.severity; prefer it over SARIF level.
_PROP_TO_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "low"}


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
            prop_sev = _PROP_TO_SEVERITY.get(res.get("properties", {}).get("severity", "").upper())
            level_sev = _LEVEL_TO_SEVERITY.get(res.get("level", "warning"), "medium")
            findings.append(Finding(
                check_id=res.get("ruleId", ""),
                engine=engine,
                file=path,
                line=int(line),
                severity=prop_sev or level_sev,
                message=msg,
                evidence=snippet or msg,
            ))
    return findings
