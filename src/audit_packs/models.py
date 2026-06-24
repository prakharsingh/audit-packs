from dataclasses import dataclass

SEVERITIES = ("low", "medium", "high", "critical")

def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)

@dataclass(frozen=True)
class Finding:
    check_id: str
    engine: str
    file: str
    line: int
    severity: str
    message: str
    evidence: str

@dataclass(frozen=True)
class ControlFinding:
    finding: Finding
    framework: str
    control_id: str
    control_title: str
