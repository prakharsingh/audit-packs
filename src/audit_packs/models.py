from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

SEVERITIES = ("low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class PathNode:
    file: str
    line: int
    snippet: str
    description: str


@dataclass(frozen=True)
class Finding:
    check_id: str
    engine: str
    file: str
    line: int
    severity: str
    message: str
    evidence: str
    doc_context: str = ""
    evidence_path: tuple[PathNode, ...] = ()


@dataclass(frozen=True)
class ControlFinding:
    finding: Finding
    framework: str
    control_id: str
    control_title: str
    evidence_requirements: tuple = ()


class AssessmentStatus(str, Enum):
    """Status of a control after evidence collection."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    MANUAL = "manual"


class AdjudicationMode(str, Enum):
    OFF = "off"
    ADVISORY = "advisory"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class AdjudicationResult:
    control_finding: ControlFinding
    detector_score: float
    verifier_argument: str
    adversarial_argument: str
    judge_score: float
    model_consensus: float
    rationale: str


@dataclass(frozen=True)
class ControlStatus:
    """Status-aware view of a single compliance control after assessment."""

    framework: str
    control_id: str
    control_title: str
    status: AssessmentStatus
    # (engine, check_id) pairs that guard this control
    check_ids: tuple
    # ControlFinding instances that caused a FAIL
    findings: tuple
    # raw evidence strings extracted from findings
    evidence: tuple
