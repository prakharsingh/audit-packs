from __future__ import annotations
from dataclasses import dataclass
from audit_packs_core.models import AdjudicationResult, AdjudicationMode

DEFAULT_WEIGHTS: dict[str, float] = {
    "rule": 0.20,
    "evidence": 0.15,
    "consensus": 0.25,
    "history": 0.10,
    "severity": 0.10,
    "flow": 0.20,
}

_SEVERITY_MAP = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}


@dataclass(frozen=True)
class ScoreComponents:
    rule_confidence: float
    evidence_confidence: float
    model_consensus: float
    historical_precision: float
    control_severity: float
    flow_confidence: float


@dataclass(frozen=True)
class ScoredFinding:
    result: AdjudicationResult
    components: ScoreComponents
    finding_score: float
    surfaced: bool
    suppression_reason: str


def score_finding(
    result: AdjudicationResult,
    components: ScoreComponents,
    weights: dict[str, float],
) -> float:
    return (
        weights["rule"] * components.rule_confidence
        + weights["evidence"] * components.evidence_confidence
        + weights["consensus"] * components.model_consensus
        + weights["history"] * components.historical_precision
        + weights["severity"] * components.control_severity
        + weights["flow"] * components.flow_confidence
    )


def apply_confidence_gate(
    pairs: list[tuple[AdjudicationResult, ScoreComponents]],
    threshold: float,
    mode: AdjudicationMode,
    weights: dict[str, float],
) -> list[ScoredFinding]:
    results = []
    for result, components in pairs:
        fs = score_finding(result, components, weights)
        if mode in (AdjudicationMode.OFF, AdjudicationMode.ADVISORY):
            surfaced = True
            reason = ""
        else:  # ENFORCE
            surfaced = fs >= threshold
            reason = "" if surfaced else f"score {fs:.2f} < threshold {threshold:.2f}"
        results.append(
            ScoredFinding(
                result=result,
                components=components,
                finding_score=fs,
                surfaced=surfaced,
                suppression_reason=reason,
            )
        )
    return results


def get_historical_precision(check_id: str, framework: str, data: dict) -> float:
    """Posterior mean of Beta(alpha, beta). Default prior: alpha=4, beta=1 → 0.8."""
    key = f"{check_id}:{framework}"
    if key not in data:
        return 4 / 5
    entry = data[key]
    return entry["alpha"] / (entry["alpha"] + entry["beta"])


def update_precision(check_id: str, framework: str, data: dict) -> dict:
    """Confirm a TP: increment alpha. Creates entry with alpha=5, beta=1 if absent."""
    key = f"{check_id}:{framework}"
    if key not in data:
        data[key] = {"alpha": 5, "beta": 1}
    else:
        data[key]["alpha"] += 1
    return data


def control_severity_score(severity: str) -> float:
    return _SEVERITY_MAP.get(severity, 0.6)
