"""coverage.py — compute ControlStatus for every framework control.

Pure logic: no subprocess, no HTTP. Takes ControlFinding instances (already
mapped by packs.map_findings) and the pack directory, and returns a
ControlStatus per control — pass, fail, manual, or not_applicable.
"""

from audit_packs_core.models import ControlFinding, ControlStatus, AssessmentStatus
from audit_packs_mapping.packs import iter_controls


def compute_coverage(
    control_findings: list[ControlFinding],
    packs_dir: str,
    frameworks: list[str],
) -> list[ControlStatus]:
    """Compute a ControlStatus for every control in *frameworks*.

    Args:
        control_findings: All ControlFinding instances from map_findings()
                          (may come from diff-only or full-repo scan).
        packs_dir:        Path to the directory containing pack YAML files.
        frameworks:       List of framework ids (e.g. ["nist-800-53", "soc2"]).

    Returns:
        One ControlStatus per (framework, control_id) pair.
    """
    # Index findings by (framework, control_id) for O(1) lookup
    findings_by_key: dict[tuple[str, str], list[ControlFinding]] = {}
    for cf in control_findings:
        key = (cf.framework, cf.control_id)
        findings_by_key.setdefault(key, []).append(cf)

    statuses: list[ControlStatus] = []
    for fw in frameworks:
        for ctrl in iter_controls(packs_dir, fw):
            key = (fw, ctrl["id"])
            matched = findings_by_key.get(key, [])
            assessment_hint = ctrl.get("assessment")

            if assessment_hint == "manual":
                status = AssessmentStatus.MANUAL
            elif matched:
                status = AssessmentStatus.FAIL
            else:
                status = AssessmentStatus.PASS

            statuses.append(
                ControlStatus(
                    framework=fw,
                    control_id=ctrl["id"],
                    control_title=ctrl["title"],
                    status=status,
                    check_ids=tuple(ctrl["check_ids"]),
                    findings=tuple(matched),
                    evidence=tuple(cf.finding.evidence for cf in matched),
                )
            )

    return statuses
