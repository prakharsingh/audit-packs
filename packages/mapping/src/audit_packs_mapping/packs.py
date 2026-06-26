import os
import yaml
from audit_packs_core.models import Finding, ControlFinding


def load_pack(path: str) -> dict:
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    framework_key = data.get("framework") or data.get("id")
    if not framework_key or "controls" not in data:
        raise ValueError(f"pack {path} missing required keys 'framework'/'controls'")
    return data


def _pack_path(packs_dir: str, pack_id: str) -> str:
    return os.path.join(packs_dir, pack_id, "controls.yaml")


def _canonical_index(pack: dict) -> dict[tuple[str, str], tuple[str, str, tuple]]:
    """(engine, check_id) -> (control_id, control_title, evidence_requirements)"""
    index: dict[tuple[str, str], tuple[str, str, tuple]] = {}
    for control in pack["controls"]:
        ev_reqs: tuple = tuple(control.get("evidence_requirements", []))
        for m in control.get("mappings", []):
            index[(m["engine"], m["check_id"])] = (
                control["id"],
                control.get("title", control["id"]),
                ev_reqs,
            )
    return index


def _canonical_check_ids(pack: dict) -> dict[str, list[tuple[str, str]]]:
    """control_id -> [(engine, check_id), ...]"""
    result: dict[str, list[tuple[str, str]]] = {}
    for control in pack["controls"]:
        pairs = [(m["engine"], m["check_id"]) for m in control.get("mappings", [])]
        result[control["id"]] = pairs
    return result


def iter_controls(packs_dir: str, framework: str) -> list[dict]:
    """Return every control in *framework* with its resolved check_ids."""
    pack = load_pack(_pack_path(packs_dir, framework))
    crosswalk_id = pack.get("crosswalk")

    if crosswalk_id:
        canonical = load_pack(_pack_path(packs_dir, crosswalk_id))
        canon_checks = _canonical_check_ids(canonical)
        result = []
        for control in pack["controls"]:
            maps_to = control.get("maps_to", [])
            assessment = control.get("assessment", None)
            check_ids: list[tuple[str, str]] = []
            for nist_id in maps_to:
                check_ids.extend(canon_checks.get(nist_id, []))
            result.append(
                {
                    "id": control["id"],
                    "title": control.get("title", control["id"]),
                    "assessment": assessment,
                    "check_ids": check_ids,
                    "maps_to": maps_to,
                }
            )
        return result
    else:
        canon_checks = _canonical_check_ids(pack)
        return [
            {
                "id": control["id"],
                "title": control.get("title", control["id"]),
                "assessment": None,
                "check_ids": canon_checks.get(control["id"], []),
                "maps_to": [],
            }
            for control in pack["controls"]
        ]


def map_findings(
    findings: list[Finding], packs_dir: str, frameworks: list[str]
) -> list[ControlFinding]:
    results: list[ControlFinding] = []
    for fw in frameworks:
        pack = load_pack(_pack_path(packs_dir, fw))
        crosswalk_id = pack.get("crosswalk")
        canonical = (
            load_pack(_pack_path(packs_dir, crosswalk_id)) if crosswalk_id else pack
        )
        check_index = _canonical_index(canonical)

        if crosswalk_id:
            cw: dict[str, list[tuple[str, str, tuple]]] = {}
            for control in pack["controls"]:
                ev_reqs: tuple = tuple(control.get("evidence_requirements", []))
                for mapped in control.get("maps_to", []):
                    cw.setdefault(mapped, []).append(
                        (control["id"], control.get("title", control["id"]), ev_reqs)
                    )
            has_manual = any(c.get("assessment") == "manual" for c in pack["controls"])
            if not cw and not has_manual:
                raise ValueError(
                    f"crosswalk pack '{fw}' has no 'maps_to' entries in any control; "
                    f"check that controls use 'maps_to' (not 'nist_ids' or similar)"
                )

        for f in findings:
            hit = check_index.get((f.engine, f.check_id))
            if not hit:
                continue
            canonical_control_id, canonical_title, canon_ev_reqs = hit
            if crosswalk_id:
                for control_id, title, fw_ev_reqs in cw.get(canonical_control_id, []):
                    results.append(ControlFinding(f, fw, control_id, title, fw_ev_reqs))
            else:
                results.append(
                    ControlFinding(
                        f, fw, canonical_control_id, canonical_title, canon_ev_reqs
                    )
                )
    return results
