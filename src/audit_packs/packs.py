import os
import yaml
from audit_packs.models import Finding, ControlFinding


def load_pack(path: str) -> dict:
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    if "id" not in data or "controls" not in data:
        raise ValueError(f"pack {path} missing required keys 'id'/'controls'")

    # Dynamic Injection of OrgPolicy custom rules
    if data.get("id") == "nist-800-53":
        dir_name = os.path.dirname(path)
        org_policy_path = os.path.join(dir_name, "org-policy.yaml")
        if os.path.exists(org_policy_path):
            try:
                with open(org_policy_path) as op_fh:
                    op_data = yaml.safe_load(op_fh) or {}
                custom_rules = op_data.get("custom_rules", [])
                for rule in custom_rules:
                    rule_id = rule.get("id")
                    maps_to = rule.get("maps_to", [])
                    if rule_id and maps_to:
                        for nist_ctrl in maps_to:
                            for control in data.get("controls", []):
                                if control.get("id") == nist_ctrl:
                                    checks = control.setdefault("checks", [])
                                    found = False
                                    for group in checks:
                                        if group.get("engine") == "org-policy-agent":
                                            if rule_id not in group["ids"]:
                                                group["ids"].append(rule_id)
                                            found = True
                                            break
                                    if not found:
                                        checks.append(
                                            {
                                                "engine": "org-policy-agent",
                                                "ids": [rule_id],
                                            }
                                        )
            except Exception as exc:
                import sys

                print(
                    f"Warning: Failed to load custom rules from org-policy.yaml: {exc}",
                    file=sys.stderr,
                )
    return data


def _pack_path(packs_dir: str, pack_id: str) -> str:
    return os.path.join(packs_dir, f"{pack_id}.yaml")


def _canonical_index(pack: dict) -> dict[tuple[str, str], tuple[str, str]]:
    """(engine, check_id) -> (control_id, control_title)"""
    index: dict[tuple[str, str], tuple[str, str]] = {}
    for control in pack["controls"]:
        for group in control.get("checks", []):
            engine = group["engine"]
            for cid in group["ids"]:
                index[(engine, cid)] = (
                    control["id"],
                    control.get("title", control["id"]),
                )
    return index


def _canonical_check_ids(pack: dict) -> dict[str, list[tuple[str, str]]]:
    """control_id -> [(engine, check_id), ...]  for a canonical pack."""
    result: dict[str, list[tuple[str, str]]] = {}
    for control in pack["controls"]:
        pairs: list[tuple[str, str]] = []
        for group in control.get("checks", []):
            engine = group["engine"]
            for cid in group["ids"]:
                pairs.append((engine, cid))
        result[control["id"]] = pairs
    return result


def iter_controls(packs_dir: str, framework: str) -> list[dict]:
    """Return every control in *framework* with its resolved check_ids.

    Each item is a dict:
      id:          control ID in this framework
      title:       human-readable title
      assessment:  None (code-observable) | "manual" (governance, no engine check)
      check_ids:   list of (engine, check_id) pairs that guard this control
      maps_to:     canonical control IDs this crosswalk entry resolves to (crosswalk only)
    """
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
        # Canonical pack — check_ids come directly from the control's checks
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
            # One canonical control may be referenced by multiple framework controls
            # (e.g. CC7.2 and CC7.4 both map_to AU-3), so we use a list per key.
            cw: dict[str, list[tuple[str, str]]] = {}
            for control in pack["controls"]:
                for mapped in control.get("maps_to", []):
                    cw.setdefault(mapped, []).append(
                        (control["id"], control.get("title", control["id"]))
                    )
            # Raise only if no control is code-observable AND no control is manual.
            # A pack with only manual entries is valid (assessment: manual covers them).
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
            canonical_control_id, canonical_title = hit
            if crosswalk_id:
                for control_id, title in cw.get(canonical_control_id, []):
                    results.append(ControlFinding(f, fw, control_id, title))
            else:
                results.append(
                    ControlFinding(f, fw, canonical_control_id, canonical_title)
                )
    return results
