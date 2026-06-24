import os
import yaml
from audit_packs.models import Finding, ControlFinding

def load_pack(path: str) -> dict:
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    if "id" not in data or "controls" not in data:
        raise ValueError(f"pack {path} missing required keys 'id'/'controls'")
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
                index[(engine, cid)] = (control["id"], control.get("title", control["id"]))
    return index

def map_findings(findings: list[Finding], packs_dir: str, frameworks: list[str]) -> list[ControlFinding]:
    results: list[ControlFinding] = []
    for fw in frameworks:
        pack = load_pack(_pack_path(packs_dir, fw))
        crosswalk_id = pack.get("crosswalk")
        canonical = load_pack(_pack_path(packs_dir, crosswalk_id)) if crosswalk_id else pack
        check_index = _canonical_index(canonical)
        
        if crosswalk_id:
            # map canonical control id -> this framework's (control_id, title)
            cw: dict[str, tuple[str, str]] = {}
            for control in pack["controls"]:
                for mapped in control.get("maps_to", []):
                    cw[mapped] = (control["id"], control.get("title", control["id"]))
            if not cw:
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
                if canonical_control_id not in cw:
                    continue
                control_id, title = cw[canonical_control_id]
            else:
                control_id, title = canonical_control_id, canonical_title
            results.append(ControlFinding(f, fw, control_id, title))
    return results
