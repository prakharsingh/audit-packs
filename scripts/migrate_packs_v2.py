#!/usr/bin/env python3
"""Migrate pack files from v1 flat schema to v2 per-framework directory schema.

Usage: python scripts/migrate_packs_v2.py
Reads:  packs/<framework>.yaml  (v1)
Writes: packs/<framework>/controls.yaml  (v2)
"""

from pathlib import Path
import yaml


def _migrate_standard(v1: dict) -> dict:
    framework = v1.get("id") or v1.get("framework")
    if not framework:
        raise ValueError("Pack has no 'id' or 'framework' key")
    v2: dict = {"schema_version": "2", "framework": framework}
    if "title" in v1:
        v2["title"] = v1["title"]
    if "crosswalk" in v1:
        v2["crosswalk"] = v1["crosswalk"]
    controls = []
    for ctrl in v1.get("controls", []):
        mappings = []
        engines: set = set()
        for group in ctrl.get("checks", []):
            engine = group["engine"]
            engines.add(engine)
            for cid in group.get("ids", []):
                mappings.append({"engine": engine, "check_id": cid})
        new_ctrl: dict = {"id": ctrl["id"], "title": ctrl.get("title", ctrl["id"])}
        for key in ("severity", "references", "assessment", "maps_to"):
            if key in ctrl:
                new_ctrl[key] = ctrl[key]
        if engines:
            new_ctrl["supported_scanners"] = sorted(engines)
        if mappings:
            new_ctrl["mappings"] = mappings
        new_ctrl["evidence_requirements"] = []
        controls.append(new_ctrl)
    v2["controls"] = controls
    return v2


def _migrate_org_policy(v1: dict) -> dict:
    """org-policy uses custom_rules, not standard controls — preserve, add header."""
    v2 = dict(v1)
    v2["schema_version"] = "2"
    v2["framework"] = v2.pop("id", "org-policy")
    return v2


def main() -> None:
    packs_dir = Path(__file__).parent.parent / "packs"
    for yaml_file in sorted(packs_dir.glob("*.yaml")):
        fw = yaml_file.stem
        print(f"Migrating {yaml_file.name} → {fw}/controls.yaml")
        v1 = yaml.safe_load(yaml_file.read_text()) or {}
        v2 = _migrate_org_policy(v1) if fw == "org-policy" else _migrate_standard(v1)
        out_dir = packs_dir / fw
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / "controls.yaml"
        with open(out_path, "w") as f:
            yaml.dump(
                v2, f, default_flow_style=False, allow_unicode=True, sort_keys=False
            )
        print(f"  ✓ {out_path}")
    print("\nDone. Inspect output, then delete the v1 flat *.yaml files.")


if __name__ == "__main__":
    main()
