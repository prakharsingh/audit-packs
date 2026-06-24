import pathlib
from audit_packs.cli import analyze

ROOT = pathlib.Path(__file__).parent.parent
PACKS = str(ROOT / "packs")
RULES = str(ROOT / "rules/weak-cipher.yaml")
TF = str(ROOT / "tests/fixtures/terraform")

def test_analyze_maps_checkov_findings_to_controls_diff_filtered():
    # Pretend every line of insecure.tf changed in the PR.
    changed = {"insecure.tf": set(range(1, 50))}
    cfs = analyze(TF, changed, PACKS, RULES, ["nist-800-53"])
    control_ids = {cf.control_id for cf in cfs}
    # Insecure S3 bucket should surface at least one mapped control.
    assert control_ids, "expected at least one control-mapped finding"
    assert all(cf.framework == "nist-800-53" for cf in cfs)

def test_analyze_drops_findings_outside_diff():
    changed = {"insecure.tf": set()}  # nothing changed
    assert analyze(TF, changed, PACKS, RULES, ["nist-800-53"]) == []
