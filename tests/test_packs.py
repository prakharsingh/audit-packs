import pathlib
import pytest
from audit_packs.models import Finding
from audit_packs.packs import load_pack, map_findings

PACKS = str(pathlib.Path(__file__).parent.parent / "packs")

def _finding(check_id, engine="checkov"):
    return Finding(check_id, engine, "main.tf", 11, "high", "msg", "ev")

def test_load_pack_validates_required_keys(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("title: missing id and controls\n")
    with pytest.raises(ValueError):
        load_pack(str(bad))

def test_map_findings_canonical_nist():
    cfs = map_findings([_finding("CKV_AWS_19")], PACKS, ["nist-800-53"])
    assert len(cfs) == 1
    assert (cfs[0].framework, cfs[0].control_id) == ("nist-800-53", "SC-13")
    assert cfs[0].control_title == "Cryptographic Protection"

def test_map_findings_crosswalk_soc2():
    cfs = map_findings([_finding("CKV_AWS_67")], PACKS, ["soc2"])
    assert len(cfs) == 1
    assert (cfs[0].framework, cfs[0].control_id) == ("soc2", "CC7.2")

def test_map_findings_unmapped_check_is_dropped():
    assert map_findings([_finding("CKV_AWS_999")], PACKS, ["nist-800-53"]) == []

def test_semgrep_custom_id_maps_to_nist():
    cfs = map_findings([_finding("weak-cipher", engine="semgrep")], PACKS, ["nist-800-53"])
    assert len(cfs) == 1
    assert cfs[0].control_id == "SC-13"
