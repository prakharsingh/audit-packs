import pathlib
import pytest
from audit_packs.models import Finding
from audit_packs.packs import load_pack, map_findings, iter_controls

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
    # CKV_AWS_67 lives in AU-2 (and AU-3) in NIST, which maps to CC7.2 (and others).
    cfs = map_findings([_finding("CKV_AWS_67")], PACKS, ["soc2"])
    assert len(cfs) >= 1
    mapped_controls = {cf.control_id for cf in cfs}
    assert "CC7.2" in mapped_controls  # CC7.2 maps_to [AU-2, AU-3], AU-2 has CKV_AWS_67
    assert all(cf.framework == "soc2" for cf in cfs)


def test_map_findings_unmapped_check_is_dropped():
    assert map_findings([_finding("CKV_AWS_999")], PACKS, ["nist-800-53"]) == []


def test_semgrep_custom_id_maps_to_nist():
    cfs = map_findings(
        [_finding("weak-cipher", engine="semgrep")], PACKS, ["nist-800-53"]
    )
    assert len(cfs) == 1
    assert cfs[0].control_id == "SC-13"


# --- Phase 1: iter_controls ---


def test_iter_controls_canonical_returns_all_controls():
    controls = iter_controls(PACKS, "nist-800-53")
    ids = {c["id"] for c in controls}
    # All 8 original controls must be present
    assert {"SC-13", "SC-28", "SC-8", "SC-7", "AC-3", "AC-6", "IA-5", "AU-2"}.issubset(
        ids
    )


def test_iter_controls_canonical_has_check_ids():
    controls = iter_controls(PACKS, "nist-800-53")
    sc13 = next(c for c in controls if c["id"] == "SC-13")
    # check_ids is a list of (engine, check_id) tuples
    assert ("checkov", "CKV_AWS_19") in sc13["check_ids"]
    assert ("semgrep", "weak-cipher") in sc13["check_ids"]


def test_iter_controls_crosswalk_returns_all_soc2_controls():
    controls = iter_controls(PACKS, "soc2")
    ids = {c["id"] for c in controls}
    # All 6 original technical criteria must be present
    assert {"CC6.1", "CC6.3", "CC6.6", "CC6.7", "CC7.2", "CC8.1"}.issubset(ids)


def test_iter_controls_crosswalk_resolves_check_ids():
    """SOC 2 CC7.2 maps_to AU-2, which has CKV_AWS_67."""
    controls = iter_controls(PACKS, "soc2")
    cc72 = next(c for c in controls if c["id"] == "CC7.2")
    assert ("checkov", "CKV_AWS_67") in cc72["check_ids"]


def test_iter_controls_manual_entry_has_empty_check_ids(tmp_path):
    """A crosswalk control with assessment: manual and no maps_to has no check_ids."""
    nist_pack = tmp_path / "nist-800-53.yaml"
    nist_pack.write_text(
        "id: nist-800-53\ntitle: NIST\ncontrols:\n"
        "  - id: SC-13\n    title: Crypto\n    checks:\n"
        "      - { engine: checkov, ids: [CKV_AWS_19] }\n"
    )
    manual_pack = tmp_path / "test-fw.yaml"
    manual_pack.write_text(
        "id: test-fw\ntitle: Test Framework\ncrosswalk: nist-800-53\ncontrols:\n"
        "  - { id: GOV-1, title: Governance, assessment: manual }\n"
        "  - { id: TECH-1, title: Technical, maps_to: [SC-13] }\n"
    )
    controls = iter_controls(str(tmp_path), "test-fw")
    gov = next(c for c in controls if c["id"] == "GOV-1")
    tech = next(c for c in controls if c["id"] == "TECH-1")
    assert gov["check_ids"] == []
    assert gov["assessment"] == "manual"
    assert ("checkov", "CKV_AWS_19") in tech["check_ids"]


def test_map_findings_crosswalk_with_manual_only_controls_does_not_raise(tmp_path):
    """A crosswalk pack where some controls are manual-only should not raise ValueError
    as long as at least one control is code-observable (has maps_to)."""
    nist_pack = tmp_path / "nist-800-53.yaml"
    nist_pack.write_text(
        "id: nist-800-53\ntitle: NIST\ncontrols:\n"
        "  - id: SC-13\n    title: Crypto\n    checks:\n"
        "      - { engine: checkov, ids: [CKV_AWS_19] }\n"
    )
    mixed_pack = tmp_path / "mixed-fw.yaml"
    mixed_pack.write_text(
        "id: mixed-fw\ntitle: Mixed\ncrosswalk: nist-800-53\ncontrols:\n"
        "  - { id: MAN-1, title: Manual Only, assessment: manual }\n"
        "  - { id: TECH-1, title: Technical, maps_to: [SC-13] }\n"
    )
    # Should not raise
    cfs = map_findings([_finding("CKV_AWS_19")], str(tmp_path), ["mixed-fw"])
    assert len(cfs) == 1
    assert cfs[0].control_id == "TECH-1"


def test_map_findings_crosswalk_one_check_id_maps_to_multiple_framework_controls(
    tmp_path,
):
    """If two framework controls both map_to the same canonical control, a finding
    on a shared check_id should produce ControlFindings for BOTH framework controls."""
    nist_pack = tmp_path / "nist-800-53.yaml"
    nist_pack.write_text(
        "id: nist-800-53\ntitle: NIST\ncontrols:\n"
        "  - id: AU-2\n    title: Audit Events\n    checks:\n"
        "      - { engine: checkov, ids: [CKV_AWS_67] }\n"
    )
    fw_pack = tmp_path / "fw.yaml"
    fw_pack.write_text(
        "id: fw\ntitle: FW\ncrosswalk: nist-800-53\ncontrols:\n"
        "  - { id: CTRL-A, title: Control A, maps_to: [AU-2] }\n"
        "  - { id: CTRL-B, title: Control B, maps_to: [AU-2] }\n"
    )
    cfs = map_findings([_finding("CKV_AWS_67")], str(tmp_path), ["fw"])
    ids = {cf.control_id for cf in cfs}
    assert ids == {"CTRL-A", "CTRL-B"}


def test_map_findings_all_manual_crosswalk_does_not_raise(tmp_path):
    """A crosswalk pack where ALL controls are manual should not raise ValueError."""
    nist_pack = tmp_path / "nist-800-53.yaml"
    nist_pack.write_text(
        "id: nist-800-53\ntitle: NIST\ncontrols:\n"
        "  - id: SC-13\n    title: Crypto\n    checks:\n"
        "      - { engine: checkov, ids: [CKV_AWS_19] }\n"
    )
    manual_pack = tmp_path / "manual-fw.yaml"
    manual_pack.write_text(
        "id: manual-fw\ntitle: Manual\ncrosswalk: nist-800-53\ncontrols:\n"
        "  - { id: GOV-1, title: Gov Only, assessment: manual }\n"
    )
    # Should return empty (no code-observable controls) without raising
    cfs = map_findings([_finding("CKV_AWS_19")], str(tmp_path), ["manual-fw"])
    assert cfs == []
