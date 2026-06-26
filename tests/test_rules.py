"""Tests verifying that authored Semgrep rules map to the correct NIST controls.

These tests do not invoke semgrep — they only verify the YAML structure of each
rule file and confirm that the rule id referenced in the rule appears in the
nist-800-53.yaml canonical pack under the expected control. This keeps the tests
fast (no subprocess) while ensuring the data-layer consistency is maintained.
"""

import pathlib
import yaml

RULES_DIR = pathlib.Path(__file__).parent.parent / "rules"
PACKS_DIR = pathlib.Path(__file__).parent.parent / "packs"


def _load_rule_ids(rule_file: pathlib.Path) -> list[str]:
    data = yaml.safe_load(rule_file.read_text()) or {}
    return [r["id"] for r in data.get("rules", [])]


def _nist_semgrep_ids() -> dict[str, str]:
    """Return {semgrep_rule_id: nist_control_id} from nist-800-53/controls.yaml."""
    nist = yaml.safe_load((PACKS_DIR / "nist-800-53" / "controls.yaml").read_text())
    mapping: dict[str, str] = {}
    for control in nist["controls"]:
        for m in control.get("mappings", []):
            if m["engine"] == "semgrep":
                mapping[m["check_id"]] = control["id"]
    return mapping


class TestRuleStructure:
    def test_rules_directory_exists(self):
        assert RULES_DIR.is_dir(), "rules/ directory must exist"

    def test_at_least_four_rule_files(self):
        yamls = list(RULES_DIR.glob("*.yaml"))
        assert (
            len(yamls) >= 4
        ), f"Expected at least 4 rule files, found {len(yamls)}: {yamls}"

    def test_each_rule_file_has_rules_key(self):
        for f in RULES_DIR.glob("*.yaml"):
            data = yaml.safe_load(f.read_text()) or {}
            assert "rules" in data, f"{f.name} missing 'rules' key"
            assert len(data["rules"]) >= 1, f"{f.name} has empty 'rules' list"

    def test_each_rule_has_required_fields(self):
        for f in RULES_DIR.glob("*.yaml"):
            data = yaml.safe_load(f.read_text()) or {}
            for rule in data.get("rules", []):
                for field in ("id", "languages", "message", "severity"):
                    assert (
                        field in rule
                    ), f"Rule {rule.get('id', '?')} in {f.name} missing '{field}'"

    def test_all_semgrep_ids_in_nist_pack_have_a_rule_file(self):
        """Every semgrep rule id referenced in nist-800-53.yaml must exist in rules/."""
        nist_semgrep_ids = set(_nist_semgrep_ids().keys())
        authored_ids: set[str] = set()
        for f in RULES_DIR.glob("*.yaml"):
            authored_ids.update(_load_rule_ids(f))
        missing = nist_semgrep_ids - authored_ids
        assert not missing, f"These semgrep ids appear in nist-800-53.yaml but have no rule file: {missing}"

    def test_all_rule_file_ids_appear_in_nist_pack(self):
        """Every semgrep rule id in rules/ must appear in nist-800-53.yaml (forward direction)."""
        nist_semgrep_ids = set(_nist_semgrep_ids().keys())
        authored_ids: set[str] = set()
        for f in RULES_DIR.glob("*.yaml"):
            authored_ids.update(_load_rule_ids(f))
        orphans = authored_ids - nist_semgrep_ids
        assert not orphans, (
            f"These rule ids exist in rules/ but have no entry in nist-800-53.yaml: {orphans}\n"
            "Add them to the appropriate control's semgrep checks list."
        )


class TestSpecificRules:
    def test_weak_cipher_rule_exists_and_maps_to_sc13(self):
        mapping = _nist_semgrep_ids()
        assert "weak-cipher" in mapping, "weak-cipher not found in nist-800-53.yaml"
        assert mapping["weak-cipher"] == "SC-13"

    def test_hardcoded_credential_rule_exists_and_maps_to_ia5(self):
        mapping = _nist_semgrep_ids()
        assert (
            "hardcoded-credential" in mapping
        ), "hardcoded-credential not found in nist-800-53.yaml"
        assert mapping["hardcoded-credential"] == "IA-5"

    def test_no_tls_verify_rule_exists_and_maps_to_sc8(self):
        mapping = _nist_semgrep_ids()
        assert "no-tls-verify" in mapping, "no-tls-verify not found in nist-800-53.yaml"
        assert mapping["no-tls-verify"] == "SC-8"

    def test_missing_audit_log_rule_exists_and_maps_to_au3(self):
        mapping = _nist_semgrep_ids()
        assert (
            "missing-audit-log" in mapping
        ), "missing-audit-log not found in nist-800-53.yaml"
        assert mapping["missing-audit-log"] == "AU-3"

    def test_overpermissive_iam_rule_exists_and_maps_to_ac6(self):
        mapping = _nist_semgrep_ids()
        assert (
            "overpermissive-iam" in mapping
        ), "overpermissive-iam not found in nist-800-53.yaml"
        assert mapping["overpermissive-iam"] == "AC-6"
