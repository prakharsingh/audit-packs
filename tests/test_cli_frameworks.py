import pytest
from audit_packs_action.cli import normalize_frameworks


def test_gdpr_normalized():
    assert normalize_frameworks("GDPR") == ["gdpr"]


def test_hipaa_lowercase():
    assert normalize_frameworks("hipaa") == ["hipaa"]


def test_soc2_alias():
    assert normalize_frameworks("SOC2") == ["soc2"]
    assert normalize_frameworks("soc-2") == ["soc2"]


def test_iso27001_aliases():
    assert normalize_frameworks("ISO27001") == ["iso27001"]
    assert normalize_frameworks("iso-27001") == ["iso27001"]


def test_pci_dss_aliases():
    assert normalize_frameworks("PCI-DSS") == ["pci-dss"]
    assert normalize_frameworks("pcidss") == ["pci-dss"]
    assert normalize_frameworks("pci_dss") == ["pci-dss"]


def test_nist_aliases():
    assert normalize_frameworks("NIST-800-53") == ["nist-800-53"]
    assert normalize_frameworks("nist800-53") == ["nist-800-53"]
    assert normalize_frameworks("nist") == ["nist-800-53"]


def test_fedramp_alias():
    assert normalize_frameworks("FedRAMP") == ["fedramp"]


def test_org_policy_aliases():
    assert normalize_frameworks("org-policy") == ["org-policy"]
    assert normalize_frameworks("org_policy") == ["org-policy"]
    assert normalize_frameworks("internal") == ["org-policy"]


def test_comma_separated():
    result = normalize_frameworks("GDPR,HIPAA")
    assert result == ["gdpr", "hipaa"]


def test_newline_separated():
    result = normalize_frameworks("GDPR\nHIPAA\nSOC2")
    assert result == ["gdpr", "hipaa", "soc2"]


def test_mixed_comma_and_newline():
    result = normalize_frameworks("GDPR\nHIPAA,SOC2")
    assert result == ["gdpr", "hipaa", "soc2"]


def test_unknown_framework_raises_value_error():
    with pytest.raises(ValueError, match="Unknown framework"):
        normalize_frameworks("UNKNOWN_FRAMEWORK")


def test_empty_tokens_skipped():
    result = normalize_frameworks("GDPR,,HIPAA")
    assert result == ["gdpr", "hipaa"]


def test_main_does_not_crash_on_missing_pr_number(monkeypatch):
    from unittest.mock import patch
    from audit_packs_action.cli import main

    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_TOKEN", "mock_token")
    monkeypatch.setenv("GITHUB_SHA", "mock_sha")
    # PR_NUMBER is explicitly not set
    monkeypatch.delenv("PR_NUMBER", raising=False)
    monkeypatch.setenv("SCAN_MODE", "full")
    monkeypatch.setenv("EMIT_OSCAL", "false")
    monkeypatch.setenv("EMIT_COVERAGE", "false")
    monkeypatch.setenv("EMIT_SARIF", "false")

    with patch("audit_packs_action.cli.assess", return_value=[]) as mock_assess:
        code = main()
        assert code == 0
        mock_assess.assert_called_once()
