"""Integration tests: verify tfsec_enabled/gitleaks_enabled route engines into the pipeline."""

from unittest.mock import patch


_EMPTY_SARIF = {"runs": []}


def test_analyze_signature_accepts_tfsec_gitleaks_params():
    import inspect

    from audit_packs_action.cli import analyze

    sig = inspect.signature(analyze)
    assert "tfsec_enabled" in sig.parameters
    assert "gitleaks_enabled" in sig.parameters
    assert sig.parameters["tfsec_enabled"].default is False
    assert sig.parameters["gitleaks_enabled"].default is False


def test_assess_signature_accepts_tfsec_gitleaks_params():
    import inspect

    from audit_packs_action.cli import assess

    sig = inspect.signature(assess)
    assert "tfsec_enabled" in sig.parameters
    assert "gitleaks_enabled" in sig.parameters
    assert sig.parameters["tfsec_enabled"].default is False
    assert sig.parameters["gitleaks_enabled"].default is False


def test_analyze_sync_path_calls_run_tfsec_when_enabled(tmp_path):
    from audit_packs_action.cli import analyze

    tfsec_called = []

    def _mock_run_tfsec(target):
        tfsec_called.append(target)
        return _EMPTY_SARIF

    with (
        patch("asyncio.run", side_effect=RuntimeError("nested asyncio.run")),
        patch("audit_packs_action.cli.run_checkov", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_semgrep", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_ast_rules", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_trivy_fs", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_trivy_image", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_tfsec", side_effect=_mock_run_tfsec),
        patch("audit_packs_action.cli.run_gitleaks", return_value=_EMPTY_SARIF),
    ):
        try:
            analyze(
                str(tmp_path),
                {},
                str(tmp_path),
                "",
                ["nist-800-53"],
                tfsec_enabled=True,
            )
        except Exception:
            pass

    assert tfsec_called, "run_tfsec was not called despite tfsec_enabled=True"


def test_analyze_sync_path_skips_run_tfsec_when_disabled(tmp_path):
    from audit_packs_action.cli import analyze

    tfsec_called = []

    def _mock_run_tfsec(target):
        tfsec_called.append(target)
        return _EMPTY_SARIF

    with (
        patch("asyncio.run", side_effect=RuntimeError("nested asyncio.run")),
        patch("audit_packs_action.cli.run_checkov", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_semgrep", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_ast_rules", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_trivy_fs", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_trivy_image", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_tfsec", side_effect=_mock_run_tfsec),
        patch("audit_packs_action.cli.run_gitleaks", return_value=_EMPTY_SARIF),
    ):
        try:
            analyze(
                str(tmp_path),
                {},
                str(tmp_path),
                "",
                ["nist-800-53"],
                tfsec_enabled=False,
            )
        except Exception:
            pass

    assert not tfsec_called, "run_tfsec was called despite tfsec_enabled=False"
