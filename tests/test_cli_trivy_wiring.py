"""Integration tests: verify trivy_enabled=True actually routes TrivyEngine into the pipeline."""

from unittest.mock import patch


_EMPTY_SARIF = {"runs": []}


def test_analyze_signature_accepts_trivy_params():
    import inspect

    from audit_packs_action.cli import analyze

    sig = inspect.signature(analyze)
    assert "trivy_enabled" in sig.parameters
    assert "trivy_image" in sig.parameters
    assert sig.parameters["trivy_enabled"].default is False
    assert sig.parameters["trivy_image"].default == ""


def test_assess_signature_accepts_trivy_params():
    import inspect

    from audit_packs_action.cli import assess

    sig = inspect.signature(assess)
    assert "trivy_enabled" in sig.parameters
    assert "trivy_image" in sig.parameters
    assert sig.parameters["trivy_enabled"].default is False
    assert sig.parameters["trivy_image"].default == ""


def test_analyze_sync_path_calls_run_trivy_fs_when_enabled(tmp_path):
    """When asyncio.run raises RuntimeError (nested event loop), sync fallback calls run_trivy_fs."""
    from audit_packs_action.cli import analyze

    trivy_fs_called = []

    def _mock_run_trivy_fs(target):
        trivy_fs_called.append(target)
        return _EMPTY_SARIF

    with (
        patch("asyncio.run", side_effect=RuntimeError("nested asyncio.run")),
        patch("audit_packs_action.cli.run_checkov", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_semgrep", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_ast_rules", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_trivy_fs", side_effect=_mock_run_trivy_fs),
        patch("audit_packs_action.cli.run_trivy_image", return_value=_EMPTY_SARIF),
    ):
        try:
            analyze(
                str(tmp_path),
                {},
                str(tmp_path),
                "",
                ["nist-800-53"],
                trivy_enabled=True,
            )
        except Exception:
            pass

    assert trivy_fs_called, "run_trivy_fs was not called despite trivy_enabled=True"


def test_analyze_sync_path_skips_run_trivy_fs_when_disabled(tmp_path):
    """run_trivy_fs must NOT be called when trivy_enabled=False (the default)."""
    from audit_packs_action.cli import analyze

    trivy_fs_called = []

    def _mock_run_trivy_fs(target):
        trivy_fs_called.append(target)
        return _EMPTY_SARIF

    with (
        patch("asyncio.run", side_effect=RuntimeError("nested asyncio.run")),
        patch("audit_packs_action.cli.run_checkov", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_semgrep", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_ast_rules", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_trivy_fs", side_effect=_mock_run_trivy_fs),
        patch("audit_packs_action.cli.run_trivy_image", return_value=_EMPTY_SARIF),
    ):
        try:
            analyze(
                str(tmp_path),
                {},
                str(tmp_path),
                "",
                ["nist-800-53"],
                trivy_enabled=False,
            )
        except Exception:
            pass

    assert not trivy_fs_called, "run_trivy_fs was called despite trivy_enabled=False"


def test_assess_sync_path_calls_run_trivy_fs_when_enabled(tmp_path):
    """When asyncio.run raises RuntimeError, assess() sync fallback calls run_trivy_fs."""
    from audit_packs_action.cli import assess

    trivy_fs_called = []

    def _mock_run_trivy_fs(target):
        trivy_fs_called.append(target)
        return _EMPTY_SARIF

    with (
        patch("asyncio.run", side_effect=RuntimeError("nested asyncio.run")),
        patch("audit_packs_action.cli.run_checkov", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_semgrep", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_ast_rules", return_value=_EMPTY_SARIF),
        patch("audit_packs_action.cli.run_trivy_fs", side_effect=_mock_run_trivy_fs),
        patch("audit_packs_action.cli.run_trivy_image", return_value=_EMPTY_SARIF),
    ):
        try:
            assess(
                str(tmp_path), str(tmp_path), "", ["nist-800-53"], trivy_enabled=True
            )
        except Exception:
            pass

    assert (
        trivy_fs_called
    ), "run_trivy_fs was not called in assess() despite trivy_enabled=True"
