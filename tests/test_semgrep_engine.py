import pytest
import asyncio
from audit_packs_action.engines import SemgrepEngine


def test_semgrep_requires_rules_path_raises_value_error():
    engine = SemgrepEngine()
    with pytest.raises(ValueError, match="semgrep requires 'rules_path' in options"):
        # rules_path is None (missing from options)
        asyncio.run(engine.run_scan_async("/tmp/target", {}))


def test_semgrep_empty_rules_path_skips_gracefully(capsys):
    engine = SemgrepEngine()
    # rules_path is empty string
    res = asyncio.run(engine.run_scan_async("/tmp/target", {"rules_path": ""}))
    assert res == {"runs": []}

    captured = capsys.readouterr()
    assert "semgrep rules path not found" in captured.err
    assert "skipping Semgrep engine" in captured.err


def test_semgrep_nonexistent_rules_path_skips_gracefully(capsys):
    engine = SemgrepEngine()
    # rules_path does not exist
    res = asyncio.run(
        engine.run_scan_async("/tmp/target", {"rules_path": "/nonexistent/rules/path"})
    )
    assert res == {"runs": []}

    captured = capsys.readouterr()
    assert "semgrep rules path not found" in captured.err
    assert "skipping Semgrep engine" in captured.err


def test_cli_resolves_bundled_rules_by_default(tmp_path):
    import os
    from unittest.mock import patch
    from audit_packs_action.cli import main

    # We mock the workspace to a temp workspace with no 'rules' dir.
    with patch(
        "sys.argv",
        [
            "audit-packs",
            "--workspace",
            str(tmp_path),
            "--packs-dir",
            str(tmp_path),
            "--scan-mode",
            "full",
        ],
    ), patch("audit_packs_action.cli.assess") as mock_assess:
        try:
            main()
        except SystemExit:
            pass

        assert mock_assess.called
        args, kwargs = mock_assess.call_args
        rules_path = args[2]
        # Should fall back to the bundled rules folder
        assert "audit_packs_action" in rules_path
        assert rules_path.endswith("rules")
        assert os.path.exists(rules_path)
